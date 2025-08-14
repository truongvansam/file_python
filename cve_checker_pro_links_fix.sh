#!/bin/bash
set -uo pipefail

TARGET=${1:-}
SCAN_FILE="scan.txt"
CVE_FILE="cve_list.txt"
HTML_FILE="cve_report.html"
TMP_FILE="$(mktemp)"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[-] Thiếu: $1"; MISSING=1; }; }
MISSING=0
for bin in nmap grep sort awk sed curl jq searchsploit msfconsole; do need "$bin"; done
[ "$MISSING" -eq 1 ] && { echo "Cài đủ các gói trên rồi chạy lại."; exit 1; }

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target_ip_or_cidr>"; exit 1
fi

echo "[*] Quét lỗ hổng với Nmap..."
nmap -sV --script vuln "$TARGET" -oN "$SCAN_FILE" || { echo "Nmap lỗi"; exit 1; }

echo "[*] Lọc CVE từ kết quả quét..."
grep -Eo "CVE-[0-9]{4}-[0-9]{4,7}" "$SCAN_FILE" | sort -u > "$CVE_FILE" || true
if [ ! -s "$CVE_FILE" ]; then
  echo "[-] Không tìm thấy CVE nào trong kết quả quét."; exit 0
fi

get_cvss(){
  local cve="$1" raw score
  raw="$(curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}")"
  # v3.1
  score="$(echo "$raw" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore // empty')"
  [ -z "$score" ] && score="$(echo "$raw" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV30[0].cvssData.baseScore // empty')"
  [ -z "$score" ] && score="$(echo "$raw" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV2[0].cvssData.baseScore // empty')"
  [ -z "$score" ] && score="0"
  echo "$score"
}

level_color(){
  # input: score -> output: "LEVEL|COLOR"
  awk -v s="$1" 'BEGIN{
    if (s+0 >= 9.0)       print "Critical|red";
    else if (s+0 >= 7.0)  print "High|orange";
    else if (s+0 >= 4.0)  print "Medium|blue";
    else                  print "Low|green";
  }'
}

msf_info(){
  # print: MODULE|GITHUB_LINK (ưu tiên exploit/, fallback auxiliary/)
  local cve="$1" line module path link
  # Lọc các dòng module
  line="$(msfconsole -qx "search cve:${cve}; exit" 2>/dev/null | awk '/^(exploit|auxiliary)\// {print $1}' | head -n1)"
  if [ -n "$line" ]; then
    module="$line"
    # Map path sang repo GitHub
    if [[ "$module" == exploit/* ]]; then
      path="modules/exploits/${module#exploit/}.rb"
    else
      path="modules/${module}.rb"
    fi
    link="https://github.com/rapid7/metasploit-framework/tree/master/${path}"
    echo "${module}|${link}"
  else
    echo "|"
  fi
}

edb_info(){
  # print: EDB_STATUS|EDB_LINK
  local cve="$1" eid
  eid="$(searchsploit --json "$cve" 2>/dev/null | jq -r '.RESULTS_EXPLOIT[0]."EDB-ID" // empty')"
  if [ -n "$eid" ]; then
    echo "Có exploit|https://www.exploit-db.com/exploits/${eid}"
  else
    echo "Không exploit|"
  fi
}

echo "[*] Kiểm tra chi tiết từng CVE..."
> "$TMP_FILE"
while IFS= read -r CVE; do
  [ -z "$CVE" ] && continue
  echo "[+] $CVE"

  SCORE="$(get_cvss "$CVE")"
  IFS='|' read -r LEVEL COLOR <<<"$(level_color "$SCORE")"

  NVD_LINK="https://nvd.nist.gov/vuln/detail/${CVE}"

  IFS='|' read -r MSF_MODULE MSF_LINK <<<"$(msf_info "$CVE")"
  if [ -n "$MSF_MODULE" ]; then
    MSF_STATUS="Có module (${MSF_MODULE})"
  else
    MSF_STATUS="Không module"
  fi

  IFS='|' read -r EDB_STATUS EDB_LINK <<<"$(edb_info "$CVE")"

  printf "%s|%s|%s|%s|%s|%s|%s|%s\n" \
    "$CVE" "$SCORE" "$LEVEL" "$COLOR" "$MSF_STATUS" "${MSF_LINK:-}" "$EDB_STATUS" "${EDB_LINK:-}" >> "$TMP_FILE"
done < "$CVE_FILE"

# Sinh HTML
cat > "$HTML_FILE" <<'EOF'
<html><head>
<meta charset="utf-8"/>
<title>CVE Scan Report</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;margin:24px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:8px;text-align:left}
th{background:#333;color:#fff;cursor:pointer}
tr:hover{background:#f9f9f9}
.badge{font-weight:bold}
</style>
<script>
function sortTable(n){
  const table=document.getElementById("tbl"), rows=[...table.rows].slice(1);
  const dir=table.getAttribute("data-dir")==="asc"?"desc":"asc";
  rows.sort((a,b)=>{
    const x=a.cells[n].getAttribute("data-sort")||a.cells[n].innerText;
    const y=b.cells[n].getAttribute("data-sort")||b.cells[n].innerText;
    const nx=parseFloat(x), ny=parseFloat(y);
    if(!isNaN(nx) && !isNaN(ny)) return dir==="asc"?nx-ny:ny-nx;
    return dir==="asc"?x.localeCompare(y):y.localeCompare(x);
  });
  rows.forEach(r=>table.tBodies[0].appendChild(r));
  table.setAttribute("data-dir",dir);
}
</script>
</head><body>
<h2>Báo cáo CVE</h2>
<p>Lưu ý: NVD API có thể rate-limit nếu không dùng API key; một số CVE cũ chỉ có CVSS v2.0.</p>
<table id="tbl" data-dir="desc">
<tr>
  <th onclick="sortTable(0)">CVE</th>
  <th onclick="sortTable(1)">CVSS</th>
  <th onclick="sortTable(2)">Mức độ</th>
  <th onclick="sortTable(3)">Metasploit</th>
  <th onclick="sortTable(4)">Exploit-DB</th>
  <th>NVD</th>
</tr>
EOF

# Ghi dòng dữ liệu (sort theo điểm số giảm dần, điểm rỗng = 0)
awk -F'|' '{
  score=$2+0;
  print $0 "|" score;
}' "$TMP_FILE" | sort -t'|' -k9,9nr | while IFS='|' read -r CVE SCORE LEVEL COLOR MSF_STATUS MSF_LINK EDB_STATUS EDB_LINK SCORE_SORT; do
  # ô CVE là link NVD; có thêm cột NVD riêng để bấm "Xem"
  NVD_LINK="https://nvd.nist.gov/vuln/detail/"$CVE
  # ô mức độ tô màu chữ
  [ -z "$SCORE" ] && SCORE="0"
  echo "<tr>
    <td data-sort=\"$CVE\"><a href=\"$NVD_LINK\" target=\"_blank\">$CVE</a></td>
    <td data-sort=\"$SCORE\">$SCORE</td>
    <td class=\"badge\" style=\"color:$COLOR\" data-sort=\"$LEVEL\">$LEVEL</td>
    <td data-sort=\"$MSF_STATUS\">"$( [ -n "$MSF_LINK" ] && echo "<a href=\"$MSF_LINK\" target=\"_blank\">$MSF_STATUS</a>" || echo "$MSF_STATUS" )"</td>
    <td data-sort=\"$EDB_STATUS\">"$( [ -n "$EDB_LINK" ] && echo "<a href=\"$EDB_LINK\" target=\"_blank\">$EDB_STATUS</a>" || echo "$EDB_STATUS" )"</td>
    <td><a href=\"$NVD_LINK\" target=\"_blank\">Xem</a></td>
  </tr>" >> "$HTML_FILE"
done

echo "</table></body></html>" >> "$HTML_FILE"

echo "[*] Xong. Mở file: $HTML_FILE"
