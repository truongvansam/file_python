#!/bin/bash
set -euo pipefail

# =========================
# CVE Intelligence Reporter
# =========================
# Usage:
#   ./cve_intel_report.sh -t <TARGET_IP>         # tự quét nmap
#   ./cve_intel_report.sh -f <nmap_output.txt>   # dùng file nmap có sẵn

TARGET=""
NMAP_FILE=""
REPORT_DIR="cve_intel_report"
NMAP_OUT="$REPORT_DIR/nmap_scan.txt"
CVE_LIST="$REPORT_DIR/cve_list.txt"
HTML="$REPORT_DIR/report.html"

mkdir -p "$REPORT_DIR"
> "$CVE_LIST"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[-] Thiếu: $1"; exit 1; }; }
for b in nmap curl jq msfconsole grep awk sort; do need "$b"; done

# Parse args
while getopts ":t:f:" opt; do
  case $opt in
    t) TARGET="$OPTARG" ;;
    f) NMAP_FILE="$OPTARG" ;;
    *) echo "Usage: $0 [-t TARGET] [-f NMAP_FILE]"; exit 1 ;;
  endac
done

if [[ -n "$TARGET" && -n "$NMAP_FILE" ]] || [[ -z "$TARGET" && -z "$NMAP_FILE" ]]; then
  echo "Chỉ chọn một trong hai: -t <TARGET> hoặc -f <NMAP_FILE>"; exit 1
fi

echo "[*] Thu thập CVE..."
if [[ -n "$TARGET" ]]; then
  echo "[*] Chạy nmap --script vulners trên $TARGET (có thể mất thời gian)..."
  nmap -sV --script vuln "$TARGET" -oN "$NMAP_OUT"
  SRC="$NMAP_OUT"
else
  [[ -f "$NMAP_FILE" ]] || { echo "[-] File không tồn tại: $NMAP_FILE"; exit 1; }
  cp "$NMAP_FILE" "$NMAP_OUT"
  SRC="$NMAP_OUT"
fi

# Rút trích CVE
grep -Eo "CVE-[0-9]{4}-[0-9]{4,7}" "$SRC" | sort -u > "$CVE_LIST" || true
if [[ ! -s "$CVE_LIST" ]]; then
  echo "[-] Không tìm thấy CVE trong kết quả."; exit 0
fi

# Hàm lấy điểm CVSS (NVD API v2)
get_cvss() {
  local cve="$1" raw score sev
  raw="$(curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}")"
  score="$(echo "$raw" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore // empty')"
  [[ -z "$score" ]] && score="$(echo "$raw" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV30[0].cvssData.baseScore // empty')"
  [[ -z "$score" ]] && score="$(echo "$raw" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV2[0].cvssData.baseScore // empty')"
  [[ -z "$score" ]] && score="0"
  sev="Low"
  awk -v s="$score" 'BEGIN{
    if (s+0>=9.0) print "Critical"; else if (s+0>=7.0) print "High";
    else if (s+0>=4.0) print "Medium"; else print "Low";
  }'
}

# Tạo report HTML
cat > "$HTML" <<'EOF'
<html><head><meta charset="utf-8">
<title>CVE Intelligence Report</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;margin:24px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:8px;text-align:left}
th{background:#333;color:#fff}
.badge{font-weight:bold}
.crit{color:#b00020}.high{color:#e67e22}.med{color:#1f77b4}.low{color:#2e7d32}
.small{font-size:12px;color:#555}
</style>
</head><body>
<h2>CVE Intelligence Report</h2>
<p class="small">Báo cáo chỉ mang tính thông tin phục vụ phân tích/phòng thủ. Không tải hoặc thực thi PoC.</p>
<table>
<tr>
  <th>CVE</th><th>CVSS</th><th>Mức độ</th>
  <th>Metasploit</th><th>Exploit-DB</th><th>GitHub PoC (Top)</th><th>NVD</th>
</tr>
EOF

# Duyệt từng CVE, điền dữ liệu
while read -r CVE; do
  [[ -z "$CVE" ]] && continue

  # CVSS + mức độ
  SCORE="$(curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${CVE}" \
    | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore // .vulnerabilities[0].cve.metrics.cvssMetricV30[0].cvssData.baseScore // .vulnerabilities[0].cve.metrics.cvssMetricV2[0].cvssData.baseScore // "0"')"
  [[ -z "$SCORE" ]] && SCORE="0"
  if awk -v s="$SCORE" 'BEGIN{exit !(s+0>=9)}'; then LEVEL="Critical"; CLASS="crit"
  elif awk -v s="$SCORE" 'BEGIN{exit !(s+0>=7)}'; then LEVEL="High"; CLASS="high"
  elif awk -v s="$SCORE" 'BEGIN{exit !(s+0>=4)}'; then LEVEL="Medium"; CLASS="med"
  else LEVEL="Low"; CLASS="low"; fi

  # Kiểm tra module Metasploit (chỉ liệt kê, không chạy)
  MSF_MODULE="$(msfconsole -qx "search cve:${CVE}; exit" 2>/dev/null | awk '/^(exploit|auxiliary)\//{print $1; exit}')"
  if [[ -n "$MSF_MODULE" ]]; then
    MSF_SHOW="$MSF_MODULE"
    MSF_LINK="https://github.com/rapid7/metasploit-framework/tree/master/modules/${MSF_MODULE%/*}/${MSF_MODULE##*/}.rb"
    MSF_HTML="<a href=\"$MSF_LINK\" target=\"_blank\">$MSF_SHOW</a>"
  else
    MSF_HTML="Không có"
  fi

  # Exploit-DB link (trang search theo CVE)
  EDB_HTML="<a href=\"https://www.exploit-db.com/search?cve=$CVE\" target=\"_blank\">Tìm kiếm</a>"

  # GitHub PoC (chỉ liệt kê top 3 repo theo stars)
  GH_LINKS="$(curl -s "https://api.github.com/search/repositories?q=$CVE+exploit&sort=stars&order=desc&per_page=3" \
    | jq -r '.items[]?.html_url' 2>/dev/null)"
  if [[ -n "$GH_LINKS" ]]; then
    GH_HTML="<ul class=\"small\">"
    while read -r L; do GH_HTML+="<li><a href=\"$L\" target=\"_blank\">$L</a></li>"; done <<< "$GH_LINKS"
    GH_HTML+="</ul>"
  else
    GH_HTML="Không thấy PoC nổi bật"
  fi

  # NVD
  NVD_LINK="https://nvd.nist.gov/vuln/detail/$CVE"

  # Ghi dòng
  {
    echo "<tr>"
    echo "<td><a href=\"$NVD_LINK\" target=\"_blank\">$CVE</a></td>"
    echo "<td>$SCORE</td>"
    echo "<td class=\"badge $CLASS\">$LEVEL</td>"
    echo "<td>$MSF_HTML</td>"
    echo "<td>$EDB_HTML</td>"
    echo "<td>$GH_HTML</td>"
    echo "<td><a href=\"$NVD_LINK\" target=\"_blank\">NVD</a></td>"
    echo "</tr>"
  } >> "$HTML"

done < "$CVE_LIST"

# Thêm gợi ý khắc phục
cat >> "$HTML" <<'EOF'
</table>
<h3>Gợi ý xử lý/khắc phục</h3>
<ul class="small">
  <li>Ưu tiên vá các CVE <b>Critical/High</b> có PoC công khai hoặc module Metasploit.</li>
  <li>Triển khai ảo hoá mạng, tường lửa ứng dụng/IPS, tắt dịch vụ không cần thiết.</li>
  <li>Giám sát IOC/telemetry liên quan CVE có PoC phổ biến.</li>
  <li>Kiểm thử khai thác chỉ trong <b>môi trường lab</b> được phép, theo quy trình kiểm thử bảo mật.</li>
</ul>
</body></html>
EOF

echo "[+] Đã tạo báo cáo: $HTML"
echo "[i] Lưu ý: Script này KHÔNG tải/khởi chạy PoC. Dùng cho mục đích phân tích & phòng thủ."
