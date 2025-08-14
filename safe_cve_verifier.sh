#!/bin/bash
set -euo pipefail

# ========= SAFE CVE VERIFIER =========
# Mục tiêu: XÁC MINH an toàn, KHÔNG KHAI THÁC
# Yêu cầu: nmap, curl, jq, msfconsole, grep, awk, sort
# Dùng:
#   ./safe_cve_verifier.sh -t <IP_or_CIDR>        # tự quét bằng nmap
#   ./safe_cve_verifier.sh -f <nmap_output.txt>   # dùng file nmap sẵn

TARGET=""
NMAP_FILE=""
OUTDIR="safe_report"
NMAP_OUT="$OUTDIR/nmap_scan.txt"
CVE_LIST="$OUTDIR/cves.txt"
HTML="$OUTDIR/report.html"
LOG="$OUTDIR/msf_check.log"

mkdir -p "$OUTDIR"
: > "$CVE_LIST"
: > "$LOG"

need(){ command -v "$1" >/dev/null 2>&1 || { echo "[-] Thiếu: $1"; exit 1; }; }
for b in nmap curl jq msfconsole grep awk sort; do need "$b"; done

while getopts ":t:f:" opt; do
  case $opt in
    t) TARGET="$OPTARG" ;;
    f) NMAP_FILE="$OPTARG" ;;
    *) echo "Usage: $0 [-t TARGET] [-f NMAP_FILE]"; exit 1 ;;
  esac
done

if [[ -n "$TARGET" && -n "$NMAP_FILE" ]] || [[ -z "$TARGET" && -z "$NMAP_FILE" ]]; then
  echo "Chỉ chọn một: -t <TARGET> hoặc -f <NMAP_FILE>"; exit 1
fi

echo "[*] Thu thập dữ liệu..."
if [[ -n "$TARGET" ]]; then
  echo "[*] Nmap safe scan trên $TARGET (scripts vuln, không khai thác)"
  nmap -sV --script vuln "$TARGET" -oN "$NMAP_OUT"
else
  [[ -f "$NMAP_FILE" ]] || { echo "[-] Không thấy file: $NMAP_FILE"; exit 1; }
  cp "$NMAP_FILE" "$NMAP_OUT"
fi

echo "[*] Trích xuất CVE..."
grep -Eo "CVE-[0-9]{4}-[0-9]{4,7}" "$NMAP_OUT" | sort -u > "$CVE_LIST" || true
if [[ ! -s "$CVE_LIST" ]]; then
  echo "[!] Không tìm thấy CVE trong kết quả."; exit 0
fi

# Hàm lấy CVSS & mức độ
cvss_level(){
  local cve="$1" raw score level
  raw="$(curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}")"
  score="$(echo "$raw" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore // .vulnerabilities[0].cve.metrics.cvssMetricV30[0].cvssData.baseScore // .vulnerabilities[0].cve.metrics.cvssMetricV2[0].cvssData.baseScore // "0"')"
  [[ -z "$score" ]] && score="0"
  if awk -v s="$score" 'BEGIN{exit !(s+0>=9)}'; then level="Critical"
  elif awk -v s="$score" 'BEGIN{exit !(s+0>=7)}'; then level="High"
  elif awk -v s="$score" 'BEGIN{exit !(s+0>=4)}'; then level="Medium"
  else level="Low"; fi
  echo "$score|$level"
}

# HTML header
cat > "$HTML" <<'EOF'
<html><head><meta charset="utf-8">
<title>Safe CVE Verification Report</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;margin:24px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:8px;text-align:left}
th{background:#333;color:#fff}
.badge{font-weight:bold}
.crit{color:#b00020}.high{color:#e67e22}.med{color:#1f77b4}.low{color:#2e7d32}
.small{font-size:12px;color:#555}
code{background:#f5f5f5;padding:2px 4px;border-radius:4px}
</style>
</head><body>
<h2>Safe CVE Verification Report</h2>
<p class="small">Báo cáo xác minh an toàn (không khai thác). Dùng cho hệ thống thuộc sở hữu của bạn.</p>
<table>
<tr>
  <th>CVE</th><th>CVSS</th><th>Mức độ</th>
  <th>Metasploit (check)</th><th>Exploit-DB</th><th>GitHub PoC</th><th>NVD</th>
</tr>
EOF

# Duyệt CVE và chạy msf ở chế độ check (nếu module hỗ trợ)
while read -r CVE; do
  [[ -z "$CVE" ]] && continue

  IFS='|' read -r SCORE LEVEL <<<"$(cvss_level "$CVE")"
  CLASS="low"; [[ "$LEVEL" == "Critical" ]] && CLASS="crit" || [[ "$LEVEL" == "High" ]] && CLASS="high" || [[ "$LEVEL" == "Medium" ]] && CLASS="med"

  # Tìm module có hỗ trợ check
  MSF_MOD="$(msfconsole -qx "search cve:${CVE}; exit" 2>/dev/null | awk '/^exploit\//{print $1}' | head -n1)"
  CHECK_HTML="Không có"
  if [[ -n "$MSF_MOD" ]]; then
    echo "[*] $CVE -> thử check với $MSF_MOD" | tee -a "$LOG"
    # chỉ thực hiện 'check', không 'run'
    OUT="$(msfconsole -qx "use $MSF_MOD; set RHOSTS 127.0.0.1; check; exit" 2>/dev/null || true)"
    echo "$OUT" >> "$LOG"
    # Gom trạng thái xuất hiện trong output
    STATUS="$(echo "$OUT" | grep -E 'appears to be|is likely vulnerable|is not vulnerable|The target' | head -n1)"
    [[ -z "$STATUS" ]] && STATUS="(Module hỗ trợ có thể khác nhau; kết quả check không khả dụng cho mọi module.)"
    GH_MOD="https://github.com/rapid7/metasploit-framework/tree/master/modules/${MSF_MOD%/*}/${MSF_MOD##*/}.rb"
    CHECK_HTML="<div class='small'><a target='_blank' href='$GH_MOD'>$MSF_MOD</a><br/><em>$STATUS</em></div>"
  fi

  # Link tham khảo
  NVD="https://nvd.nist.gov/vuln/detail/$CVE"
  EDB="<a target='_blank' href='https://www.exploit-db.com/search?cve=$CVE'>Tìm kiếm</a>"
  GH_POC_HTML="Không thấy PoC nổi bật"
  GH_LINKS="$(curl -s "https://api.github.com/search/repositories?q=$CVE+exploit&sort=stars&order=desc&per_page=3" | jq -r '.items[]?.html_url' 2>/dev/null)"
  if [[ -n "$GH_LINKS" ]]; then
    GH_POC_HTML="<ul class='small'>"
    while read -r L; do GH_POC_HTML+="<li><a target='_blank' href='$L'>$L</a></li>"; done <<< "$GH_LINKS"
    GH_POC_HTML+="</ul>"
  fi

  {
    echo "<tr>"
    echo "<td><a target='_blank' href='$NVD'>$CVE</a></td>"
    echo "<td>$SCORE</td>"
    echo "<td class='badge $CLASS'>$LEVEL</td>"
    echo "<td>$CHECK_HTML</td>"
    echo "<td>$EDB</td>"
    echo "<td>$GH_POC_HTML</td>"
    echo "<td><a target='_blank' href='$NVD'>NVD</a></td>"
    echo "</tr>"
  } >> "$HTML"
done < "$CVE_LIST"

cat >> "$HTML" <<'EOF'
</table>
<h3>Khuyến nghị an toàn</h3>
<ul class="small">
  <li>Tạo snapshot/backup trước khi kiểm thử.</li>
  <li>Giới hạn IP nguồn kiểm thử bằng firewall/ACL; chạy trong VLAN lab cô lập.</li>
  <li>Ưu tiên xử lý CVE mức <b>Critical/High</b> có PoC công khai.</li>
  <li>Nếu cần tái hiện PoC, hãy thực hiện trong lab riêng, review mã thủ công trước khi chạy.</li>
</ul>
<p class="small">Ghi chú: Một số module Metasploit không hỗ trợ <code>check</code>; khi đó, cần đánh giá thủ công bằng phiên bản, banner, hoặc vendor advisory.</p>
</body></html>
EOF

echo "[+] Xong. Báo cáo: $HTML"
