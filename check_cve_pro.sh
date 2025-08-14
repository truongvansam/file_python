!/bin/bash
TARGET=$1
SCAN_FILE="scan.txt"
CVE_FILE="cve_list.txt"
HTML_FILE="cve_report.html"
TMP_FILE="result.tmp"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

echo "[*] Quét lỗ hổng với Nmap..."
nmap -sV --script vuln $TARGET -oN $SCAN_FILE

echo "[*] Lọc CVE từ kết quả quét..."
grep -Eo "CVE-[0-9]{4}-[0-9]{4,7}" $SCAN_FILE | sort -u > $CVE_FILE

echo "[*] Kiểm tra CVE..."
> $TMP_FILE
while read CVE; do
    echo "[+] Đang xử lý $CVE"

    # Lấy điểm CVSS từ NVD
    SCORE=$(curl -s "https://services.nvd.nist.gov/rest/json/cve/1.0/$CVE" \
      | jq '.result.CVE_Items[].impact.baseMetricV3.cvssV3.baseScore' 2>/dev/null)

    # Phân loại mức độ
    if (( $(echo "$SCORE >= 9.0" | bc -l) )); then
        LEVEL="Critical"
        COLOR="red"
    elif (( $(echo "$SCORE >= 7.0" | bc -l) )); then
        LEVEL="High"
        COLOR="orange"
    elif (( $(echo "$SCORE >= 4.0" | bc -l) )); then
        LEVEL="Medium"
        COLOR="blue"
    else
        LEVEL="Low"
        COLOR="green"
    fi

    # Kiểm tra trong Metasploit
    MSF_RESULT=$(msfconsole -q -x "search cve:$CVE; exit" | grep "$CVE")
    if [ ! -z "$MSF_RESULT" ]; then
        MSF_STATUS="Có module"
    else
        MSF_STATUS="Không module"
    fi

    # Kiểm tra trên Exploit-DB
    EXPLOITDB_RESULT=$(searchsploit $CVE | grep -v "No Results")
    if [ ! -z "$EXPLOITDB_RESULT" ]; then
        EDB_STATUS="Có exploit"
    else
        EDB_STATUS="Không exploit"
    fi

    echo "$CVE|$SCORE|$LEVEL|$COLOR|$MSF_STATUS|$EDB_STATUS" >> $TMP_FILE
done < $CVE_FILE

# Xuất HTML
echo "<html><head>
<title>CVE Scan Report</title>
<style>
body { font-family: Arial; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #333; color: white; }
tr:hover { background-color: #f1f1f1; }
</style>
</head><body>
<h2>Báo cáo CVE cho $TARGET</h2>
<table>
<tr><th>CVE</th><th>CVSS Score</th><th>Mức độ</th><th>Metasploit</th><th>Exploit-DB</th></tr>" > $HTML_FILE

sort -t"|" -k2 -nr $TMP_FILE | while IFS="|" read CVE SCORE LEVEL COLOR MSF_STATUS EDB_STATUS; do
    echo "<tr>
    <td>$CVE</td>
    <td>$SCORE</td>
    <td style='color:$COLOR;'>$LEVEL</td>
    <td>$MSF_STATUS</td>
    <td>$EDB_STATUS</td>
    </tr>" >> $HTML_FILE
done

echo "</table></body></html>" >> $HTML_FILE

echo "[*] Báo cáo đã lưu tại: $HTML_FILE"
