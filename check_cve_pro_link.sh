#!/bin/bash
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
nmap -sV --script vulners $TARGET -oN $SCAN_FILE

echo "[*] Lọc CVE từ kết quả quét..."
grep -Eo "CVE-[0-9]{4}-[0-9]{4,7}" $SCAN_FILE | sort -u > $CVE_FILE

echo "[*] Kiểm tra CVE..."
> $TMP_FILE
while read CVE; do
    echo "[+] Đang xử lý $CVE"

    # Link NVD
    NVD_LINK="https://nvd.nist.gov/vuln/detail/$CVE"

    # Lấy điểm CVSS
    SCORE=$(curl -s "https://services.nvd.nist.gov/rest/json/cve/1.0/$CVE" \
      | jq '.result.CVE_Items[].impact.baseMetricV3.cvssV3.baseScore' 2>/dev/null)

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

    # Metasploit
    MSF_RESULT=$(msfconsole -q -x "search cve:$CVE; exit" | grep "$CVE")
    if [ ! -z "$MSF_RESULT" ]; then
        MSF_STATUS="Có module"
        MSF_LINK="https://www.rapid7.com/db/modules/$(echo $MSF_RESULT | awk '{print $1}')"
    else
        MSF_STATUS="Không module"
        MSF_LINK=""
    fi

    # Exploit-DB
    EXPLOITDB_RESULT=$(searchsploit --json $CVE | jq -r '.RESULTS_EXPLOIT[]?.Path' 2>/dev/null)
    if [ ! -z "$EXPLOITDB_RESULT" ]; then
        EDB_STATUS="Có exploit"
        EDB_ID=$(basename "$EXPLOITDB_RESULT" | cut -d'.' -f1)
        EDB_LINK="https://www.exploit-db.com/exploits/$EDB_ID"
    else
        EDB_STATUS="Không exploit"
        EDB_LINK=""
    fi

    echo "$CVE|$SCORE|$LEVEL|$COLOR|$MSF_STATUS|$MSF_LINK|$EDB_STATUS|$EDB_LINK|$NVD_LINK" >> $TMP_FILE
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
<tr>
<th>CVE</th><th>CVSS Score</th><th>Mức độ</th>
<th>Metasploit</th><th>Exploit-DB</th><th>NVD</th>
</tr>" > $HTML_FILE

sort -t"|" -k2 -nr $TMP_FILE | while IFS="|" read CVE SCORE LEVEL COLOR MSF_STATUS MSF_LINK EDB_STATUS EDB_LINK NVD_LINK; do
    echo "<tr>
    <td><a href='$NVD_LINK' target='_blank'>$CVE</a></td>
    <td>$SCORE</td>
    <td style='color:$COLOR;'>$LEVEL</td>
    <td>$( [ -n "$MSF_LINK" ] && echo "<a href='$MSF_LINK' target='_blank'>$MSF_STATUS</a>" || echo "$MSF_STATUS" )</td>
    <td>$( [ -n "$EDB_LINK" ] && echo "<a href='$EDB_LINK' target='_blank'>$EDB_STATUS</a>" || echo "$EDB_STATUS" )</td>
    <td><a href='$NVD_LINK' target='_blank'>Xem</a></td>
    </tr>" >> $HTML_FILE
done

echo "</table></body></html>" >> $HTML_FILE

echo "[*] Báo cáo đã lưu tại: $HTML_FILE
