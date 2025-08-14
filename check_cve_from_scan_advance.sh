#!/bin/bash
TARGET=$1
SCAN_FILE="scan.txt"
CVE_FILE="cve_list.txt"
RESULT_FILE="result.txt"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

echo "[*] Quét lỗ hổng với Nmap..."
nmap -sV --script vulners $TARGET -oN $SCAN_FILE

echo "[*] Lọc CVE từ kết quả quét..."
grep -Eo "CVE-[0-9]{4}-[0-9]{4,7}" $SCAN_FILE | sort -u > $CVE_FILE

echo "[*] Kiểm tra và xếp hạng CVE..."
> $RESULT_FILE
while read CVE; do
    echo "[+] Đang kiểm tra $CVE ..."

    # Lấy điểm CVSS từ NVD
    SCORE=$(curl -s "https://services.nvd.nist.gov/rest/json/cve/1.0/$CVE" \
      | jq '.result.CVE_Items[].impact.baseMetricV3.cvssV3.baseScore' 2>/dev/null)

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

    echo "$CVE | Điểm: $SCORE | Metasploit: $MSF_STATUS | Exploit-DB: $EDB_STATUS" >> $RESULT_FILE
done < $CVE_FILE

# Sắp xếp theo điểm CVSS giảm dần
echo "[*] Kết quả xếp hạng:"
sort -t: -k2 -nr $RESULT_FILE
