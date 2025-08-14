#!/bin/bash
TARGET=$1
SCAN_FILE="scan.txt"
CVE_FILE="cve_list.txt"

echo "[*] Quét lỗ hổng với Nmap..."
nmap -sV --script vuln $TARGET -oN $SCAN_FILE

echo "[*] Lọc CVE từ kết quả quét..."
grep -Eo "CVE-[0-9]{4}-[0-9]{4,7}" $SCAN_FILE | sort -u > $CVE_FILE

echo "[*] Kiểm tra trong Metasploit..."
while read cve; do
    echo "[+] $cve"
    msfconsole -q -x "search cve:$cve; exit" | grep "$cve"
done < $CVE_FILE

echo "[*] Kiểm tra trên Exploit-DB..."
while read cve; do
    echo "[+] $cve"
    searchsploit $cve
done < $CVE_FILE
