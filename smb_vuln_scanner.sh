#!/bin/bash

TARGET=$1
REPORT_TXT="smb_report.txt"
REPORT_HTML="smb_report.html"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

echo "[*] Quét SMB trên $TARGET ..."
echo "===== SMB Vulnerability Scan Report =====" > $REPORT_TXT
echo "Target: $TARGET" >> $REPORT_TXT
echo "Date: $(date)" >> $REPORT_TXT
echo "" >> $REPORT_TXT

# 1. Kiểm tra port SMB
echo "[*] Kiểm tra port 139 và 445..."
nmap -p 139,445 $TARGET >> $REPORT_TXT

# 2. Quét version SMB
echo "[*] Quét version SMB..."
nmap -p 139,445 --script smb-os-discovery $TARGET >> $REPORT_TXT

# 3. Quét các lỗ hổng SMB
echo "[*] Quét lỗ hổng SMB với Nmap..."
nmap -p 139,445 --script smb-vuln* $TARGET -oN smb_vuln_nmap.txt
cat smb_vuln_nmap.txt >> $REPORT_TXT

# 4. Lấy CVE từ kết quả
echo "[*] Trích xuất CVE..."
grep -Eo "CVE-[0-9]{4}-[0-9]{4,7}" smb_vuln_nmap.txt | sort -u > cve_smb.txt

# 5. Kiểm tra trong Metasploit
echo "[*] Kiểm tra CVE trong Metasploit..."
> msf_smb.txt
while read CVE; do
    echo "[+] $CVE" >> msf_smb.txt
    msfconsole -q -x "search $CVE; exit" | grep "$CVE" >> msf_smb.txt
done < cve_smb.txt
cat msf_smb.txt >> $REPORT_TXT

# 6. Sử dụng Enum4linux-ng để enum SMB
echo "[*] Enumeration SMB với enum4linux-ng..."
enum4linux-ng.py $TARGET >> $REPORT_TXT

# 7. Xuất HTML báo cáo
echo "<html><head><title>SMB Vulnerability Report</title></head><body>" > $REPORT_HTML
echo "<h2>SMB Vulnerability Report for $TARGET</h2><pre>" >> $REPORT_HTML
cat $REPORT_TXT >> $REPORT_HTML
echo "</pre></body></html>" >> $REPORT_HTML

echo "[*] Hoàn tất! Báo cáo TXT: $REPORT_TXT | HTML: $REPORT_HTML"
