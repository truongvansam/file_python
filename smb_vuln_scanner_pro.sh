#!/bin/bash

# Màu
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

TARGET=$1
REPORT_TXT="smb_report.txt"
REPORT_HTML="smb_report.html"
REPORT_JSON="smb_report.json"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

echo -e "${YELLOW}[*] Quét SMB trên $TARGET ...${NC}"
echo "===== SMB Vulnerability Scan Report =====" > $REPORT_TXT
echo "Target: $TARGET" >> $REPORT_TXT
echo "Date: $(date)" >> $REPORT_TXT
echo "" >> $REPORT_TXT

# 1. Kiểm tra port SMB
echo -e "${GREEN}[*] Kiểm tra port 139 và 445...${NC}"
nmap -p 139,445 $TARGET >> $REPORT_TXT

# 2. Quét version SMB
echo -e "${GREEN}[*] Quét version SMB...${NC}"
nmap -p 139,445 --script smb-os-discovery $TARGET >> $REPORT_TXT

# 3. Quét các lỗ hổng SMB
echo -e "${GREEN}[*] Quét lỗ hổng SMB với Nmap...${NC}"
nmap -p 139,445 --script smb-vuln* $TARGET -oN smb_vuln_nmap.txt
cat smb_vuln_nmap.txt >> $REPORT_TXT

# 4. Lấy CVE từ kết quả và phân loại mức độ
echo -e "${GREEN}[*] Trích xuất CVE và phân loại mức độ...${NC}"
grep -Eo "CVE-[0-9]{4}-[0-9]{4,7}" smb_vuln_nmap.txt | sort -u > cve_smb.txt

# 5. Kiểm tra CVE trong Metasploit và thêm link
> msf_smb.txt
echo "[" > $REPORT_JSON
while read CVE; do
    echo "[+] $CVE" >> msf_smb.txt

    # Thêm link CVE
    echo "CVE: $CVE" >> $REPORT_TXT
    echo "Link NVD: https://nvd.nist.gov/vuln/detail/$CVE" >> $REPORT_TXT
    echo "Link Exploit-DB: https://www.exploit-db.com/search?cve=$CVE" >> $REPORT_TXT

    # Tìm trong Metasploit
    MODULES=$(msfconsole -q -x "search $CVE; exit" | grep exploit | awk '{print $2}')
    if [ -n "$MODULES" ]; then
        echo -e "${RED}[CRITICAL] Có module khai thác: ${MODULES}${NC}"
        echo "Metasploit module: $MODULES" >> $REPORT_TXT
        echo "  - Sử dụng: msfconsole -q -x 'use $MODULES; set RHOSTS $TARGET; run'" >> $REPORT_TXT
        echo "{ \"cve\": \"$CVE\", \"severity\": \"Critical\", \"modules\": \"$MODULES\" }," >> $REPORT_JSON
    else
        echo -e "${YELLOW}[WARNING] Không tìm thấy module khai thác trực tiếp${NC}"
        echo "{ \"cve\": \"$CVE\", \"severity\": \"Unknown\", \"modules\": null }," >> $REPORT_JSON
    fi

    echo "" >> $REPORT_TXT
done < cve_smb.txt
echo "]" >> $REPORT_JSON

# 6. Enum SMB
echo -e "${GREEN}[*] Enumeration SMB với enum4linux-ng...${NC}"
enum4linux-ng.py $TARGET >> $REPORT_TXT

# 7. Xuất HTML
echo "<html><head><title>SMB Vulnerability Report</title></head><body>" > $REPORT_HTML
echo "<h2>SMB Vulnerability Report for $TARGET</h2><pre>" >> $REPORT_HTML
cat $REPORT_TXT >> $REPORT_HTML
echo "</pre></body></html>" >> $REPORT_HTML

echo -e "${GREEN}[*] Hoàn tất!${NC}"
echo "Báo cáo TXT: $REPORT_TXT"
echo "Báo cáo HTML: $REPORT_HTML"
echo "Báo cáo JSON: $REPORT_JSON"
