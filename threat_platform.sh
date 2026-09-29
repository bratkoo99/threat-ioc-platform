#!/usr/bin/env bash
#
#  ================================================================
#           THREAT INTELLIGENCE & IOC SCANNER PLATFORM
#           Business Platform Proposal - Main Console
#           Ransomware Detection & Threat Hunting Suite
#  ================================================================
#

#  ---------------- CONFIGURATION ----------------
PLATFORM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_SRC="$PLATFORM_DIR/ioc_scanner.c"
SCANNER_BIN="$PLATFORM_DIR/ioc_scanner"
IOC_DB_DIR="$PLATFORM_DIR/ioc_databases"
REPORT_DIR="$PLATFORM_DIR/reports"
LOG_DIR="$PLATFORM_DIR/logs"
# IOC research document. Kept OUT of git on purpose: it is a working data file,
# not source. Overridable with TIOX_RESEARCH_FILE.
RESEARCH_FILE="${TIOX_RESEARCH_FILE:-$PLATFORM_DIR/data/IOC-C2-Known_servers.local}"
MAKEFILE="$PLATFORM_DIR/Makefile"
TIMESTAMP="$(date '+%Y-%m-%d_%H-%M-%S')"

#  ---------------- COLORS ----------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

#  ---------------- INIT ----------------
mkdir -p "$IOC_DB_DIR" "$REPORT_DIR" "$LOG_DIR"

#  ---------------- BANNER ----------------
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "  ================================================================"
    echo "           THREAT INTELLIGENCE & IOC SCANNER PLATFORM"
    echo "           Business Platform Proposal - Main Console"
    echo "           Ransomware Detection & Threat Hunting Suite"
    echo "  ================================================================"
    echo -e "${NC}"
    echo -e "  ${DIM}Date: $(date '+%Y-%m-%d %H:%M:%S')  |  Host: $(hostname)  |  User: $(whoami)${NC}"
    echo ""
}

#  ---------------- MENU ----------------
show_menu() {
    local W="${WHITE}" N="${NC}" G="${GREEN}" Y="${YELLOW}" M="${MAGENTA}" C="${CYAN}" R="${RED}"
    echo -e "${W}  +--------------------------------------------------------------+${N}"
    echo -e "${W}  |                    MAIN MENU                                 |${N}"
    echo -e "${W}  +--------------------------------------------------------------+${N}"
    echo -e "${W}  |${N}  ${G}[1]${N}  Compile / Rebuild Scanner                              ${W}|${N}"
    echo -e "${W}  |${N}  ${G}[2]${N}  Quick Scan (system-wide, hash-skip)                    ${W}|${N}"
    echo -e "${W}  |${N}  ${G}[3]${N}  Full Scan (deep, with hash matching)                  ${W}|${N}"
    echo -e "${W}  |${N}  ${G}[4]${N}  Custom Scan (choose path & options)                   ${W}|${N}"
    echo -e "${W}  |${N}  ${G}[5]${N}  Scan Single File                                     ${W}|${N}"
    echo -e "${W}  +--------------------------------------------------------------+${N}"
    echo -e "${W}  |${N}  ${Y}[6]${N}  View IOC Research Document                            ${W}|${N}"
    echo -e "${W}  |${N}  ${Y}[7]${N}  Manage IOC Databases                                  ${W}|${N}"
    echo -e "${W}  |${N}  ${Y}[8]${N}  Import IOCs from CSV                                 ${W}|${N}"
    echo -e "${W}  |${N}  ${Y}[9]${N}  View Scan Reports                                    ${W}|${N}"
    echo -e "${W}  +--------------------------------------------------------------+${N}"
    echo -e "${W}  |${N}  ${M}[10]${N} Threat Intel Lookup (hash/pattern search)             ${W}|${N}"
    echo -e "${W}  |${N}  ${M}[11]${N} Generate IOC Report                                  ${W}|${N}"
    echo -e "${W}  |${N}  ${M}[12]${N} Run Scanner Self-Test                                ${W}|${N}"
    echo -e "${W}  +--------------------------------------------------------------+${N}"
    echo -e "${W}  |${N}  ${C}[13]${N} Launch Web Dashboard (port 8443)                      ${W}|${N}"
    echo -e "${W}  +--------------------------------------------------------------+${N}"
    echo -e "${W}  |${N}  ${R}[0]${N}  Exit                                                  ${W}|${N}"
    echo -e "${W}  +--------------------------------------------------------------+${N}"
    echo ""
}

#  ---------------- UTILITIES ----------------
log_action() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $1" >> "$LOG_DIR/platform.log"
}

pause() {
    echo ""
    read -n 1 -s -r -p "  Press any key to continue..."
    echo ""
}

check_scanner() {
    if [ ! -f "$SCANNER_BIN" ]; then
        echo -e "  ${YELLOW}Scanner not compiled. Building now...${NC}"
        compile_scanner
    fi
}

#  ---------------- [1] COMPILE ----------------
compile_scanner() {
    echo -e "\n  ${CYAN}===== COMPILING IOC SCANNER =====${NC}\n"
    
    if [ ! -f "$SCANNER_SRC" ]; then
        echo -e "  ${RED}ERROR: Source file not found: $SCANNER_SRC${NC}"
        log_action "COMPILE FAILED: source not found"
        pause
        return 1
    fi

    local missing_deps=()
    
    if ! command -v gcc &>/dev/null; then
        missing_deps+=("gcc")
    fi
    
    if ! pkg-config --exists openssl 2>/dev/null && [ ! -f /usr/include/openssl/sha.h ]; then
        missing_deps+=("libssl-dev/openssl-devel")
    fi

    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo -e "  ${YELLOW}Missing dependencies: ${missing_deps[*]}${NC}"
        echo -e "  ${DIM}Install with: sudo apt install gcc libssl-dev${NC}"
        echo -e "  ${DIM}          or: sudo dnf install gcc openssl-devel${NC}"
        log_action "COMPILE FAILED: missing deps: ${missing_deps[*]}"
        pause
        return 1
    fi

    echo -e "  ${DIM}Compiling ioc_scanner.c...${NC}"
    
    if [ -f "$MAKEFILE" ]; then
        cd "$PLATFORM_DIR" && make clean && make 2>&1
    else
        gcc -O2 -Wall -Wextra -std=c11 -o "$SCANNER_BIN" "$SCANNER_SRC" -lssl -lcrypto 2>&1
    fi

    if [ -f "$SCANNER_BIN" ]; then
        echo -e "\n  ${GREEN}[OK] Scanner compiled successfully!${NC}"
        echo -e "  ${DIM}Binary: $SCANNER_BIN${NC}"
        log_action "COMPILE SUCCESS"
    else
        echo -e "\n  ${RED}[FAIL] Compilation failed!${NC}"
        log_action "COMPILE FAILED"
    fi
    pause
}

#  ---------------- [2] QUICK SCAN ----------------
quick_scan() {
    echo -e "\n  ${CYAN}===== QUICK SYSTEM SCAN =====${NC}\n"
    check_scanner
    
    echo -e "  ${YELLOW}Starting quick scan of / (skipping hash computation)...${NC}"
    echo -e "  ${DIM}This may take a few minutes...${NC}\n"
    
    local report_file="$REPORT_DIR/quick_scan_$TIMESTAMP.txt"
    
    echo "===================================================" > "$report_file"
    echo "  QUICK SCAN REPORT - $TIMESTAMP" >> "$report_file"
    echo "===================================================" >> "$report_file"
    echo "" >> "$report_file"
    
    "$SCANNER_BIN" -Q -v / 2>&1 | tee -a "$report_file"
    local exit_code=$?
    
    echo "" >> "$report_file"
    echo "---------------------------------------------------" >> "$report_file"
    echo "Scan completed at $(date '+%Y-%m-%d %H:%M:%S')" >> "$report_file"
    echo "Exit code: $exit_code" >> "$report_file"
    
    echo -e "\n  ${GREEN}Report saved to: $report_file${NC}"
    log_action "QUICK SCAN completed (exit: $exit_code)"
    pause
}

#  ---------------- [3] FULL SCAN ----------------
full_scan() {
    echo -e "\n  ${CYAN}===== FULL DEEP SCAN =====${NC}\n"
    check_scanner
    
    echo -e "  ${YELLOW}Starting full system scan (with hash matching)...${NC}"
    echo -e "  ${DIM}This will take significantly longer...${NC}\n"
    
    local report_file="$REPORT_DIR/full_scan_$TIMESTAMP.txt"
    
    echo "===================================================" > "$report_file"
    echo "  FULL SCAN REPORT - $TIMESTAMP" >> "$report_file"
    echo "===================================================" >> "$report_file"
    echo "" >> "$report_file"
    
    "$SCANNER_BIN" -v / 2>&1 | tee -a "$report_file"
    local exit_code=$?
    
    echo "" >> "$report_file"
    echo "---------------------------------------------------" >> "$report_file"
    echo "Scan completed at $(date '+%Y-%m-%d %H:%M:%S')" >> "$report_file"
    echo "Exit code: $exit_code" >> "$report_file"
    
    echo -e "\n  ${GREEN}Report saved to: $report_file${NC}"
    log_action "FULL SCAN completed (exit: $exit_code)"
    pause
}

#  ---------------- [4] CUSTOM SCAN ----------------
custom_scan() {
    echo -e "\n  ${CYAN}===== CUSTOM SCAN =====${NC}\n"
    check_scanner
    
    echo -e "  ${WHITE}Enter target path:${NC}"
    read -r -p "  > " scan_path
    
    if [ -z "$scan_path" ] || [ ! -e "$scan_path" ]; then
        echo -e "  ${RED}Invalid path!${NC}"
        pause
        return
    fi
    
    echo -e "  ${WHITE}Scan mode:${NC}"
    echo -e "    ${GREEN}1${NC}  Quick (skip hashes)"
    echo -e "    ${GREEN}2${NC}  Full (with hashes)"
    read -r -p "  > " mode_choice
    
    echo -e "  ${WHITE}Max depth (default 32):${NC}"
    read -r -p "  > " depth_choice
    depth_choice=${depth_choice:-32}
    
    echo -e "  ${WHITE}Verbose output? (y/n):${NC}"
    read -r -p "  > " verbose_choice
    
    local flags="-D $depth_choice"
    [ "$mode_choice" = "1" ] && flags="-Q $flags"
    [[ "$verbose_choice" =~ ^[Yy]$ ]] && flags="-v $flags"
    
    echo -e "\n  ${YELLOW}Scanning: $scan_path${NC}"
    echo -e "  ${DIM}Flags: $flags${NC}\n"
    
    local report_file="$REPORT_DIR/custom_scan_$TIMESTAMP.txt"
    
    echo "===================================================" > "$report_file"
    echo "  CUSTOM SCAN REPORT - $TIMESTAMP" >> "$report_file"
    echo "  Target: $scan_path" >> "$report_file"
    echo "  Flags: $flags" >> "$report_file"
    echo "===================================================" >> "$report_file"
    echo "" >> "$report_file"
    
    "$SCANNER_BIN" $flags "$scan_path" 2>&1 | tee -a "$report_file"
    local exit_code=$?
    
    echo "" >> "$report_file"
    echo "---------------------------------------------------" >> "$report_file"
    echo "Scan completed at $(date '+%Y-%m-%d %H:%M:%S')" >> "$report_file"
    echo "Exit code: $exit_code" >> "$report_file"
    
    echo -e "\n  ${GREEN}Report saved to: $report_file${NC}"
    log_action "CUSTOM SCAN: $scan_path (exit: $exit_code)"
    pause
}

#  ---------------- [5] SCAN SINGLE FILE ----------------
scan_single_file() {
    echo -e "\n  ${CYAN}===== SINGLE FILE SCAN =====${NC}\n"
    check_scanner
    
    echo -e "  ${WHITE}Enter file path:${NC}"
    read -r -p "  > " file_path
    
    if [ -z "$file_path" ] || [ ! -f "$file_path" ]; then
        echo -e "  ${RED}File not found!${NC}"
        pause
        return
    fi
    
    echo -e "\n  ${YELLOW}Scanning: $file_path${NC}\n"
    
    "$SCANNER_BIN" -v "$file_path" 2>&1
    local exit_code=$?
    
    if [ $exit_code -eq 2 ]; then
        echo -e "\n  ${RED}!! THREAT DETECTED !!${NC}"
    elif [ $exit_code -eq 0 ]; then
        echo -e "\n  ${GREEN}[OK] File appears clean.${NC}"
    fi
    
    log_action "SINGLE FILE SCAN: $file_path (exit: $exit_code)"
    pause
}

#  ---------------- [6] VIEW RESEARCH ----------------
view_research() {
    echo -e "\n  ${CYAN}===== IOC RESEARCH DOCUMENT =====${NC}\n"
    
    if [ ! -f "$RESEARCH_FILE" ]; then
        echo -e "  ${RED}Research file not found!${NC}"
        pause
        return
    fi
    
    echo -e "  ${WHITE}Research Document Options:${NC}"
    echo -e "    ${GREEN}1${NC}  View full document (paginated)"
    echo -e "    ${GREEN}2${NC}  Search for keyword"
    echo -e "    ${GREEN}3${NC}  Show document statistics"
    echo -e "    ${GREEN}4${NC}  Extract ransomware group names"
    read -r -p "  > " research_choice
    
    case $research_choice in
        1)
            echo ""
            if command -v less &>/dev/null; then
                less -R "$RESEARCH_FILE"
            else
                head -100 "$RESEARCH_FILE"
                echo -e "\n  ${DIM}... (showing first 100 lines, install less for full pagination)${NC}"
            fi
            ;;
        2)
            echo -e "  ${WHITE}Enter search term:${NC}"
            read -r -p "  > " search_term
            echo ""
            grep -n -i --color=always "$search_term" "$RESEARCH_FILE" | head -50
            echo ""
            local count
            count=$(grep -c -i "$search_term" "$RESEARCH_FILE")
            echo -e "  ${DIM}$count matches found${NC}"
            ;;
        3)
            echo -e "\n  ${WHITE}Document Statistics:${NC}"
            echo -e "  -----------------------------"
            echo -e "  Total lines:    $(wc -l < "$RESEARCH_FILE")"
            echo -e "  Total words:    $(wc -w < "$RESEARCH_FILE")"
            echo -e "  Total bytes:    $(wc -c < "$RESEARCH_FILE")"
            echo -e "  Ransomware groups mentioned:"
            local p1='(LockBit|BlackCat|ALPHV|Black Basta|Royal|Cl0p|Play|Medusa|Akira)'
            local p2='(Inc Ransom|BassterHunter|QakBot|Cobalt Strike|Mimikats|Conti|REvil)'
            local p3='(Sodinokibi|DarkSide|Avlocker|Phobos|Dharma|Ryuk|MaLock|CryptOn)'
            local p4='(HiBye|NoCry|Zeppelin|Netwalker|Ragnar|Mount Locker|XDLV|XData)'
            local p5='(Bad Rabbit|Petya|NotPtya|GoldenEye|WannaCry|Cryptolocker|Cerber)'
            local p6='(CTB-Locker|Jigsaw|SamSam|Maktub|LambdaLocker|Linux.Encoder|KeRanger)'
            local p7='(FileCoder|Thor|MacRansom|Patcher|ThiefQuest|GinX)'
            grep -oiE "${p1}${p2}${p3}${p4}${p5}${p6}${p7}" "$RESEARCH_FILE" 2>/dev/null | sort | uniq -c | sort -rn | head -20
            ;;
        4)
            echo -e "\n  ${WHITE}Ransomware Groups Found:${NC}"
            echo -e "  -----------------------------"
            grep -iE '(ransomware group|threat actor|APT|campaign)' "$RESEARCH_FILE" | head -20
            ;;
    esac
    log_action "VIEW RESEARCH: option $research_choice"
    pause
}

#  ---------------- [7] MANAGE IOC DATABASES ----------------
manage_databases() {
    while true; do
        echo -e "\n  ${CYAN}===== IOC DATABASE MANAGEMENT =====${NC}\n"
        
        echo -e "  ${WHITE}Current databases in $IOC_DB_DIR:${NC}"
        echo -e "  -----------------------------"
        
        if [ -z "$(ls -A "$IOC_DB_DIR" 2>/dev/null)" ]; then
            echo -e "  ${DIM}(empty)${NC}"
        else
            local i=1
            for f in "$IOC_DB_DIR"/*; do
                [ -f "$f" ] && echo -e "  ${GREEN}$i${NC} $(basename "$f") ($(wc -c < "$f") bytes)"
                i=$((i+1))
            done
        fi
        
        echo ""
        echo -e "  ${WHITE}Options:${NC}"
        echo -e "    ${GREEN}1${NC}  Create new database"
        echo -e "    ${GREEN}2${NC}  View database contents"
        echo -e "    ${GREEN}3${NC}  Delete database"
        echo -e "    ${GREEN}4${NC}  Add entry to database"
        echo -e "    ${GREEN}5${NC}  Export database to CSV"
        echo -e "    ${GREEN}0${NC}  Back to main menu"
        read -r -p "  > " db_choice
        
        case $db_choice in
            1)
                echo -e "  ${WHITE}Database name (without extension):${NC}"
                read -r -p "  > " db_name
                echo -e "  ${WHITE}Type:${NC} 1) Hashes  2) Patterns"
                read -r -p "  > " db_type
                if [ "$db_type" = "1" ]; then
                    echo "# SHA-256 Hash,Family,Description" > "$IOC_DB_DIR/${db_name}_hashes.csv"
                    echo -e "  ${GREEN}Created: ${db_name}_hashes.csv${NC}"
                else
                    echo "# Pattern,Family,Description,IsExtension" > "$IOC_DB_DIR/${db_name}_patterns.csv"
                    echo -e "  ${GREEN}Created: ${db_name}_patterns.csv${NC}"
                fi
                ;;
            2)
                echo -e "  ${WHITE}Enter database filename:${NC}"
                read -r -p "  > " db_file
                if [ -f "$IOC_DB_DIR/$db_file" ]; then
                    echo ""
                    head -50 "$IOC_DB_DIR/$db_file"
                    echo -e "\n  ${DIM}... ($(wc -l < "$IOC_DB_DIR/$db_file") total lines)${NC}"
                else
                    echo -e "  ${RED}File not found!${NC}"
                fi
                ;;
            3)
                echo -e "  ${WHITE}Enter database filename to DELETE:${NC}"
                read -r -p "  > " db_file
                if [ -f "$IOC_DB_DIR/$db_file" ]; then
                    rm -i "$IOC_DB_DIR/$db_file"
                else
                    echo -e "  ${RED}File not found!${NC}"
                fi
                ;;
            4)
                echo -e "  ${WHITE}Enter database filename:${NC}"
                read -r -p "  > " db_file
                if [ -f "$IOC_DB_DIR/$db_file" ]; then
                    echo -e "  ${WHITE}Enter value (hash or pattern):${NC}"
                    read -r -p "  > " entry_value
                    echo -e "  ${WHITE}Family/Group:${NC}"
                    read -r -p "  > " entry_family
                    echo -e "  ${WHITE}Description:${NC}"
                    read -r -p "  > " entry_desc
                    echo "$entry_value,$entry_family,$entry_desc" >> "$IOC_DB_DIR/$db_file"
                    echo -e "  ${GREEN}Entry added!${NC}"
                else
                    echo -e "  ${RED}File not found!${NC}"
                fi
                ;;
            5)
                echo -e "  ${WHITE}Enter database filename:${NC}"
                read -r -p "  > " db_file
                if [ -f "$IOC_DB_DIR/$db_file" ]; then
                    cp "$IOC_DB_DIR/$db_file" "$REPORT_DIR/export_${db_file%.csv}_$TIMESTAMP.csv"
                    echo -e "  ${GREEN}Exported to: $REPORT_DIR/export_${db_file%.csv}_$TIMESTAMP.csv${NC}"
                fi
                ;;
            0) break ;;
        esac
        log_action "DB MANAGE: option $db_choice"
        pause
    done
}

#  ---------------- [8] IMPORT IOCs ----------------
import_iocs() {
    echo -e "\n  ${CYAN}===== IMPORT IOCs FROM CSV =====${NC}\n"
    
    echo -e "  ${WHITE}CSV Import Options:${NC}"
    echo -e "    ${GREEN}1${NC}  Import from local file"
    echo -e "    ${GREEN}2${NC}  Import from URL (curl)"
    echo -e "    ${GREEN}3${NC}  Paste IOCs manually"
    read -r -p "  > " import_choice
    
    case $import_choice in
        1)
            echo -e "  ${WHITE}Enter CSV file path:${NC}"
            read -r -p "  > " csv_path
            if [ -f "$csv_path" ]; then
                echo -e "  ${WHITE}Import as:${NC} 1) Hashes  2) Patterns"
                read -r -p "  > " import_type
                if [ "$import_type" = "1" ]; then
                    cp "$csv_path" "$IOC_DB_DIR/imported_hashes_$TIMESTAMP.csv"
                else
                    cp "$csv_path" "$IOC_DB_DIR/imported_patterns_$TIMESTAMP.csv"
                fi
                echo -e "  ${GREEN}Imported successfully!${NC}"
                echo -e "  ${DIM}$(wc -l < "$csv_path") lines imported${NC}"
            else
                echo -e "  ${RED}File not found!${NC}"
            fi
            ;;
        2)
            echo -e "  ${WHITE}Enter CSV URL:${NC}"
            read -r -p "  > " csv_url
            echo -e "  ${WHITE}Import as:${NC} 1) Hashes  2) Patterns"
            read -r -p "  > " import_type
            if [ "$import_type" = "1" ]; then
                curl -sL "$csv_url" -o "$IOC_DB_DIR/imported_hashes_$TIMESTAMP.csv"
            else
                curl -sL "$csv_url" -o "$IOC_DB_DIR/imported_patterns_$TIMESTAMP.csv"
            fi
            echo -e "  ${GREEN}Downloaded and imported!${NC}"
            ;;
        3)
            echo -e "  ${WHITE}Enter IOCs (one per line, Ctrl+D when done):${NC}"
            local temp_file="$IOC_DB_DIR/manual_import_$TIMESTAMP.csv"
            echo "# Manually imported IOCs - $TIMESTAMP" > "$temp_file"
            echo "# Value,Family,Description" >> "$temp_file"
            while IFS= read -r line; do
                [ -n "$line" ] && echo "$line" >> "$temp_file"
            done
            echo -e "  ${GREEN}Imported to: $temp_file${NC}"
            ;;
    esac
    log_action "IMPORT IOCs: option $import_choice"
    pause
}

#  ---------------- [9] VIEW REPORTS ----------------
view_reports() {
    echo -e "\n  ${CYAN}===== SCAN REPORTS =====${NC}\n"
    
    echo -e "  ${WHITE}Available reports:${NC}"
    echo -e "  -----------------------------"
    
    if [ -z "$(ls -A "$REPORT_DIR" 2>/dev/null)" ]; then
        echo -e "  ${DIM}(no reports yet)${NC}"
        pause
        return
    fi
    
    local i=1
    for f in "$REPORT_DIR"/*; do
        [ -f "$f" ] && echo -e "  ${GREEN}$i${NC} $(basename "$f") ($(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null) bytes)"
        i=$((i+1))
    done
    
    echo ""
    echo -e "  ${WHITE}Options:${NC}"
    echo -e "    ${GREEN}1${NC}  View a report"
    echo -e "    ${GREEN}2${NC}  Delete old reports"
    echo -e "    ${GREEN}3${NC}  Compare two reports"
    echo -e "    ${GREEN}0${NC}  Back"
    read -r -p "  > " report_choice
    
    case $report_choice in
        1)
            echo -e "  ${WHITE}Enter report number:${NC}"
            read -r -p "  > " report_num
            local file
            file=$(ls "$REPORT_DIR"/* 2>/dev/null | sed -n "${report_num}p")
            if [ -f "$file" ]; then
                echo ""
                cat "$file"
            fi
            ;;
        2)
            echo -e "  ${WHITE}Delete reports older than (days):${NC}"
            read -r -p "  > " days_old
            find "$REPORT_DIR" -type f -mtime +"$days_old" -delete 2>/dev/null
            echo -e "  ${GREEN}Old reports deleted.${NC}"
            ;;
        3)
            echo -e "  ${WHITE}Select two report numbers to compare:${NC}"
            read -r -p "  > " r1 r2
            local f1 f2
            f1=$(ls "$REPORT_DIR"/* 2>/dev/null | sed -n "${r1}p")
            f2=$(ls "$REPORT_DIR"/* 2>/dev/null | sed -n "${r2}p")
            if [ -f "$f1" ] && [ -f "$f2" ]; then
                echo -e "\n  ${CYAN}=== DIFF ===${NC}\n"
                diff --color=always "$f1" "$f2" | head -100
            fi
            ;;
    esac
    log_action "VIEW REPORTS: option $report_choice"
    pause
}

#  ---------------- [10] THREAT INTEL LOOKUP ----------------
threat_intel_lookup() {
    echo -e "\n  ${CYAN}===== THREAT INTEL LOOKUP =====${NC}\n"
    
    echo -e "  ${WHITE}Lookup type:${NC}"
    echo -e "    ${GREEN}1${NC}  Search by hash"
    echo -e "    ${GREEN}2${NC}  Search by pattern/filename"
    echo -e "    ${GREEN}3${NC}  Search by ransomware family"
    echo -e "    ${GREEN}4${NC}  Search research document"
    read -r -p "  > " lookup_choice
    
    echo -e "  ${WHITE}Enter search term:${NC}"
    read -r -p "  > " search_term
    
    echo -e "\n  ${CYAN}===== SEARCH RESULTS =====${NC}\n"
    
    case $lookup_choice in
        1)
            echo -e "  ${WHITE}Searching databases for hash: $search_term${NC}\n"
            for db in "$IOC_DB_DIR"/*; do
                [ -f "$db" ] && grep -i "$search_term" "$db" 2>/dev/null
            done
            echo -e "  ${WHITE}Searching research document...${NC}\n"
            grep -i "$search_term" "$RESEARCH_FILE" 2>/dev/null | head -10
            ;;
        2)
            echo -e "  ${WHITE}Searching databases for pattern: $search_term${NC}\n"
            for db in "$IOC_DB_DIR"/*; do
                [ -f "$db" ] && grep -i "$search_term" "$db" 2>/dev/null
            done
            ;;
        3)
            echo -e "  ${WHITE}Searching for family: $search_term${NC}\n"
            for db in "$IOC_DB_DIR"/*; do
                [ -f "$db" ] && grep -i "$search_term" "$db" 2>/dev/null
            done
            echo -e "  ${WHITE}Research document matches:${NC}\n"
            grep -i "$search_term" "$RESEARCH_FILE" 2>/dev/null | head -20
            ;;
        4)
            echo -e "  ${WHITE}Searching research document...${NC}\n"
            grep -n -i --color=always "$search_term" "$RESEARCH_FILE" | head -30
            echo ""
            local count
            count=$(grep -c -i "$search_term" "$RESEARCH_FILE")
            echo -e "  ${DIM}$count matches found${NC}"
            ;;
    esac
    
    log_action "THREAT INTEL LOOKUP: type $lookup_choice, term: $search_term"
    pause
}

#  ---------------- [11] GENERATE IOC REPORT ----------------
generate_ioc_report() {
    echo -e "\n  ${CYAN}===== GENERATE IOC REPORT =====${NC}\n"
    
    local report_file="$REPORT_DIR/ioc_summary_$TIMESTAMP.txt"
    
    echo "===================================================" > "$report_file"
    echo "  IOC SUMMARY REPORT" >> "$report_file"
    echo "  Generated: $(date '+%Y-%m-%d %H:%M:%S')" >> "$report_file"
    echo "===================================================" >> "$report_file"
    echo "" >> "$report_file"
    
    echo "--- IOC DATABASES ---" >> "$report_file"
    echo "" >> "$report_file"
    
    for db in "$IOC_DB_DIR"/*; do
        if [ -f "$db" ]; then
            echo "  Database: $(basename "$db")" >> "$report_file"
            echo "  Entries: $(wc -l < "$db")" >> "$report_file"
            echo "  Size: $(wc -c < "$db") bytes" >> "$report_file"
            echo "" >> "$report_file"
        fi
    done
    
    echo "--- RESEARCH DOCUMENT ---" >> "$report_file"
    echo "  Lines: $(wc -l < "$RESEARCH_FILE")" >> "$report_file"
    echo "  Words: $(wc -w < "$RESEARCH_FILE")" >> "$report_file"
    echo "" >> "$report_file"
    
    echo "--- KNOWN RANSOMWARE FAMILIES ---" >> "$report_file"
    echo "" >> "$report_file"
    local families="LockBit BlackCat ALPHV Black-Basta Royal Cl0p Play Medusa Akira Inc-Ransom BassterHunter QakBot Cobalt-Strike Mimikats Conti REvil Sodinokibi DarkSide Avlocker Phobos Dharma Ryuk MaLock CryptOn HiBye NoCry Zeppelin Netwalker Ragnar Mount-Locker XDLV XData Bad-Rabbit Petya NotPtya GoldenEye WannaCry Cryptolocker Cerber CTB-Locker Jigsaw SamSam Maktub LambdaLocker Linux.Encoder KeRanger FileCoder Thor MacRansom Patcher ThiefQuest GinX"
    for family in $families; do
        local count
        count=$(grep -oi "$family" "$RESEARCH_FILE" 2>/dev/null | wc -l)
        [ "$count" -gt 0 ] && echo "  $count $family" >> "$report_file"
    done | sort -rn >> "$report_file"
    
    echo "" >> "$report_file"
    echo "--- SCAN HISTORY ---" >> "$report_file"
    echo "" >> "$report_file"
    for r in "$REPORT_DIR"/*; do
        [ -f "$r" ] && echo "  $(basename "$r")" >> "$report_file"
    done
    
    echo "" >> "$report_file"
    echo "===================================================" >> "$report_file"
    echo "  END OF REPORT" >> "$report_file"
    echo "===================================================" >> "$report_file"
    
    echo -e "  ${GREEN}Report generated: $report_file${NC}"
    echo ""
    cat "$report_file"
    
    log_action "GENERATE REPORT: $report_file"
    pause
}

#  ---------------- [12] SELF-TEST ----------------
run_self_test() {
    echo -e "\n  ${CYAN}===== RUNNING SELF-TEST =====${NC}\n"
    check_scanner
    
    echo -e "  ${YELLOW}Running scanner self-test...${NC}\n"
    
    if [ -f "$MAKEFILE" ]; then
        cd "$PLATFORM_DIR" && make test 2>&1
    else
        echo "  Creating test files..."
        echo "test ransom note" > /tmp/test_RECOVER-FILES.txt
        echo "test" > /tmp/test_tomcat.exe
        echo "test" > /tmp/test.lockbit
        echo "  Running scan..."
        "$SCANNER_BIN" -q /tmp/ 2>&1 || true
        echo "  Cleaning up..."
        rm -f /tmp/test_RECOVER-FILES.txt /tmp/test_tomcat.exe /tmp/test.lockbit
        echo "  Test complete!"
    fi
    
    log_action "SELF-TEST completed"
    pause
}

#  ---------------- [13] LAUNCH WEB DASHBOARD ----------------
launch_web_dashboard() {
    echo -e "\n  ${CYAN}===== LAUNCHING WEB DASHBOARD =====${NC}\n"
    
    if ! command -v python3 &>/dev/null; then
        echo -e "  ${RED}Python3 not found! Install it first.${NC}"
        pause
        return 1
    fi
    
    local web_server="$PLATFORM_DIR/web_ui_server.py"
    if [ ! -f "$web_server" ]; then
        echo -e "  ${RED}Web server not found: $web_server${NC}"
        pause
        return 1
    fi
    
    echo -e "  ${GREEN}Starting web dashboard...${NC}"
    echo -e "  ${DIM}Open http://localhost:8443 in your browser${NC}"
    echo -e "  ${DIM}Press Ctrl+C to stop${NC}\n"
    
    log_action "WEB DASHBOARD started"
    
    python3 "$web_server" &
    local pid=$!
    
    sleep 2
    
    if kill -0 "$pid" 2>/dev/null; then
        echo -e "  ${GREEN}Web dashboard running (PID: $pid)${NC}"
        echo -e "  ${DIM}URL: http://localhost:8443${NC}"
    else
        echo -e "  ${RED}Failed to start web dashboard${NC}"
    fi
    
    pause
}

#  ---------------- MAIN LOOP ----------------
main() {
    while true; do
        show_banner
        show_menu
        
        read -r -p "  Enter choice [0-13]: " choice
        echo ""
        
        case $choice in
            1) compile_scanner ;;
            2) quick_scan ;;
            3) full_scan ;;
            4) custom_scan ;;
            5) scan_single_file ;;
            6) view_research ;;
            7) manage_databases ;;
            8) import_iocs ;;
            9) view_reports ;;
            10) threat_intel_lookup ;;
            11) generate_ioc_report ;;
            12) run_self_test ;;
            13) launch_web_dashboard ;;
            0)
                echo -e "  ${CYAN}Goodbye! Stay secure.${NC}\n"
                log_action "SESSION END"
                exit 0
                ;;
            *)
                echo -e "  ${RED}Invalid choice!${NC}"
                sleep 1
                ;;
        esac
    done
}

#  ---------------- ENTRY POINT ----------------
if [ $# -gt 0 ]; then
    case "$1" in
        --quick|-Q)
            check_scanner
            "$SCANNER_BIN" -Q "${2:-/}"
            exit $?
            ;;
        --full|-F)
            check_scanner
            "$SCANNER_BIN" -v "${2:-/}"
            exit $?
            ;;
        --scan|-S)
            check_scanner
            shift
            "$SCANNER_BIN" "$@"
            exit $?
            ;;
        --compile|-C)
            compile_scanner
            exit $?
            ;;
        --report|-R)
            generate_ioc_report
            exit 0
            ;;
        --help|-h)
            echo "Usage: $0 [OPTION]"
            echo ""
            echo "Interactive mode (no args):"
            echo "  $0                  Launch menu-driven console"
            echo ""
            echo "Direct scan mode:"
            echo "  $0 --quick [path]   Quick scan (skip hashes)"
            echo "  $0 --full [path]    Full scan (with hashes)"
            echo "  $0 --scan [opts]    Pass args directly to scanner"
            echo ""
            echo "Other:"
            echo "  $0 --compile        Build the scanner"
            echo "  $0 --report         Generate IOC summary report"
            echo "  $0 --help           Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
fi

# Run interactive mode
log_action "SESSION START"
main
