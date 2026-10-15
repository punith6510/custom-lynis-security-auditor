#!/bin/bash

# Linux Process Integrity Auditor - Enhancement Option 2
# Risk scoring, PASS/WARN/FAIL status, report logging and exit codes

CPU_THRESHOLD=80
REPORT_DIR="$HOME/process_audit_reports"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/audit_$(date +%Y%m%d_%H%M%S).log"
SCORE=0

# Colours only when printing to a terminal
if [ -t 1 ]; then
    RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; RST=$'\e[0m'
else
    RED=""; YEL=""; GRN=""; RST=""
fi

# Print to screen and save a colour-free copy to the report file
log() {
    echo -e "$1"
    echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$REPORT"
}

# verdict <name> <count> <points-per-hit> <max-points>
verdict() {
    local name=$1 count=$2 weight=$3 cap=$4 pts
    if (( count == 0 )); then
        log "  ${GRN}[PASS]${RST} $name: 0"
        return
    fi
    pts=$(( count * weight ))
    (( pts > cap )) && pts=$cap
    SCORE=$(( SCORE + pts ))
    if (( weight >= 20 )); then
        log "  ${RED}[FAIL]${RST} $name: $count (+$pts risk points)"
    else
        log "  ${YEL}[WARN]${RST} $name: $count (+$pts risk points)"
    fi
}

log "=========================================="
log "  LINUX PROCESS INTEGRITY AUDITOR v3.0"
log "  Enhancement 2: Risk Scoring & Reporting"
log "=========================================="
log "Host: $(hostname)   Date: $(date '+%Y-%m-%d %H:%M:%S')"
log ""

# Collect counts
ZOMBIES=$(ps -eo stat= | awk '$1 ~ /^Z/ {c++} END {print c+0}')
ORPHANS=$(ps -eo ppid= | awk '$1 == 1 {c++} END {print c+0}')
CPU_COUNT=$(ps -eo pcpu= | awk -v t="$CPU_THRESHOLD" '$1 >= t {c++} END {print c+0}')

TMP_COUNT=0; SHM_COUNT=0; DELETED_COUNT=0
for exe in /proc/[0-9]*/exe; do
    target=$(readlink "$exe" 2>/dev/null) || continue
    case "$target" in
        /tmp/*|/var/tmp/*) ((TMP_COUNT++)) ;;
        /dev/shm/*)        ((SHM_COUNT++)) ;;
    esac
    case "$target" in
        *" (deleted)")     ((DELETED_COUNT++)) ;;
    esac
done

log "Check results:"
verdict "Zombie processes"                 "$ZOMBIES"       5  15
log "  ${GRN}[INFO]${RST} Processes with PPID 1: $ORPHANS (not scored)"
verdict "Executables running from /tmp"    "$TMP_COUNT"     20 40
verdict "Executables running from /dev/shm" "$SHM_COUNT"    30 40
verdict "Deleted executables"              "$DELETED_COUNT" 25 40
verdict "Processes >= ${CPU_THRESHOLD}% CPU" "$CPU_COUNT"   10 20
log ""

(( SCORE > 100 )) && SCORE=100

if   (( SCORE == 0 )); then RATING="LOW";    COLOR=$GRN; EXIT_CODE=0
elif (( SCORE < 40 )); then RATING="MEDIUM"; COLOR=$YEL; EXIT_CODE=1
else                        RATING="HIGH";   COLOR=$RED; EXIT_CODE=2
fi

log "=========================================="
log "             AUDIT SUMMARY"
log "=========================================="
log "Risk score : $SCORE / 100"
log "Risk rating: ${COLOR}${RATING}${RST}"
log "Report file: $REPORT"
log ""
log "Exit codes: 0 = LOW, 1 = MEDIUM, 2 = HIGH"
log "This script detects conditions; it does not"
log "terminate processes or modify system settings."
exit $EXIT_CODE