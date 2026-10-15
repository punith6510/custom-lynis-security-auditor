#!/bin/bash

# Linux Process Integrity Auditor - Enhancement Option 1
# Detailed findings: shows WHICH processes triggered each check
# and widens the suspicious-path check to /tmp, /var/tmp and /dev/shm

SUSPICIOUS_DIRS=("/tmp" "/var/tmp" "/dev/shm")
CPU_THRESHOLD=80

echo "=========================================="
echo "  LINUX PROCESS INTEGRITY AUDITOR v2.0"
echo "  Enhancement 1: Detailed Process Findings"
echo "=========================================="
echo

# 1. Zombie processes (with PID, PPID and command)
echo "[1] Checking Zombie Processes..."
ZOMBIES=0
while read -r pid ppid stat comm; do
    [[ $stat == Z* ]] || continue
    ((ZOMBIES++))
    printf "    -> PID=%-7s PPID=%-7s CMD=%s\n" "$pid" "$ppid" "$comm"
done < <(ps -eo pid=,ppid=,stat=,comm=)
echo "Zombie processes found: $ZOMBIES"
echo

# 2. Processes with PPID 1 (count + first 10 listed)
echo "[2] Checking Processes with PPID 1..."
ORPHANS=0
while read -r pid user comm; do
    ((ORPHANS++))
    (( ORPHANS <= 10 )) && printf "    -> PID=%-7s USER=%-10s CMD=%s\n" "$pid" "$user" "$comm"
done < <(ps -eo pid=,ppid=,user=,comm= | awk '$2 == 1 {print $1, $3, $4}')
(( ORPHANS > 10 )) && echo "    ... and $((ORPHANS - 10)) more"
echo "Processes with PPID 1: $ORPHANS"
echo "Note: PPID 1 does not necessarily indicate a problem."
echo

# 3. Executables running from temporary directories
echo "[3] Checking Executables Running from Temporary Directories..."
TMP_COUNT=0
for exe in /proc/[0-9]*/exe; do
    pid=${exe#/proc/}; pid=${pid%/exe}
    target=$(readlink "$exe" 2>/dev/null) || continue
    for dir in "${SUSPICIOUS_DIRS[@]}"; do
        case "$target" in
            "$dir"/*)
                ((TMP_COUNT++))
                user=$(ps -o user= -p "$pid" 2>/dev/null)
                printf "    -> PID=%-7s USER=%-10s EXE=%s\n" "$pid" "$user" "$target"
                break ;;
        esac
    done
done
echo "Executables from /tmp, /var/tmp or /dev/shm: $TMP_COUNT"
echo

# 4. Deleted executables (with PID and original path)
echo "[4] Checking Deleted Executables..."
DELETED_COUNT=0
for exe in /proc/[0-9]*/exe; do
    pid=${exe#/proc/}; pid=${pid%/exe}
    target=$(readlink "$exe" 2>/dev/null) || continue
    case "$target" in
        *" (deleted)")
            ((DELETED_COUNT++))
            printf "    -> PID=%-7s EXE=%s\n" "$pid" "$target" ;;
    esac
done
echo "Deleted executable references: $DELETED_COUNT"
echo

# 5. High CPU usage (with PID, CPU% and command)
echo "[5] Checking High CPU Usage..."
CPU_COUNT=0
while read -r pid cpu comm; do
    ((CPU_COUNT++))
    printf "    -> PID=%-7s CPU=%-6s CMD=%s\n" "$pid" "$cpu" "$comm"
done < <(ps -eo pid=,pcpu=,comm= | awk -v t="$CPU_THRESHOLD" '$2 >= t {print $1, $2, $3}')
echo "Processes using at least ${CPU_THRESHOLD}% CPU: $CPU_COUNT"
echo

echo "=========================================="
echo "             AUDIT SUMMARY"
echo "=========================================="
echo "Zombie processes: $ZOMBIES"
echo "Processes with PPID 1: $ORPHANS"
echo "Executables from temp directories: $TMP_COUNT"
echo "Deleted executable references: $DELETED_COUNT"
echo "Processes at >=${CPU_THRESHOLD}% CPU: $CPU_COUNT"
echo
echo "Audit completed. Investigate the listed PIDs."
echo "This script detects conditions; it does not"
echo "terminate processes or modify system settings."