#!/bin/bash

TARGET_FILE=$(ls /sample | head -1)
TARGET="/sample/$TARGET_FILE"
RESULTS_DIR="/results"
mkdir -p "$RESULTS_DIR"

START_TIME=$(date +%s)

# ─────────────────────────────────────────────
# 1. FILE TYPE DETECTION (CRITICAL FIX)
# ─────────────────────────────────────────────
FILE_TYPE=$(file --mime-type -b "$TARGET")

if [[ "$FILE_TYPE" != "application/x-dosexec" ]]; then
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    cat > "$RESULTS_DIR/behavior.json" <<EOF
{
  "status": "skipped",
  "reason": "Non-executable file",
  "filename": "$TARGET_FILE",
  "file_type": "$FILE_TYPE",
  "duration_seconds": $DURATION,
  "threat_score": 0,
  "threat_level": "CLEAN",
  "confidence": "HIGH"
}
EOF

    cat "$RESULTS_DIR/behavior.json"
    exit 0
fi

# ─────────────────────────────────────────────
# 2. RUN STRACE + TCPDUMP
# ─────────────────────────────────────────────
timeout 60 tcpdump -i any -w "$RESULTS_DIR/network.pcap" >/dev/null 2>&1 &
TCP_PID=$!

timeout 60 strace -f \
  -e trace=openat,write,connect,execve,unlink,mkdir,chmod,kill,ptrace \
  -o "$RESULTS_DIR/strace_raw.txt" \
  wine "$TARGET" >/dev/null 2>&1 || true

kill $TCP_PID 2>/dev/null

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# ─────────────────────────────────────────────
# 3. CLEAN WINE NOISE
# ─────────────────────────────────────────────
grep -vE "wine|wineserver|wine-preloader" "$RESULTS_DIR/strace_raw.txt" > "$RESULTS_DIR/clean_trace.txt"

TRACE="$RESULTS_DIR/clean_trace.txt"

# ─────────────────────────────────────────────
# 4. SAFE COUNT FUNCTION
# ─────────────────────────────────────────────
count_syscall() {
    grep -c "$1(" "$TRACE" 2>/dev/null || echo 0
}

FILE_OPS=$(count_syscall openat)
WRITE_OPS=$(count_syscall write)
NET_OPS=$(count_syscall connect)
EXEC_OPS=$(count_syscall execve)
DELETE_OPS=$(count_syscall unlink)
MKDIR_OPS=$(count_syscall mkdir)
CHMOD_OPS=$(count_syscall chmod)
KILL_OPS=$(count_syscall kill)
PTRACE_OPS=$(count_syscall ptrace)

TOTAL_OPS=$((FILE_OPS + WRITE_OPS + NET_OPS + EXEC_OPS + DELETE_OPS + 1))

# ─────────────────────────────────────────────
# 5. RATIOS (ADVANCED SCORING)
# ─────────────────────────────────────────────
NET_RATIO=$((NET_OPS * 100 / TOTAL_OPS))
EXEC_RATIO=$((EXEC_OPS * 100 / TOTAL_OPS))
DELETE_RATIO=$((DELETE_OPS * 100 / TOTAL_OPS))

# ─────────────────────────────────────────────
# 6. EXTRACT DATA
# ─────────────────────────────────────────────
FILES=$(grep -oP '(?<=openat\(AT_FDCWD, ")[^"]+' "$TRACE" | sort -u | head -20 | awk '{print "\"" $0 "\""}' | paste -sd ',' -)

IPS=$(tcpdump -nn -r "$RESULTS_DIR/network.pcap" 2>/dev/null | awk '{print $5}' | cut -d'.' -f1-4 | sort -u | head -10 | awk '{print "\"" $0 "\""}' | paste -sd ',' -)

# ─────────────────────────────────────────────
# 7. INDICATORS
# ─────────────────────────────────────────────
INDICATORS=""
add_indicator() {
    [ -n "$INDICATORS" ] && INDICATORS="$INDICATORS,"
    INDICATORS="$INDICATORS\"$1\""
}

[ "$NET_RATIO" -gt 20 ] && add_indicator "High network activity"
[ "$EXEC_RATIO" -gt 15 ] && add_indicator "Suspicious process spawning"
[ "$DELETE_RATIO" -gt 10 ] && add_indicator "Mass file deletion"
[ "$PTRACE_OPS" -gt 0 ] && add_indicator "Possible process injection"
grep -q "/tmp/" "$TRACE" && add_indicator "Temp directory usage"
grep -Eiq "cmd.exe|powershell|wget|curl" "$TRACE" && add_indicator "Command execution behavior"

# ─────────────────────────────────────────────
# 8. ADVANCED SCORING
# ─────────────────────────────────────────────
SCORE=0

[ "$NET_RATIO" -gt 20 ] && SCORE=$((SCORE + 20))
[ "$EXEC_RATIO" -gt 15 ] && SCORE=$((SCORE + 20))
[ "$DELETE_RATIO" -gt 10 ] && SCORE=$((SCORE + 20))
[ "$PTRACE_OPS" -gt 0 ] && SCORE=$((SCORE + 25))
[ "$KILL_OPS" -gt 2 ] && SCORE=$((SCORE + 10))

# Benign behavior reduction
if [ "$EXEC_OPS" -lt 3 ] && [ "$NET_OPS" -lt 2 ]; then
    SCORE=$((SCORE - 15))
fi

# Clamp
[ "$SCORE" -lt 0 ] && SCORE=0
[ "$SCORE" -gt 100 ] && SCORE=100

# ─────────────────────────────────────────────
# 9. THREAT LEVEL
# ─────────────────────────────────────────────
if [ $SCORE -ge 70 ]; then
    LEVEL="HIGH"
elif [ $SCORE -ge 40 ]; then
    LEVEL="MEDIUM"
elif [ $SCORE -ge 15 ]; then
    LEVEL="LOW"
else
    LEVEL="CLEAN"
fi

# ─────────────────────────────────────────────
# 10. CONFIDENCE (NEW)
# ─────────────────────────────────────────────
if [ "$SCORE" -ge 70 ] && [ "$PTRACE_OPS" -gt 0 ]; then
    CONFIDENCE="HIGH"
elif [ "$SCORE" -ge 40 ]; then
    CONFIDENCE="MEDIUM"
else
    CONFIDENCE="LOW"
fi

# ─────────────────────────────────────────────
# 11. MITRE TAGS
# ─────────────────────────────────────────────
MITRE=""
add_mitre() {
    [ -n "$MITRE" ] && MITRE="$MITRE,"
    MITRE="$MITRE{\"id\":\"$1\",\"name\":\"$2\"}"
}

[ "$NET_RATIO" -gt 20 ] && add_mitre "T1071" "Application Layer Protocol"
[ "$EXEC_RATIO" -gt 15 ] && add_mitre "T1059" "Command Execution"
[ "$PTRACE_OPS" -gt 0 ] && add_mitre "T1055" "Process Injection"

# ─────────────────────────────────────────────
# 12. FINAL JSON
# ─────────────────────────────────────────────
cat > "$RESULTS_DIR/behavior.json" <<EOF
{
  "status": "completed",
  "filename": "$TARGET_FILE",
  "file_type": "$FILE_TYPE",
  "duration_seconds": $DURATION,
  "syscall_summary": {
    "file_operations": $FILE_OPS,
    "write_operations": $WRITE_OPS,
    "network_operations": $NET_OPS,
    "process_executions": $EXEC_OPS,
    "file_deletions": $DELETE_OPS
  },
  "network_addresses": [ $IPS ],
  "files_accessed": [ $FILES ],
  "suspicious_indicators": [ $INDICATORS ],
  "mitre_tags": [ $MITRE ],
  "threat_score": $SCORE,
  "threat_level": "$LEVEL",
  "confidence": "$CONFIDENCE"
}
EOF

cat "$RESULTS_DIR/behavior.json"