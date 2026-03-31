#!/bin/bash
TARGET="/sample/$(ls /sample | head -1)"
RESULTS_DIR="/results"
mkdir -p "$RESULTS_DIR"

FILENAME=$(ls /sample | head -1)
START_TIME=$(date +%s)

# ─── Run strace ───────────────────────────────────────────────
timeout 60 strace -f \
  -e trace=openat,write,connect,execve,unlink,mkdir,chmod,kill,ptrace \
  -o "$RESULTS_DIR/strace_raw.txt" \
  wine "$TARGET" 2>/dev/null || true

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# ─── Syscall counts ───────────────────────────────────────────
count_syscall() { grep -c "^[0-9]*  *$1(" "$RESULTS_DIR/strace_raw.txt" 2>/dev/null | tr -d '[:space:]' || echo 0; }

FILE_OPS=$(count_syscall openat)
WRITE_OPS=$(count_syscall write)
NET_OPS=$(count_syscall connect)
EXEC_OPS=$(count_syscall execve)
DELETE_OPS=$(count_syscall unlink)
MKDIR_OPS=$(count_syscall mkdir)
CHMOD_OPS=$(count_syscall chmod)
KILL_OPS=$(count_syscall kill)
PTRACE_OPS=$(count_syscall ptrace)

# ─── Files accessed ───────────────────────────────────────────
FILES=$(grep -oP '(?<=openat\(AT_FDCWD, ")[^"]+' "$RESULTS_DIR/strace_raw.txt" \
  | sort -u | head -30 \
  | awk '{print "\"" $0 "\""}' | paste -sd ',' -)

# ─── Network connections ──────────────────────────────────────
NET_ADDRS=$(grep -oP '(?<=sin_addr=inet_addr\(")[^"]+' "$RESULTS_DIR/strace_raw.txt" \
  | sort -u | head -10 \
  | awk '{print "\"" $0 "\""}' | paste -sd ',' -)

# ─── Suspicious indicators ────────────────────────────────────
INDICATORS=""
add_indicator() {
  if [ -n "$INDICATORS" ]; then INDICATORS="$INDICATORS,"; fi
  INDICATORS="$INDICATORS\"$1\""
}

[ "$NET_OPS" -gt 0 ]     && add_indicator "Network connections attempted: $NET_OPS"
[ "$EXEC_OPS" -gt 2 ]    && add_indicator "Process spawning detected: $EXEC_OPS execve calls"
[ "$DELETE_OPS" -gt 10 ] && add_indicator "Mass file deletion detected: $DELETE_OPS files"
[ "$PTRACE_OPS" -gt 0 ]  && add_indicator "Anti-debug / process injection attempt (ptrace)"
[ "$CHMOD_OPS" -gt 0 ]   && add_indicator "File permission changes detected: $CHMOD_OPS chmod calls"
[ "$KILL_OPS" -gt 0 ]    && add_indicator "Process termination attempts: $KILL_OPS kill calls"
[ "$MKDIR_OPS" -gt 5 ]   && add_indicator "Suspicious directory creation: $MKDIR_OPS mkdir calls"

# Check for suspicious file paths
grep -q "/tmp/" "$RESULTS_DIR/strace_raw.txt"       && add_indicator "Activity in /tmp directory (common malware staging)"
grep -q "system32" "$RESULTS_DIR/strace_raw.txt"    && add_indicator "Windows System32 access detected"
grep -q "startup" "$RESULTS_DIR/strace_raw.txt"     && add_indicator "Startup folder access (persistence attempt)"
grep -q "registry" "$RESULTS_DIR/strace_raw.txt"    && add_indicator "Registry access detected"
grep -q "autorun" "$RESULTS_DIR/strace_raw.txt"     && add_indicator "Autorun access detected (persistence)"

# ─── Threat score ─────────────────────────────────────────────
SCORE=0
[ "$NET_OPS" -gt 0 ]     && SCORE=$((SCORE + 20))
[ "$NET_OPS" -gt 10 ]    && SCORE=$((SCORE + 10))
[ "$EXEC_OPS" -gt 2 ]    && SCORE=$((SCORE + 15))
[ "$DELETE_OPS" -gt 10 ] && SCORE=$((SCORE + 20))
[ "$PTRACE_OPS" -gt 0 ]  && SCORE=$((SCORE + 25))
[ "$KILL_OPS" -gt 0 ]    && SCORE=$((SCORE + 10))
[ "$CHMOD_OPS" -gt 5 ]   && SCORE=$((SCORE + 10))
grep -q "/tmp/" "$RESULTS_DIR/strace_raw.txt"       && SCORE=$((SCORE + 10))
grep -q "startup" "$RESULTS_DIR/strace_raw.txt"     && SCORE=$((SCORE + 20))
grep -q "registry" "$RESULTS_DIR/strace_raw.txt"    && SCORE=$((SCORE + 15))
[ $SCORE -gt 100 ] && SCORE=100

# ─── Threat level ─────────────────────────────────────────────
if [ $SCORE -ge 70 ]; then   LEVEL="HIGH"
elif [ $SCORE -ge 40 ]; then LEVEL="MEDIUM"
elif [ $SCORE -ge 15 ]; then LEVEL="LOW"
else                          LEVEL="CLEAN"
fi

# ─── MITRE tags ───────────────────────────────────────────────
MITRE=""
add_mitre() {
  if [ -n "$MITRE" ]; then MITRE="$MITRE,"; fi
  MITRE="$MITRE{\"id\":\"$1\",\"name\":\"$2\"}"
}

[ "$NET_OPS" -gt 0 ]    && add_mitre "T1071" "Application Layer Protocol"
[ "$EXEC_OPS" -gt 2 ]   && add_mitre "T1059" "Command and Scripting Interpreter"
[ "$PTRACE_OPS" -gt 0 ] && add_mitre "T1055" "Process Injection"
[ "$DELETE_OPS" -gt 10 ]&& add_mitre "T1485" "Data Destruction"
[ "$KILL_OPS" -gt 0 ]   && add_mitre "T1562" "Impair Defenses"
grep -q "startup" "$RESULTS_DIR/strace_raw.txt" && add_mitre "T1547" "Boot or Logon Autostart Execution"
grep -q "registry" "$RESULTS_DIR/strace_raw.txt" && add_mitre "T1112" "Modify Registry"

# ─── Write final JSON ─────────────────────────────────────────
cat > "$RESULTS_DIR/behavior.json" <<EOF
{
  "status": "completed",
  "filename": "$FILENAME",
  "duration_seconds": $DURATION,
  "syscall_summary": {
    "file_operations": $FILE_OPS,
    "write_operations": $WRITE_OPS,
    "network_operations": $NET_OPS,
    "process_executions": $EXEC_OPS,
    "file_deletions": $DELETE_OPS,
    "directory_creations": $MKDIR_OPS,
    "permission_changes": $CHMOD_OPS,
    "process_kills": $KILL_OPS,
    "ptrace_calls": $PTRACE_OPS
  },
  "network_addresses": [ $NET_ADDRS ],
  "files_accessed": [ $FILES ],
  "suspicious_indicators": [ $INDICATORS ],
  "mitre_tags": [ $MITRE ],
  "threat_score": $SCORE,
  "threat_level": "$LEVEL"
}
EOF

cat "$RESULTS_DIR/behavior.json"