#!/usr/bin/env bash
# FuzzRay reproducer — crash 4
# CWE: CWE-190 (CWE-190)
# Severity: LOW
# Location: exif.c:584

set -u

TARGET='j/jheadt'
CRASH='j/outt/default/crashes/id_000007,sig_04,src_000000,time_23612,execs_1946,op_havoc,rep_2'

if [[ ! -x "$TARGET" ]]; then
  echo "ERROR: target binary not found or not executable: $TARGET" >&2
  exit 2
fi
if [[ ! -f "$CRASH" ]]; then
  echo "ERROR: crash file not found: $CRASH" >&2
  exit 2
fi

echo "[FuzzRay] Reproducing crash 4 (CWE-190)..."
echo "[FuzzRay] Target: $TARGET"
echo "[FuzzRay] Input:  $CRASH"
echo

"$TARGET" "$CRASH"
EXIT_CODE=$?

echo
echo "[FuzzRay] Exit code: $EXIT_CODE"
case $EXIT_CODE in
  0)   echo "[FuzzRay] Program exited normally (bug not reproduced?)";;
  124) echo "[FuzzRay] Program timed out";;
  134) echo "[FuzzRay] SIGABRT (assert / heap corruption)";;
  136) echo "[FuzzRay] SIGFPE (arithmetic error)";;
  139) echo "[FuzzRay] SIGSEGV (segmentation fault)";;
  132) echo "[FuzzRay] SIGILL (illegal instruction / UBSan trap)";;
  *)   echo "[FuzzRay] Crash reproduced with exit code $EXIT_CODE";;
esac
exit $EXIT_CODE
