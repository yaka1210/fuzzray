#!/usr/bin/env bash
# FuzzRay reproducer — crash 58
# CWE: CWE-190 (CWE-190)
# Severity: LOW
# Location: exif.c:336

set -u

TARGET='jhead-2.90/jhead'
CRASH='jhead-2.90/out/default/crashes/id_000071,sig_04,src_000266,time_6168359,execs_428680,op_quick,pos_698,val_+2'

if [[ ! -x "$TARGET" ]]; then
  echo "ERROR: target binary not found or not executable: $TARGET" >&2
  exit 2
fi
if [[ ! -f "$CRASH" ]]; then
  echo "ERROR: crash file not found: $CRASH" >&2
  exit 2
fi

echo "[FuzzRay] Reproducing crash 58 (CWE-190)..."
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
