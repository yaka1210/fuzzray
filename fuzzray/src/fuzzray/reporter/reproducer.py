from __future__ import annotations

from pathlib import Path

from fuzzray.models import Crash

_TEMPLATE = """#!/usr/bin/env bash
# FuzzRay reproducer — crash {crash_id}
# CWE: {cwe} ({cwe_title})
# Severity: {severity}
# Location: {location}

set -u

TARGET={target!r}
CRASH={crash_path!r}

if [[ ! -x "$TARGET" ]]; then
  echo "ERROR: target binary not found or not executable: $TARGET" >&2
  exit 2
fi
if [[ ! -f "$CRASH" ]]; then
  echo "ERROR: crash file not found: $CRASH" >&2
  exit 2
fi

echo "[FuzzRay] Reproducing crash {crash_id} ({cwe})..."
echo "[FuzzRay] Target: $TARGET"
echo "[FuzzRay] Input:  $CRASH"
echo

{cmd}
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
"""


def _build_cmd(target: str, target_args: str, crash_path: str) -> str:
    if "@@" in target_args:
        argv = target_args.replace("@@", f'"$CRASH"')
    else:
        argv = f'"$CRASH"'
    return f'"$TARGET" {argv}'


def render(
    crash: Crash,
    crash_id: int,
    target: Path | None,
    target_args: str,
) -> str:
    cwe = crash.top_cwe
    cwe_title = "—"
    if crash.cwe_distribution:
        cwe_title = max(crash.cwe_distribution.items(), key=lambda kv: kv[1])[0]
    location = crash.crash_location or (
        f"{crash.crash_function}" if crash.crash_function else "unknown"
    )
    target_str = str(target) if target else "./target"
    crash_path = str(crash.raw.path)

    return _TEMPLATE.format(
        crash_id=crash_id,
        cwe=cwe,
        cwe_title=cwe_title,
        severity=crash.severity_level,
        location=location,
        target=target_str,
        crash_path=crash_path,
        cmd=_build_cmd(target_str, target_args, crash_path),
    )
