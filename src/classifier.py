# src/classifier.py

import re
import subprocess
import concurrent.futures
from pathlib import Path
from typing import List, Optional

from rich.console import Console

from models import Crash, GDBAnalysis

console = Console()


CWE_TABLE = {
    "CWE-787": {
        "name": "Out-of-Bounds Write",
        "asan_patterns": ["heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow"]
    },
    "CWE-125": {
        "name": "Out-of-Bounds Read",
        "asan_patterns": ["heap-buffer-overflow", "out-of-bounds read", "stack-buffer-overflow"]
    },
    "CWE-416": {
        "name": "Use After Free",
        "asan_patterns": ["use-after-free", "heap-use-after-free"]
    },
    "CWE-119": {
        "name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "asan_patterns": ["buffer overflow"]
    },
    "CWE-476": {
        "name": "NULL Pointer Dereference",
        "asan_patterns": ["null-pointer-dereference", "null-dereference"]
    },
    "CWE-190": {
        "name": "Integer Overflow or Wraparound",
        "asan_patterns": ["integer-overflow", "signed-integer-overflow"]
    },
    "CWE-415": {
        "name": "Double Free",
        "asan_patterns": ["double-free"]
    },
}

ERROR_TABLE = {
    "ERROR_SEGFAULT": {
        "description": "Нарушение доступа к памяти (SIGSEGV)",
        "signal": "sig:11"
    },
    "ERROR_ABORT": {
        "description": "Прерывание программы (SIGABRT, assert или double-free)",
        "signal": "sig:06"
    },
    "ERROR_BUSERR": {
        "description": "Ошибка шины / некорректное выравнивание (SIGBUS)",
        "signal": "sig:07"
    },
    "ERROR_FPE": {
        "description": "Арифметическая ошибка (SIGFPE, деление на 0)",
        "signal": "sig:08"
    },
    "ERROR_ILL": {
        "description": "Недопустимая инструкция (SIGILL)",
        "signal": "sig:04"
    },
    "ERROR_TIMEOUT": {
        "description": "Превышение лимита времени выполнения",
        "signal": "hangs"
    },
    "ERROR_UNKNOWN": {
        "description": "Неизвестно",
        "signal": "other"
    },
}


def analyze_with_gdb(crash_file: Path, target_bin: str) -> GDBAnalysis:
    console.print(f"[cyan]GDB анализ: {crash_file.name} ...[/cyan]", end=" ")

    try:
        cmd = [
            "gdb", "-batch", "-quiet", "-ex", "set pagination off",
            "-ex", f"set args {crash_file.absolute()}",
            "-ex", "run",
            "-ex", "bt full",
            "-ex", "info registers",
            "-ex", "quit",
            target_bin
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=12, env={"LC_ALL": "C"})
        output = result.stdout + "\n" + result.stderr

        gdb_result = parse_gdb_output(output)

        if gdb_result.success and gdb_result.function:
            console.print(f"[green]✓ {gdb_result.function}()[/green]")
        elif gdb_result.success:
            console.print("[yellow]✓ (backtrace есть, функция не найдена)[/yellow]")
        else:
            console.print(f"[red]✗ {gdb_result.error}[/red]")

        return gdb_result

    except Exception as e:
        console.print(f"[red]✗ {e}[/red]")
        return GDBAnalysis(success=False, error=str(e))


def parse_gdb_output(output: str) -> GDBAnalysis:
    analysis = GDBAnalysis(success=True)

    signal_match = re.search(r"Program received signal (\w+)", output)
    if signal_match:
        analysis.signal = signal_match.group(1)

    bt_lines = [line.strip() for line in output.splitlines() if re.match(r"#\d+", line.strip())]
    analysis.backtrace = bt_lines

    func_match = re.search(r"#0\s+.*?in\s+([^\s\(]+)", output)
    if func_match:
        analysis.function = func_match.group(1)

    source_match = re.search(r"at\s+([^:]+):(\d+)", output)
    if source_match:
        analysis.source_file = source_match.group(1)
        analysis.source_line = int(source_match.group(2))

    return analysis


def classify_crash(crash_path: Path, target_bin: Optional[str] = None) -> Crash:
    filename = crash_path.name.lower()

    level = "Unknown"
    code = "ERROR_UNKNOWN"
    description = "Неизвестный тип ошибки"

    # Уровень 1 — CWE
    for cwe_id, info in CWE_TABLE.items():
        for pattern in info["asan_patterns"]:
            if pattern in filename:
                level = "1"
                code = cwe_id
                description = info["name"]
                break
        if level != "Unknown":
            break

    # Чтение содержимого файла (для ASan)
    if level == "Unknown":
        try:
            with crash_path.open("r", encoding="utf-8", errors="ignore") as f:
                content = f.read(200000).lower()
                for cwe_id, info in CWE_TABLE.items():
                    for pattern in info["asan_patterns"]:
                        if pattern in content:
                            level = "1"
                            code = cwe_id
                            description = info["name"]
                            break
                    if level != "Unknown":
                        break
        except Exception:
            pass

    # Уровень 2 — по сигналу
    if level == "Unknown":
        match = re.search(r",sig[_:]?(\d+),", filename)
        if match:
            sig = match.group(1)
            for error_code, info in ERROR_TABLE.items():
                if info.get("signal") == f"sig:{sig}":
                    level = "2"
                    code = error_code
                    description = info["description"]
                    break

    if "hang" in filename or "timeout" in filename:
        level = "2"
        code = "ERROR_TIMEOUT"
        description = ERROR_TABLE["ERROR_TIMEOUT"]["description"]

    crash = Crash(
        file=crash_path.name,
        path=str(crash_path),
        level=level,
        code=code,
        description=description,
        manifestations=1
    )

    if target_bin:
        gdb_result = analyze_with_gdb(crash_path, target_bin)
        crash.gdb_analysis = gdb_result

    return crash


def classify_crashes(
    crashes: List[Path],
    hangs: List[Path],
    target_bin: Optional[str] = None,
    use_gdb: bool = True,
    parallel: bool = True
) -> dict:
    console.print("[bold cyan]🔍 Классификация крашей...[/bold cyan]")

    crash_list: List[Crash] = []
    if use_gdb and target_bin and parallel and len(crashes) > 5:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(classify_crash, c, target_bin) for c in crashes]
            for f in concurrent.futures.as_completed(futures):
                crash_list.append(f.result())
    else:
        for c in crashes:
            crash_list.append(classify_crash(c, target_bin if use_gdb else None))

    console.print(f"[green]✓ Обработано {len(crash_list)} крашей[/green]")

    hang_list: List[Crash] = []
    for h in hangs:
        hang_list.append(Crash(
            file=h.name,
            path=str(h),
            level="2",
            code="ERROR_TIMEOUT",
            description=ERROR_TABLE["ERROR_TIMEOUT"]["description"],
            manifestations=1
        ))

    console.print(f"[green]✓ Обработано {len(hang_list)} хэнгов[/green]")

    return {
        "crashes": crash_list,
        "hangs": hang_list
    }