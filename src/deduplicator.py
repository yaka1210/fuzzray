# src/deduplicator.py
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from collections import defaultdict

from rich.console import Console

from models import Crash
from classifier import classify_crash   

console = Console(highlight=True)


def normalize_backtrace(backtrace: List[str]) -> str:
    if not backtrace:
        return ""
    normalized = []
    for line in backtrace[:12]:
        line = line.strip()
        if ' in ' in line:
            part = line.split(' in ')[1].split(' (')[0].strip()
        else:
            part = line
        part = re.sub(r'\b0x[0-9a-fA-F]+\b', 'ADDR', part)
        part = re.sub(r'\([^)]*\)', '', part)
        part = re.sub(r'\s+', ' ', part).strip()
        if part:
            normalized.append(part)
    return " → ".join(normalized)


def deduplicate_crashes(
    crashes: List[Path], 
    target_bin: Optional[str] = None
) -> Tuple[List[Crash], Dict]:
    if not crashes:
        return [], {"total": 0, "unique_locations": 0, "total_manifestations": 0, "duplicates_removed": 0}

    level1_groups = defaultdict(list)

    for crash_path in crashes:
        try:
            # Получаем готовый объект Crash
            crash_obj: Crash = classify_crash(crash_path, target_bin)

            # Уровень 1
            if crash_obj.gdb_analysis and crash_obj.gdb_analysis.success and crash_obj.gdb_analysis.function:
                func = crash_obj.gdb_analysis.function
                src = f"{crash_obj.gdb_analysis.source_file or 'unknown'}:{crash_obj.gdb_analysis.source_line or 0}"
                level1_key = f"{func} | {src}"
            else:
                level1_key = f"NO_GDB | {crash_path.name}"

            # Уровень 2
            bt_norm = normalize_backtrace(crash_obj.gdb_analysis.backtrace if crash_obj.gdb_analysis else [])
            level2_key = bt_norm if bt_norm else crash_path.name

            level1_groups[level1_key].append((level2_key, crash_obj))

        except Exception as e:
            console.print(f"[yellow]Ошибка обработки {crash_path.name}: {e}[/yellow]")

    # Формируем уникальные краши
    unique_crashes: List[Crash] = []
    for level1_key, items in level1_groups.items():
        sub_groups = defaultdict(list)
        for level2_key, crash_obj in items:
            sub_groups[level2_key].append(crash_obj)

        for group in sub_groups.values():
            rep = group[0]
            final_crash = Crash(
                file=rep.file,
                path=rep.path,
                level=rep.level,
                code=rep.code,
                description=rep.description,
                manifestations=len(group),
                gdb_analysis=rep.gdb_analysis
            )
            unique_crashes.append(final_crash)

    stats = {
        "total": len(crashes),
        "unique_locations": len(level1_groups),
        "total_manifestations": len(crashes),
        "duplicates_removed": len(crashes) - len(unique_crashes),
        "unique": len(unique_crashes)
    }

    console.print("[green]✓ Дедупликация завершена[/green]")
    console.print(f"  Всего крашей:           {stats['total']}")
    console.print(f"  Уникальных мест:        {stats['unique_locations']}")
    console.print(f"  Проявлений всего:       {stats['total_manifestations']}")
    console.print(f"  Удалено дубликатов:     {stats['duplicates_removed']}")

    return unique_crashes, stats