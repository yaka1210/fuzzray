# src/prioritizer.py

from typing import List
from collections import Counter

from rich.console import Console
from models import Crash

console = Console(highlight=True)


def get_priority(crash: Crash) -> str:
    """
    Приоритет на основе уровня и количества проявлений
    """
    if crash.is_critical:                    # level == "1"
        return "Критический"

    # Чем больше проявлений — тем выше приоритет
    if crash.manifestations >= 10:
        return "Высокий (много проявлений)"
    elif crash.manifestations >= 5:
        return "Средний-высокий"
    elif crash.code == "ERROR_SEGFAULT" or (crash.gdb_analysis and crash.gdb_analysis.signal and "SIGSEGV" in crash.gdb_analysis.signal):
        return "Средний"
    
    return "Низкий"


def prioritize_crashes(crashes: List[Crash]) -> List[Crash]:
    """
    Приоритизирует краши с учётом количества проявлений
    """
    console.print("[cyan]→ Приоритизация крашей (с учётом проявлений)...[/cyan]")

    for crash in crashes:
        crash.priority = get_priority(crash)

    # Сортировка: Критический → Высокий → Средний → Низкий
    priority_order = {
        "Критический": 0,
        "Высокий (много проявлений)": 1,
        "Средний-высокий": 2,
        "Средний": 3,
        "Низкий": 4
    }

    crashes.sort(key=lambda x: priority_order.get(x.priority, 999))

    # Статистика
    priority_counts = Counter(c.priority for c in crashes)
    console.print("[green]✓ Приоритизация завершена[/green]")
    for p, count in sorted(priority_counts.items(), key=lambda x: priority_order.get(x[0], 999)):
        console.print(f"  {p}: {count} уникальных крашей")

    return crashes