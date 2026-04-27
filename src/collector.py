# src/collector.py

from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console

console = Console()

def parse_fuzzer_stats(stats_path: Path) -> Optional[Dict[str, str]]:
    """Парсит файл fuzzer_stats в словарь ключ-значение"""
    if not stats_path.exists():
        return None

    stats = {}
    try:
        with stats_path.open("r", encoding="utf-8") as f:
            for line in f:
                if ":" not in line:
                    continue
                key, value = line.strip().split(":", 1)
                stats[key.strip()] = value.strip()
        return stats
    except Exception as e:
        console.print(f"[bold red]Ошибка чтения fuzzer_stats:[/bold red] {e}")
        return None


def collect_afl_data(afl_dir: Path, verbose: bool = False) -> Dict:
    """Собрать ключевые данные из директории AFL++"""
    data = {
        "crashes": list(afl_dir.joinpath("crashes").glob("*")) if afl_dir.joinpath("crashes").is_dir() else [],
        "queue": list(afl_dir.joinpath("queue").glob("*")) if afl_dir.joinpath("queue").is_dir() else [],
        "hangs": list(afl_dir.joinpath("hangs").glob("*")) if afl_dir.joinpath("hangs").is_dir() else [],
        "fuzzer_stats_path": afl_dir.joinpath("fuzzer_stats") if afl_dir.joinpath("fuzzer_stats").exists() else None,
        "fuzzer_stats": None,
    }

    # Парсим fuzzer_stats, если файл есть
    if data["fuzzer_stats_path"]:
        data["fuzzer_stats"] = parse_fuzzer_stats(data["fuzzer_stats_path"])

    if verbose:
        console.print("[bold blue]Собрано данных:[/bold blue]")
        console.print(f"  crashes: {len(data['crashes'])} файлов")
        console.print(f"  queue:   {len(data['queue'])} файлов")
        console.print(f"  hangs:   {len(data['hangs'])} файлов")

        if data["fuzzer_stats"]:
            console.print("[bold blue]Ключевые метрики из fuzzer_stats:[/bold blue]")
            important_keys = [
                "start_time", "last_update", "fuzzer_pid", "cycles_done",
                "execs_done", "execs_per_sec", "paths_total", "edges_found"
            ]
            for k in important_keys:
                if k in data["fuzzer_stats"]:
                    console.print(f"  {k:15}: {data['fuzzer_stats'][k]}")
        else:
            console.print("[yellow]fuzzer_stats не найден или не удалось прочитать[/yellow]")

    if not data["crashes"] and not data["hangs"]:
        console.print("[bold yellow]Предупреждение:[/bold yellow] Нет крашей или хэнгов для анализа.")

    return data