from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from collections import Counter

from fuzzray.classifier.cwe_rules import (
    CWE_TITLES,
    build_dynamic_recommendation,
)
from fuzzray.models import Crash, Report
from fuzzray.reporter.svg_chart import render_crashes_over_time

_TEMPLATE_DIR = Path(__file__).parent / "templates"

SIGNAL_CLASS_NAMES: dict[str, str] = {
    "ERROR_SEGFAULT": "ERROR_SEGFAULT — Нарушение доступа к памяти (SIGSEGV)",
    "ERROR_ABORT": "ERROR_ABORT — Аварийное завершение (SIGABRT)",
    "ERROR_FPE": "ERROR_FPE — Арифметическая ошибка (SIGFPE)",
    "ERROR_BUSERROR": "ERROR_BUSERROR — Ошибка шины / некорректное выравнивание (SIGBUS)",
    "ERROR_ILL": "ERROR_ILL — Недопустимая инструкция (SIGILL)",
    "ERROR_TIMEOUT": "ERROR_TIMEOUT — Превышение лимита времени выполнения",
    "ERROR_UNKNOWN": "ERROR_UNKNOWN — Не удалось классифицировать сбой",
}

ERROR_CATEGORIES: dict[str, str] = {
    "ERROR_SEGFAULT": "Память",
    "ERROR_ABORT": "Память",
    "ERROR_BUSERROR": "Память",
    "ERROR_ILL": "Процессор",
    "ERROR_FPE": "Арифметика",
    "ERROR_TIMEOUT": "Время",
    "ERROR_UNKNOWN": "Неизвестно",
}

ERROR_DESCRIPTIONS: dict[str, str] = {
    "ERROR_SEGFAULT": "Общее нарушение доступа к памяти: чтение или запись по недопустимому адресу",
    "ERROR_ABORT": "Программа аварийно завершена (assert, double-free, повреждение heap-метаданных)",
    "ERROR_BUSERROR": "Ошибка шины: некорректное выравнивание адреса или обращение к несуществующей физической памяти",
    "ERROR_ILL": "Процессор встретил недопустимую инструкцию (часто UBSan trap-режим при UB)",
    "ERROR_FPE": "Ошибка арифметики с плавающей точкой: деление на ноль, переполнение",
    "ERROR_TIMEOUT": "Программа не завершилась в отведённое время (бесконечный цикл, рекурсия)",
    "ERROR_UNKNOWN": "Причина сбоя не определена автоматически",
}

CRASH_SITE_NAMES: dict[str, str] = {
    "user_code": "Код программы",
    "libc_alloc": "Аллокатор (malloc/free)",
    "libc_string": "Строковая функция (memcpy/strcpy)",
    "libc_io": "Функция ввода-вывода (printf/fwrite)",
    "dynamic_linker": "Динамический загрузчик (ld.so)",
    "kernel_syscall": "Системный вызов",
    "unknown": "Неизвестно",
}

MEMORY_REGION_NAMES: dict[str, str] = {
    "heap": "Куча (heap)",
    "stack": "Стек (stack)",
    "bss": "Глобальные данные (bss)",
    "mmap": "Отображённая память (mmap)",
    "null_page": "Нулевая страница (NULL)",
    "unmapped": "Неотображённая память",
    "kernel_space": "Ядро (kernel)",
    "unknown": "Неизвестно",
}

CONTROL_FLOW_NAMES: dict[str, str] = {
    "normal": "Нормальный",
    "ret_to_unmapped": "Возврат в невалидный адрес",
    "indirect_call_corrupt": "Повреждённый косвенный вызов",
    "stack_exhaustion": "Переполнение стека вызовов",
    "unknown": "Неизвестно",
}

EXPLOITABILITY_NAMES: dict[str, str] = {
    "EXPLOITABLE": "Эксплуатируемая",
    "PROBABLY_EXPLOITABLE": "Вероятно эксплуатируемая",
    "PROBABLY_NOT_EXPLOITABLE": "Вероятно не эксплуатируемая",
    "UNKNOWN": "Не определено",
}


def _build_recommendation(c: Crash) -> str:
    return build_dynamic_recommendation(
        top_cwe=c.top_cwe,
        signal_class=c.taxonomy.signal_class,
        crash_site=c.taxonomy.crash_site_kind,
        backtrace=c.backtrace,
        faulting_instruction=c.faulting_instruction,
        crash_function=c.crash_function,
        crash_location=c.crash_location,
        source_snippet=c.source_snippet,
        source_snippet_crash_line=c.source_snippet_crash_line,
    )


def render_html(report: Report) -> str:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "html.j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals["cwe_titles"] = CWE_TITLES
    env.globals["signal_class_names"] = SIGNAL_CLASS_NAMES
    env.globals["crash_site_names"] = CRASH_SITE_NAMES
    env.globals["memory_region_names"] = MEMORY_REGION_NAMES
    env.globals["control_flow_names"] = CONTROL_FLOW_NAMES
    env.globals["exploitability_names"] = EXPLOITABILITY_NAMES
    env.globals["error_categories"] = ERROR_CATEGORIES
    env.globals["error_descriptions"] = ERROR_DESCRIPTIONS
    tpl = env.get_template("report.html.j2")

    by_signal = Counter(c.taxonomy.signal_class for c in report.crashes)
    by_site = Counter(c.taxonomy.crash_site_kind for c in report.crashes)
    by_region = Counter(c.taxonomy.memory_region for c in report.crashes)
    by_exploit = Counter(c.exploitability for c in report.crashes)

    cwe_crashes = [c for c in report.crashes if c.top_cwe != "unknown"]
    error_crashes = [c for c in report.crashes if c.top_cwe == "unknown"]

    cwe_recs: list[str] = [_build_recommendation(c) for c in cwe_crashes]
    error_recs: list[str] = [_build_recommendation(c) for c in error_crashes]

    crashes_chart = render_crashes_over_time(report.plot_points)

    sev_counts = Counter(c.severity_level for c in report.crashes)

    return tpl.render(
        report=report,
        cwe_crashes=cwe_crashes,
        error_crashes=error_crashes,
        cwe_recs=cwe_recs,
        error_recs=error_recs,
        by_signal=by_signal.most_common(),
        by_site=by_site.most_common(),
        by_region=by_region.most_common(),
        by_exploit=by_exploit.most_common(),
        crashes_chart=crashes_chart,
        sev_counts=sev_counts,
    )
