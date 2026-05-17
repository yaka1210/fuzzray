from __future__ import annotations

import re

CWE_TITLES: dict[str, str] = {
    "CWE-787": "Запись за пределами буфера",
    "CWE-125": "Чтение за пределами буфера",
    "CWE-415": "Двойное освобождение памяти",
    "CWE-416": "Использование памяти после освобождения",
    "CWE-476": "Разыменование нулевого указателя",
    "CWE-190": "Целочисленное переполнение",
    "CWE-369": "Деление на ноль",
    "CWE-457": "Использование неинициализированной переменной",
    "unknown": "Не классифицировано",
}

ERROR_RECOMMENDATIONS: dict[str, str] = {
    "ERROR_SEGFAULT": "Проверьте указатели и границы массивов. Соберите с -fsanitize=address для точного диагноза.",
    "ERROR_ABORT": "Проверьте assert-условия и операции с памятью (double-free, heap corruption).",
    "ERROR_BUSERROR": "Проверьте выравнивание структур и работу с mmap.",
    "ERROR_ILL": "Недопустимая инструкция — часто UBSan trap. Соберите с -fsanitize=undefined для подробностей.",
    "ERROR_FPE": "Проверьте операции деления: убедитесь, что делитель не равен нулю.",
    "ERROR_TIMEOUT": "Проверьте циклы и рекурсию на предмет бесконечных итераций.",
    "ERROR_UNKNOWN": "Соберите цель с -fsanitize=address,undefined и повторите анализ.",
}


def build_dynamic_recommendation(
    signal_class: str,
    backtrace: list[str],
    crash_function: str | None = None,
    crash_location: str | None = None,
) -> str:
    func_name = crash_function
    file_loc = crash_location
    if func_name and _is_noise(func_name):
        func_name = None
    if (not func_name or not file_loc) and backtrace:
        for frame in backtrace:
            if _is_noise(frame):
                continue
            func_name = func_name or _extract_function(frame)
            file_loc = file_loc or _extract_location(frame)
            if func_name and func_name != "optimized out":
                break

    # Location prefix: "Функция foo (file.c:42)" or "file.c:42" or empty
    if func_name and file_loc:
        location_prefix = f"Функция {func_name} ({file_loc})"
    elif func_name:
        location_prefix = f"Функция {func_name}"
    elif file_loc:
        location_prefix = file_loc
    else:
        location_prefix = ""

    advice = ERROR_RECOMMENDATIONS.get(signal_class) or \
        "соберите цель с отладочной информацией (-g) и повторите анализ"

    advice = advice.rstrip(".")
    if location_prefix:
        return f"{location_prefix}: {advice[0].lower()}{advice[1:]}."
    return f"{advice[0].upper()}{advice[1:]}."


_NOISE_FRAME_RE = re.compile(
    # libc / pthread / standard signal entry points
    r"__pthread_kill|__GI_raise|__GI_abort|\bpthread_kill\b|\braise\b|\babort\b|"
    r"__libc_message|__assert_fail|"
    # sanitizer C-style symbols
    r"__asan_|__sanitizer_|__interceptor_|"
    r"__ubsan_|__msan_|__lsan_|__tsan_|"
    # sanitizer C++ namespace symbols
    r"__sanitizer::|__asan::|__ubsan::|__msan::|__lsan::|__tsan::|"
    r"printf_common|"
    # UBSan internal report builders
    r"handleIntegerOverflow|handleDivremOverflow|handleShiftOutOfBounds|"
    r"handleTypeMismatch|handleNonNullArg|handleFloatCastOverflow|"
    r"handleImplicitConversion|handleOutOfBounds|handleBuiltinUnreachable|"
    r"handleMissingReturn|"
    # signal handler synthetic frame
    r"<signal handler called>|"
    # standard libc paths
    r"/nptl/|/sysdeps/|/glibc-|"
    r"__libc_start|_start$"
)


def _is_noise(frame: str) -> bool:
    return bool(_NOISE_FRAME_RE.search(frame))


_FUNC_RE = re.compile(r"\bin\s+([\w:]+)\s*\(")
_FUNC_ANGLE_RE = re.compile(r"<([^+>]+)")
_LOC_RE = re.compile(r"at\s+(\S+:\d+)")


def _extract_function(frame: str) -> str | None:
    m = _FUNC_RE.search(frame)
    if m and m.group(1) not in ("optimized", "out"):
        return m.group(1)
    m = _FUNC_ANGLE_RE.search(frame)
    if m:
        return m.group(1)
    return None


def _extract_location(frame: str) -> str | None:
    m = _LOC_RE.search(frame)
    return m.group(1) if m else None


def signal_to_cwe_prior(sig: int | None) -> dict[str, float]:
    if sig is None:
        return {"unknown": 0.5}
    if sig == 11:  # SIGSEGV
        return {"CWE-787": 0.25, "CWE-125": 0.25, "CWE-476": 0.2, "unknown": 0.3}
    if sig == 6:  # SIGABRT
        return {"CWE-787": 0.3, "CWE-416": 0.3, "CWE-415": 0.2, "unknown": 0.2}
    if sig == 8:  # SIGFPE
        return {"CWE-369": 0.7, "CWE-190": 0.2, "unknown": 0.1}
    if sig == 7:  # SIGBUS
        return {"CWE-787": 0.3, "CWE-125": 0.3, "unknown": 0.4}
    if sig == 4:  # SIGILL (часто UBSan trap: NULL deref, div-by-zero, overflow)
        return {"CWE-476": 0.25, "CWE-369": 0.2, "CWE-190": 0.15, "CWE-787": 0.1, "unknown": 0.3}
    return {"unknown": 0.6}


def signal_to_class(sig: int | None) -> str:
    return {
        4: "ERROR_ILL",
        6: "ERROR_ABORT",
        7: "ERROR_BUSERROR",
        8: "ERROR_FPE",
        11: "ERROR_SEGFAULT",
    }.get(sig or -1, "ERROR_UNKNOWN")


def normalize_distribution(dist: dict[str, float]) -> dict[str, float]:
    total = sum(dist.values())
    if total <= 0:
        return {"unknown": 1.0}
    return {k: round(v / total, 3) for k, v in dist.items()}
