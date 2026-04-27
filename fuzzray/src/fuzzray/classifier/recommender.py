from __future__ import annotations

import re
from collections.abc import Callable

_ID = r"[A-Za-z_]\w*"
_IDX = r"[A-Za-z_]\w*(?:\.\w+)*"


def _strip_string_literals(line: str) -> str:
    """Remove "..." and '...' so operators inside strings don't trigger patterns."""
    line = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)
    line = re.sub(r"'(?:[^'\\]|\\.)*'", "''", line)
    return line


# CWE-190: Integer Overflow
def _cwe_190(line: str) -> str | None:
    s = _strip_string_literals(line)
    if re.search(r"<<", s):
        return ("Операция битового сдвига `<<` может вызвать целочисленное переполнение "
                "или сдвиг знакового значения, что является неопределённым поведением. "
                "Проверьте, что операнд сдвига не превышает ширину типа и что левый операнд "
                "беззнаковый или гарантированно неотрицательный.")
    m = re.search(rf"\b({_ID})\s*\*\s*({_ID})\b", s)
    if m and "[" not in line[:line.find(m.group(0))][-3:] and "*" not in s[:s.find(m.group(0))][-2:]:
        a, b = m.group(1), m.group(2)
        return (f"Умножение `{a} * {b}` может переполниться. "
                f"Используйте проверяемую арифметику: "
                f"`if (__builtin_mul_overflow({a}, {b}, &result)) return ERR;`.")
    m = re.search(rf"\b({_ID})\s*([+-])\s*({_ID})\b", s)
    if m:
        a, op, b = m.group(1), m.group(2), m.group(3)
        builtin = "add" if op == "+" else "sub"
        return (f"Арифметика `{a} {op} {b}` может переполниться. "
                f"Используйте `__builtin_{builtin}_overflow({a}, {b}, &result)`.")
    return None


# CWE-369: Divide By Zero
def _cwe_369(line: str) -> str | None:
    s = _strip_string_literals(line)
    m = re.search(rf"\b({_ID})\s*/\s*({_ID})\b", s)
    if m:
        a, b = m.group(1), m.group(2)
        return (f"Деление `{a} / {b}` — добавьте проверку перед операцией: "
                f"`if ({b} == 0) return ERR;`.")
    m = re.search(rf"\b({_ID})\s*%\s*({_ID})\b", s)
    if m:
        a, b = m.group(1), m.group(2)
        return (f"Операция `{a} % {b}` — убедитесь, что `{b} != 0` "
                f"перед взятием остатка.")
    return None


# CWE-476: NULL Pointer Dereference
def _cwe_476(line: str) -> str | None:
    s = _strip_string_literals(line)
    m = re.search(rf"\b({_ID})\s*->\s*({_ID})", s)
    if m:
        ptr, field = m.group(1), m.group(2)
        return (f"Разыменование `{ptr}->{field}` без проверки на NULL. "
                f"Добавьте перед этой строкой: `if ({ptr} == NULL) return ERR;`.")
    m = re.search(rf"\*\s*\([^)]+\)\s*({_ID})\b", s)
    if m:
        ptr = m.group(1)
        return (f"Разыменование `*(...){ptr}` без проверки на NULL. "
                f"Добавьте `if ({ptr} == NULL) return ERR;` перед обращением.")
    m = re.search(rf"(?<![\w\*\)])\*\s*({_ID})\b", s)
    if m and not re.search(rf"\b{_ID}\s*\*\s*{re.escape(m.group(1))}", s):
        ptr = m.group(1)
        return (f"Разыменование `*{ptr}` без проверки на NULL. "
                f"Добавьте `if ({ptr} == NULL) return ERR;` перед использованием.")
    return None


# CWE-681: Incorrect Type Conversion
def _cwe_681(line: str) -> str | None:
    s = _strip_string_literals(line)
    m = re.search(
        r"\(\s*((?:un)?signed\s+)?(int8_t|int16_t|int32_t|uint8_t|uint16_t|uint32_t|short|char|int|unsigned|long|float)\s*\)\s*[\(\w]",
        s,
    )
    if m:
        target = m.group(2)
        return (f"Приведение значения к типу `{target}` может привести к потере значения "
                f"при выходе исходного значения за диапазон. Перед приведением проверьте, "
                f"что значение умещается в `{target}`, либо используйте safe-cast обёртку.")
    return None


# CWE-787: Out-of-Bounds Write
def _cwe_787(line: str) -> str | None:
    s = _strip_string_literals(line)
    m = re.search(rf"\bmemcpy\s*\(\s*({_ID})\s*,\s*({_ID})\s*,\s*({_ID})\s*\)", s)
    if m:
        dst, src, n = m.group(1), m.group(2), m.group(3)
        return (f"Вызов `memcpy({dst}, {src}, {n})` — добавьте проверку: "
                f"`if ({n} > sizeof({dst})) return ERR;`. "
                f"Альтернатива — заменить на безопасный аналог `memcpy_s`.")
    m = re.search(rf"\bstrcpy\s*\(\s*({_ID})\s*,\s*({_ID})\s*\)", s)
    if m:
        dst, src = m.group(1), m.group(2)
        return (f"Функция `strcpy({dst}, {src})` не проверяет длину. "
                f"Замените на `strncpy({dst}, {src}, sizeof({dst}) - 1); "
                f"{dst}[sizeof({dst}) - 1] = '\\0';`.")
    m = re.search(rf"\b({_IDX})\s*\[\s*({_ID})\s*\]\s*=", s)
    if m:
        arr, idx = m.group(1), m.group(2)
        return (f"Запись в `{arr}[{idx}]` — проверьте, что `{idx}` находится "
                f"в допустимых границах массива перед присваиванием.")
    return None


# CWE-125: Out-of-Bounds Read
def _cwe_125(line: str) -> str | None:
    s = _strip_string_literals(line)
    m = re.search(rf"\b({_IDX})\s*\[\s*({_ID})\s*\]", s)
    if m:
        arr, idx = m.group(1), m.group(2)
        return (f"Чтение `{arr}[{idx}]` — проверьте границы: `{idx}` должен быть "
                f"в [0, длина {arr}) перед обращением.")
    return None


# CWE-134: Format String
def _cwe_134(line: str) -> str | None:
    s = _strip_string_literals(line)
    m = re.search(rf"\b(printf|fprintf|sprintf|snprintf|vprintf|fputs)\s*\(\s*([^,\")]+)\s*[,)]", s)
    if m and not re.search(r'""', m.group(0)):
        func, arg = m.group(1), m.group(2).strip()
        if not arg.startswith('"'):
            return (f"В вызове `{func}(...)` форматная строка не является литералом — "
                    f"возможна уязвимость форматной строки. Используйте `{func}(\"%s\", {arg})` "
                    f"вместо `{func}({arg})`.")
    return None


_HANDLERS: dict[str, Callable[[str], str | None]] = {
    "CWE-190": _cwe_190,
    "CWE-369": _cwe_369,
    "CWE-476": _cwe_476,
    "CWE-681": _cwe_681,
    "CWE-787": _cwe_787,
    "CWE-125": _cwe_125,
    "CWE-134": _cwe_134,
}


def analyze_snippet(
    top_cwe: str,
    source_snippet: list[tuple[int, str]],
    crash_line: int | None,
) -> str | None:
    """Try to generate a code-aware recommendation for the crash line.

    Returns context-specific text if a pattern matches in the crash line
    (or its immediate neighbours), else None.
    """
    if not source_snippet or top_cwe not in _HANDLERS:
        return None
    handler = _HANDLERS[top_cwe]

    candidates: list[str] = []
    if crash_line is not None:
        for ln, src in source_snippet:
            if ln == crash_line:
                candidates.append(src)
        for ln, src in source_snippet:
            if ln in (crash_line - 1, crash_line + 1):
                candidates.append(src)
    else:
        candidates = [src for _, src in source_snippet]

    for src in candidates:
        result = handler(src)
        if result:
            return result
    return None
