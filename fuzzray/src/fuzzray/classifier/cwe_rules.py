from __future__ import annotations

CWE_TITLES: dict[str, str] = {
    "CWE-787": "Запись за пределами буфера",
    "CWE-125": "Чтение за пределами буфера",
    "CWE-415": "Двойное освобождение памяти",
    "CWE-416": "Использование памяти после освобождения",
    "CWE-119": "Некорректное ограничение операций в пределах буфера",
    "CWE-476": "Разыменование нулевого указателя",
    "CWE-190": "Целочисленное переполнение",
    "CWE-369": "Деление на ноль",
    "CWE-457": "Использование неинициализированной переменной",
    "CWE-681": "Некорректное преобразование между числовыми типами",
    "CWE-134": "Уязвимость форматной строки",
    "unknown": "Не классифицировано",
}

CWE_RECOMMENDATIONS: dict[str, str] = {
    "CWE-787": "Проверяйте границы буфера перед записью; используйте безопасные API с проверкой длины (strncpy_s, snprintf); добавьте флаги защиты времени выполнения -D_FORTIFY_SOURCE=2 и -fstack-protector-strong.",
    "CWE-125": "Проверяйте индексы и длины перед чтением; используйте size_t и насыщающую арифметику; убедитесь, что поле длины не контролируется пользователем без валидации.",
    "CWE-415": "Обнуляйте указатели после free() и проверяйте на NULL перед повторным освобождением; используйте обёртки с автоматическим обнулением.",
    "CWE-416": "Обнуляйте указатели после освобождения и не используйте их повторно; рассмотрите использование arena-аллокаторов или умных указателей.",
    "CWE-119": "Проведите аудит арифметики указателей и полей длины; предпочитайте абстракции span/slice; добавьте флаг -D_FORTIFY_SOURCE=2.",
    "CWE-476": "Проверяйте указатели на NULL перед разыменованием; превращайте неявные контракты в явные assert-проверки.",
    "CWE-190": "Используйте проверяемую арифметику (__builtin_add_overflow, __builtin_mul_overflow) или насыщение size_t; добавьте проверки границ перед арифметическими операциями.",
    "CWE-369": "Проверяйте делитель на ноль перед операцией деления или взятия остатка; добавьте явную проверку: if (b == 0) return ERR;.",
    "CWE-457": "Инициализируйте все локальные переменные и поля структур при объявлении; компилируйте с предупреждением -Wuninitialized.",
    "CWE-681": "Проверяйте диапазон значений перед приведением типов (float→int, int64→int32); используйте явные проверки или safe_cast-обёртки.",
    "CWE-134": "Никогда не передавайте пользовательские данные как форматную строку; всегда используйте литеральные форматные строки вида printf(\"%s\", user_data); компилируйте с -Wformat-security.",
}

ERROR_RECOMMENDATIONS: dict[str, str] = {
    "ERROR_SEGFAULT": "Проверьте обращения к памяти в указанной функции: валидность указателей, границы массивов, корректность индексов. Соберите с -fsanitize=address для точной диагностики.",
    "ERROR_ABORT": "Программа вызвала abort() — проверьте assert-условия, работу с heap (double-free, heap corruption). Соберите с -fsanitize=address для детализации.",
    "ERROR_BUSERROR": "Проверьте выравнивание данных при обращении к памяти и работу с mmap/shared memory. Убедитесь, что структуры выровнены корректно.",
    "ERROR_ILL": "Процессор встретил недопустимую инструкцию. Часто вызвано UBSan в trap-режиме — соберите с -fsanitize=undefined -fno-sanitize-trap для подробного отчёта.",
    "ERROR_FPE": "Проверьте все операции деления и модуля в указанной функции — убедитесь, что делитель не может быть нулём. Добавьте проверку перед операцией.",
    "ERROR_TIMEOUT": "Программа зависла — проверьте циклы и рекурсию в указанной функции на предмет бесконечных итераций при определённых входных данных.",
    "ERROR_UNKNOWN": "Причина сбоя не определена автоматически. Соберите цель с -fsanitize=address,undefined и повторите анализ для точной классификации.",
}


def build_dynamic_recommendation(
    top_cwe: str,
    signal_class: str,
    crash_site: str,
    backtrace: list[str],
    faulting_instruction: str | None,
    crash_function: str | None = None,
    crash_location: str | None = None,
    source_snippet: list[tuple[int, str]] | None = None,
    source_snippet_crash_line: int | None = None,
) -> str:
    parts: list[str] = []

    from fuzzray.classifier.recommender import analyze_snippet
    code_aware = analyze_snippet(top_cwe, source_snippet or [], source_snippet_crash_line)
    if code_aware:
        parts.append(code_aware)
    elif top_cwe != "unknown" and top_cwe in CWE_RECOMMENDATIONS:
        parts.append(CWE_RECOMMENDATIONS[top_cwe])
    elif signal_class in ERROR_RECOMMENDATIONS:
        parts.append(ERROR_RECOMMENDATIONS[signal_class])

    func_name = crash_function
    file_loc = crash_location
    if (not func_name or not file_loc) and backtrace:
        for frame in backtrace:
            if _is_noise(frame):
                continue
            func_name = func_name or _extract_function(frame)
            file_loc = file_loc or _extract_location(frame)
            if func_name and func_name != "optimized out":
                break
    if func_name and file_loc:
        parts.append(f"Сбой произошёл в функции {func_name} ({file_loc}).")
    elif func_name:
        parts.append(f"Сбой произошёл в функции {func_name}.")
    elif file_loc:
        parts.append(f"Сбой произошёл в {file_loc}.")

    site_hints = {
        "libc_alloc": "Краш в аллокаторе (malloc/free) — вероятно повреждение heap-метаданных выше по стеку. Ищите ошибку в вызывающем коде.",
        "libc_string": "Краш в строковой функции (memcpy/strcpy) — вероятно передан буфер недостаточного размера. Проверьте аргументы вызова.",
        "libc_io": "Краш в функции ввода-вывода — возможна проблема с форматной строкой или невалидным буфером.",
    }
    if crash_site in site_hints:
        parts.append(site_hints[crash_site])

    if faulting_instruction:
        if "div" in faulting_instruction.lower() or "idiv" in faulting_instruction.lower():
            parts.append("Инструкция деления — убедитесь, что делитель проверяется на ноль.")
        elif "call" in faulting_instruction.lower() or "jmp" in faulting_instruction.lower():
            parts.append("Инструкция перехода — возможно повреждение указателя на функцию или vtable.")
        elif "mov" in faulting_instruction.lower():
            parts.append("Инструкция обращения к памяти — проверьте валидность адреса назначения.")

    return " ".join(parts) if parts else "Соберите цель с -fsanitize=address,undefined для точной классификации."


_NOISE_FRAME_RE = None


def _is_noise(frame: str) -> bool:
    global _NOISE_FRAME_RE
    if _NOISE_FRAME_RE is None:
        import re
        _NOISE_FRAME_RE = re.compile(
            r"__pthread_kill|__GI_raise|__GI_abort|"
            r"__asan_|__sanitizer_|__interceptor_|"
            r"__ubsan_|__msan_|__lsan_|"
            r"/nptl/|/sysdeps/|/glibc-|"
            r"__libc_start|_start$"
        )
    return bool(_NOISE_FRAME_RE.search(frame))


def _extract_function(frame: str) -> str | None:
    import re
    m = re.search(r"\bin\s+(\w+)\s*\(", frame)
    if m and m.group(1) not in ("optimized", "out"):
        return m.group(1)
    m = re.search(r"<([^+>]+)", frame)
    if m:
        return m.group(1)
    return None


def _extract_location(frame: str) -> str | None:
    import re
    m = re.search(r"at\s+(\S+:\d+)", frame)
    if m:
        return m.group(1)
    return None


def signal_to_cwe_prior(sig: int | None) -> dict[str, float]:
    if sig is None:
        return {"unknown": 0.5}
    if sig == 11:  # SIGSEGV
        return {"CWE-787": 0.25, "CWE-125": 0.25, "CWE-476": 0.2, "unknown": 0.3}
    if sig == 6:  # SIGABRT
        return {"CWE-787": 0.3, "CWE-416": 0.2, "CWE-119": 0.2, "unknown": 0.3}
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
