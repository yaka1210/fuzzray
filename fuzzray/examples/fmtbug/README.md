# fmtbug — целочисленные и форматные баги

`fmtbug.c` содержит три независимых бага, выбираемых первым байтом входа:

| Байт | Баг | CWE | Ожидаемая классификация |
|---|---|---|---|
| `F` | Format String (printf с пользовательскими данными) | CWE-134 | HIGH, libc_io |
| `I` | Integer Overflow (signed addition) | CWE-190 | MEDIUM |
| `V` | Use of Uninitialized Variable | CWE-457 | MEDIUM (нужен MSan) |

## Сборка

```bash
# ASan + UBSan (ловит CWE-134 и CWE-190)
afl-clang-fast -O1 -g -fsanitize=address,undefined \
    -fno-omit-frame-pointer -o fmtbug.asan examples/fmtbug/fmtbug.c

# MSan (ловит CWE-457, не совместим с ASan — отдельная сборка)
clang -O1 -g -fsanitize=memory -fno-omit-frame-pointer \
    -o fmtbug.msan examples/fmtbug/fmtbug.c

# обычная (для AFL++)
afl-clang-fast -O1 -g -o fmtbug examples/fmtbug/fmtbug.c
```

## Фаззинг

```bash
mkdir -p out_fmt
timeout 120 afl-fuzz -i examples/fmtbug/seeds -o out_fmt -- ./fmtbug @@
```

## Анализ

```bash
uv run fuzzray --afl-out out_fmt --target ./fmtbug.asan -o report_fmt.html
```

Ожидается: **3 уникальных issue** — CWE-134 (high), CWE-190 (medium), CWE-457 (medium).
