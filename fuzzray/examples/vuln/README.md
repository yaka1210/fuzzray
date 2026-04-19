# Ground-truth target for FuzzRay

`vuln.c` contains three independent bugs selected by `input[0]`:

| First byte | Bug | CWE | Expected classification |
|---|---|---|---|
| `A` | stack overflow via `strcpy` | CWE-787 | CRITICAL, ERROR_SEGFAULT / libc_string |
| `B` | NULL pointer dereference | CWE-476 | MEDIUM, ERROR_SEGFAULT / user_code / null_page |
| `C` | division by zero | CWE-369 | MEDIUM, ERROR_FPE / user_code |

## Build

```bash
# AFL++ instrumented
afl-clang-fast -O1 -g -o vuln examples/vuln/vuln.c

# ASan + UBSan variant — used by FuzzRay for ground-truth labels
afl-clang-fast -O1 -g -fsanitize=address,undefined \
    -fno-omit-frame-pointer -o vuln.asan examples/vuln/vuln.c
```

## Fuzz

```bash
mkdir -p seeds out
printf 'A' > seeds/a ; printf 'B' > seeds/b ; printf 'C' > seeds/c
timeout 120 afl-fuzz -i seeds -o out -- ./vuln @@
```

## Analyze

```bash
uv run fuzzray --afl-out out --target ./vuln.asan -o report.html
```

Expected: **3 unique issues** in the report (dedup works), each labelled
with the correct CWE (classifier works), CRITICAL / MEDIUM / MEDIUM
ordering (prioritizer works).
