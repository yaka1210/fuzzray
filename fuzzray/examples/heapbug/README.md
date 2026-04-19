# heapbug — heap-ориентированные баги

`heapbug.c` содержит три независимых бага, выбираемых первым байтом входа:

| Байт | Баг | CWE | Ожидаемая классификация |
|---|---|---|---|
| `U` | Use After Free | CWE-416 | CRITICAL, heap |
| `O` | Out-of-bounds Read (heap) | CWE-125 | HIGH, heap |
| `L` | Memory Leak (без free) | CWE-401 | LOW, heap |

## Сборка

```bash
afl-clang-fast -O1 -g -o heapbug examples/heapbug/heapbug.c
afl-clang-fast -O1 -g -fsanitize=address,undefined \
    -fno-omit-frame-pointer -o heapbug.asan examples/heapbug/heapbug.c
```

## Фаззинг

```bash
mkdir -p out_heap
timeout 120 afl-fuzz -i examples/heapbug/seeds -o out_heap -- ./heapbug @@
```

## Анализ

```bash
uv run fuzzray --afl-out out_heap --target ./heapbug.asan -o report_heap.html
```

Ожидается: **3 уникальных issue** — CWE-416 (critical), CWE-125 (high), CWE-401 (low).
