/*
 * FuzzRay ground-truth target #2 — heap-ориентированные баги.
 *
 *   input[0] == 'U'  -> CWE-416  Use After Free
 *   input[0] == 'O'  -> CWE-125  Out-of-bounds Read (heap)
 *   input[0] == 'L'  -> CWE-401  Memory Leak (утечка, LeakSanitizer)
 *   otherwise        -> чистый выход
 *
 * Сборка:
 *   afl-clang-fast -O1 -g -o heapbug examples/heapbug/heapbug.c
 *   afl-clang-fast -O1 -g -fsanitize=address,undefined \
 *       -fno-omit-frame-pointer -o heapbug.asan examples/heapbug/heapbug.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void bug_use_after_free(const unsigned char *data, size_t n) {
    char *buf = malloc(64);
    if (!buf) return;
    size_t copy = n < 63 ? n : 63;
    memcpy(buf, data, copy);
    buf[copy] = '\0';
    free(buf);
    /* CWE-416: обращение к освобождённой памяти */
    printf("freed content: %s\n", buf);
}

static void bug_oob_read(const unsigned char *data, size_t n) {
    size_t alloc = 16;
    char *buf = malloc(alloc);
    if (!buf) return;
    memcpy(buf, data, alloc < n ? alloc : n);
    /* CWE-125: индекс из входных данных, без проверки границ */
    unsigned idx = 0;
    if (n >= 3) {
        idx = ((unsigned)data[1] << 8) | data[2];
    }
    printf("read: %d\n", buf[idx]);
    free(buf);
}

static void bug_memory_leak(const unsigned char *data, size_t n) {
    /* CWE-401: выделяем и «забываем» освободить */
    for (int i = 0; i < 10; i++) {
        char *block = malloc(256);
        if (!block) return;
        memset(block, data[1 % n], 256);
        /* free(block) — намеренно пропущен */
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

    unsigned char buf[512] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) return 0;

    switch (buf[0]) {
        case 'U': bug_use_after_free(buf + 1, n - 1); break;
        case 'O': bug_oob_read(buf, n); break;
        case 'L': bug_memory_leak(buf, n); break;
        default:  break;
    }
    return 0;
}
