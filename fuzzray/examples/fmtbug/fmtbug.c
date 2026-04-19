/*
 * FuzzRay ground-truth target #3 — целочисленные и форматные баги.
 *
 *   input[0] == 'F'  -> CWE-134  Format String (printf с пользовательскими данными)
 *   input[0] == 'I'  -> CWE-190  Integer Overflow (signed, через сложение)
 *   input[0] == 'V'  -> CWE-457  Use of Uninitialized Variable (MSan)
 *   otherwise        -> чистый выход
 *
 * Сборка:
 *   afl-clang-fast -O1 -g -o fmtbug examples/fmtbug/fmtbug.c
 *   afl-clang-fast -O1 -g -fsanitize=address,undefined \
 *       -fno-omit-frame-pointer -o fmtbug.asan examples/fmtbug/fmtbug.c
 *   # для CWE-457 нужен MSan (не совместим с ASan):
 *   clang -O1 -g -fsanitize=memory -fno-omit-frame-pointer \
 *       -o fmtbug.msan examples/fmtbug/fmtbug.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void bug_format_string(const char *data, size_t n) {
    char user_fmt[128] = {0};
    size_t copy = n < 127 ? n : 127;
    memcpy(user_fmt, data, copy);
    /* CWE-134: пользовательские данные как форматная строка */
    printf(user_fmt);
    printf("\n");
}

static void bug_integer_overflow(const unsigned char *data, size_t n) {
    if (n < 8) return;
    int a, b;
    memcpy(&a, data, 4);
    memcpy(&b, data + 4, 4);
    /* CWE-190: знаковое сложение без проверки переполнения */
    int sum = a + b;
    char *buf = malloc(sum > 0 ? (size_t)sum : 1);
    if (!buf) return;
    memset(buf, 'X', sum > 0 ? (size_t)sum : 1);
    free(buf);
}

static void bug_uninit_var(const unsigned char *data, size_t n) {
    int arr[16];
    /* CWE-457: arr не инициализирован, индекс из входа */
    unsigned idx = 0;
    if (n >= 2) idx = data[1] & 0x0F;
    /* чтение неинициализированного значения */
    if (arr[idx] > 1000) {
        printf("big value: %d\n", arr[idx]);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

    unsigned char buf[256] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) return 0;

    switch (buf[0]) {
        case 'F': bug_format_string((const char *)buf + 1, n - 1); break;
        case 'I': bug_integer_overflow(buf + 1, n - 1); break;
        case 'V': bug_uninit_var(buf, n); break;
        default:  break;
    }
    return 0;
}
