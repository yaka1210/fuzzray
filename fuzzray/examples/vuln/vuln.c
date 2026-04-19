/*
 * FuzzRay ground-truth target: three distinct bugs selected by the
 * first byte of the input. Each bug maps to a known CWE so the
 * classifier can be validated on a controlled corpus.
 *
 *   input[0] == 'A'  -> CWE-787 (stack-buffer-overflow via strcpy)
 *   input[0] == 'B'  -> CWE-476 (NULL pointer dereference)
 *   input[0] == 'C'  -> CWE-369 (divide by zero)
 *   otherwise        -> clean exit
 *
 * Build (regular):
 *   afl-clang-fast -O1 -g -o vuln examples/vuln/vuln.c
 * Build (sanitizer variant used by FuzzRay for ground-truth labels):
 *   afl-clang-fast -O1 -g -fsanitize=address,undefined \
 *       -fno-omit-frame-pointer -o vuln.asan examples/vuln/vuln.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void bug_oob_write(const char *payload) {
    char tiny[8];
    /* CWE-787: no length check on source. */
    strcpy(tiny, payload);
    puts(tiny);
}

static void bug_null_deref(void) {
    int *p = NULL;
    /* CWE-476: deterministic NULL dereference. */
    *p = 42;
}

static void bug_div_zero(const unsigned char *input, size_t n) {
    int divisor = (n >= 2) ? (int)input[1] : 0;
    /* CWE-369: input[1] is the attacker-controlled divisor. */
    int result = 1000 / divisor;
    printf("%d\n", result);
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
        case 'A': bug_oob_write((const char *)buf + 1); break;
        case 'B': bug_null_deref(); break;
        case 'C': bug_div_zero(buf, n); break;
        default:  break;
    }
    return 0;
}
