#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct Header {
    char magic[4];
    int32_t type;
    int32_t count;
    int32_t size;
    int32_t offset;
    char name[16];
};

void process(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return;

    struct Header hdr;
    if (fread(&hdr, sizeof(hdr), 1, fp) != 1) {
        fclose(fp);
        return;
    }

    // CWE-125: stack-buffer-overflow READ (name не null-terminated)
    printf("Name: %s\n", hdr.name);

    // CWE-190: integer overflow (add)
    int32_t total = hdr.count + hdr.size;

    // CWE-190: integer overflow (mul)
    int32_t area = hdr.count * hdr.size;

    // CWE-190: integer underflow (sub)
    int32_t diff = hdr.count - hdr.size;

    // CWE-369: divide by zero
    if (hdr.type > 0) {
        int32_t ratio = hdr.count / hdr.offset;
        printf("Ratio: %d\n", ratio);
    }

    // CWE-190: shift out of bounds
    if (hdr.type > 1) {
        int32_t shifted = hdr.count << hdr.offset;
        printf("Shifted: %d\n", shifted);
    }

    char *buf = (char *)malloc(total);
    if (!buf) {
        fclose(fp);
        return;
    }

    // CWE-787: heap-buffer-overflow WRITE
    memcpy(buf, hdr.name, sizeof(hdr.name));

    // CWE-125: heap-buffer-overflow READ
    if (hdr.type > 2) {
        char leak = buf[total + 10];
        printf("Leak: %c\n", leak);
    }

    // CWE-787: OOB write (heap)
    if (hdr.type > 3) {
        buf[total + 5] = 'X';
    }

    // CWE-415: double-free
    free(buf);
    if (hdr.type > 4) {
        free(buf);
    }

    // CWE-416: use-after-free
    if (hdr.type > 5) {
        buf[0] = 'A';
    }

    // CWE-476: NULL pointer dereference
    if (hdr.type > 6) {
        char *p = NULL;
        p[0] = 'B';
    }

    // CWE-134: format string
    if (hdr.type > 7) {
        char fmt[20];
        memcpy(fmt, hdr.name, 16);
        fmt[16] = '\0';
        printf(fmt);
    }

    // CWE-787: stack buffer overflow WRITE
    if (hdr.type > 8) {
        char small[8];
        memcpy(small, hdr.name, sizeof(hdr.name));
    }

    // CWE-457: uninitialized read (via computed index)
    if (hdr.type > 9) {
        int idx;
        char arr[10] = {0};
        arr[idx] = 'C';
    }

    // CWE-787: OOB write via negative index
    if (hdr.type > 10) {
        char local[32];
        memset(local, 0, 32);
        local[diff] = 'D';
    }

    fclose(fp);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }
    process(argv[1]);
    return 0;
}
