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

    // [R1 FIX] CWE-190 AddOverflow
    int64_t total64 = (int64_t)hdr.count + (int64_t)hdr.size;
    if (total64 > INT32_MAX || total64 < 0) {
        fprintf(stderr, "overflow detected (add)\n");
        fclose(fp);
        return;
    }
    int32_t total = (int32_t)total64;

    // [R1 FIX] CWE-190 MulOverflow
    int64_t area64 = (int64_t)hdr.count * (int64_t)hdr.size;
    if (area64 > INT32_MAX || area64 < INT32_MIN) {
        fprintf(stderr, "overflow detected (mul)\n");
        fclose(fp);
        return;
    }
    int32_t area = (int32_t)area64;

    // [R1 FIX] CWE-190 SubOverflow
    int64_t diff64 = (int64_t)hdr.count - (int64_t)hdr.size;
    if (diff64 > INT32_MAX || diff64 < INT32_MIN) {
        fprintf(stderr, "overflow detected (sub)\n");
        fclose(fp);
        return;
    }
    int32_t diff = (int32_t)diff64;

    // [R1 FIX] CWE-369: divide by zero
    if (hdr.type > 0) {
        if (hdr.offset != 0) {
            int32_t ratio = hdr.count / hdr.offset;
            printf("Ratio: %d\n", ratio);
        }
    }

    // [R1 FIX] CWE-190 ShiftOutOfBounds
    if (hdr.type > 1) {
        if (hdr.count >= 0 && hdr.offset >= 0 && hdr.offset < 31) {
            int32_t shifted = hdr.count << hdr.offset;
            printf("Shifted: %d\n", shifted);
        }
    }

    if (total <= 0) {
        fclose(fp);
        return;
    }

    char *buf = (char *)malloc(total);
    if (!buf) {
        fclose(fp);
        return;
    }

    // CWE-787: heap-buffer-overflow WRITE
    memcpy(buf, hdr.name, sizeof(hdr.name));

    // [R1 FIX] CWE-125: heap-buffer-overflow READ — убран выход за границы
    if (hdr.type > 2) {
        if (total > 0) {
            char leak = buf[total - 1];
            printf("Leak: %c\n", leak);
        }
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
