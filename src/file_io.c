#define _POSIX_C_SOURCE 200809L
#include "file_io.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>

static void log_info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[INFO] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static void log_error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[ERROR] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

int read_file(const char *path, unsigned char **out_buf, size_t *out_len) {
    if (!path || !out_buf || !out_len) return -1;
    struct stat st;
    if (stat(path, &st) != 0) {
        log_error("Could not stat input file %s: %s", path, strerror(errno));
        return -2;
    }
    if (!S_ISREG(st.st_mode)) {
        log_error("Input path is not a regular file: %s", path);
        return -3;
    }
    FILE *f = fopen(path, "rb");
    if (!f) {
        log_error("Failed to open input file %s: %s", path, strerror(errno));
        return -4;
    }
    size_t size = st.st_size;
    unsigned char *buf = malloc(size + 1);
    if (!buf) { fclose(f); return -5; }
    size_t read = fread(buf, 1, size, f);
    if (read != size && !feof(f)) {
        log_error("Failed to read file %s", path);
        free(buf); fclose(f); return -6;
    }
    fclose(f);
    *out_buf = buf;
    *out_len = read;
    log_info("Read %zu bytes from %s", read, path);
    return 0;
}

int write_file_atomic(const char *path, const unsigned char *data, size_t data_len) {
    if (!path || (!data && data_len>0)) return -1;
    char *path_copy = strdup(path);
    if (!path_copy) return -2;
    char *dir = dirname(path_copy);
    char tmpl[4096];
    snprintf(tmpl, sizeof(tmpl), "%s/cryptocore_tmp_XXXXXX", dir);
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        free(path_copy);
        fprintf(stderr, "[ERROR] mkstemp failed in dir %s: %s\n", dir, strerror(errno));
        return -3;
    }
    ssize_t written = 0;
    size_t to_write = data_len;
    const unsigned char *ptr = data;
    while (to_write > 0) {
        ssize_t w = write(fd, ptr, to_write);
        if (w < 0) {
            close(fd);
            unlink(tmpl);
            free(path_copy);
            fprintf(stderr, "[ERROR] write failed: %s\n", strerror(errno));
            return -4;
        }
        to_write -= w;
        ptr += w;
        written += w;
    }
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmpl);
        free(path_copy);
        fprintf(stderr, "[ERROR] fsync failed: %s\n", strerror(errno));
        return -5;
    }
    close(fd);
    if (rename(tmpl, path) != 0) {
        unlink(tmpl);
        free(path_copy);
        fprintf(stderr, "[ERROR] rename to %s failed: %s\n", path, strerror(errno));
        return -6;
    }
    free(path_copy);
    fprintf(stderr, "[INFO] Wrote %zu bytes to %s (atomic)\n", data_len, path);
    return 0;
}
