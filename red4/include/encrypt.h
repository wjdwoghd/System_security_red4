#ifndef ENCRYPT_H
#define ENCRYPT_H
#include <stddef.h>
#include <stdint.h>

int encrypt_file(const char *filepath);

typedef struct {
    char     magic[4];
    uint8_t  version;
    uint8_t  reserved[3];
    uint32_t original_size;
    uint16_t ek_len;
    uint16_t iv_len;
} enc_header_t;

#endif

