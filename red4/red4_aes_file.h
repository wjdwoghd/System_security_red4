#ifndef RED4_AES_FILE_H
#define RED4_AES_FILE_H

#include <stddef.h>

// AES 암/복호화 크기
#define ENCRYPT_SIZE (512 * 1024)
#define AES_IVLEN    16

// 파일 AES 암호화/복호화
int encrypt_file_ctr(const char *filepath, unsigned char *key);
int decrypt_file_ctr(const char *filepath, unsigned char *key);

// 디렉터리 일괄 처리
int process_directory(const char *dirpath, unsigned char *key, int encrypt);

#endif
