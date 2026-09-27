#ifndef RED4_UTIL_H
#define RED4_UTIL_H

#include <stddef.h>

// /dev/urandom 기반 안전한 랜덤 바이트 생성
int generate_random(unsigned char *buffer, size_t len);

// 임시 파일 생성 (원본파일 + ".tmp")
int create_tmp_file(const char *filepath, char *tmp_path, int *tmp_fd);

// tmp 파일을 원본 파일로 교체 및 원본 파일 삭제 (rename)
int commit_tmp_file(const char *tmp_path, const char *filepath);

#endif

