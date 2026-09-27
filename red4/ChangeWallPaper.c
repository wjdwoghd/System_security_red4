#include "ChangeWallPaper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// 암호화 완료 후 설정할 새로운 바탕화면 이미지의 경로를 정의합니다.
// GNOME 환경에서 사용되는 이미지 파일 경로여야 합니다.
const char *FIXED_WALLPAPER = "/home/jjh/RED4/test.png"; // 시연 당시에는 절대 경로 수정 필요

/**
 * @brief 지정된 이미지 경로로 현재 시스템의 바탕화면을 변경합니다.
 * 주로 GNOME 데스크톱 환경의 'gsettings' 명령을 사용합니다.
 * @param image_path 새로운 바탕화면 이미지 파일의 경로 (절대 경로 권장)
 * @return int 성공 시 0, 실패 시 -1 반환
 */
int change_wallpaper(const char *image_path)
{
     // 입력 경로 유효성 검사
    if (image_path == NULL || image_path[0] == '\0') {
        fprintf(stderr, "[WALLPAPER] Error: Image path is NULL or empty.\n");
        return -1;
    }
    printf("[WALLPAPER] Changing to wallpaper: %s\n", image_path);

    char cmd[2048];     // 실행할 쉘 명령어를 저장할 버퍼  
    int system_result;    // system() 함수 실행 결과를 저장할 변수

    // gsettings 명령 문자열 생성:
    // org.gnome.desktop.background 스키마의 picture-uri 속성을 변경합니다.
    // 'file://' 접두사를 붙여 URI 형식으로 경로를 설정해야 합니다.
    // picture-uri (일반 모드)와 picture-uri-dark (다크 모드) 모두 설정합니다.
    snprintf(cmd, sizeof(cmd),
        "gsettings set org.gnome.desktop.background picture-uri 'file://%s' && "
        "gsettings set org.gnome.desktop.background picture-uri-dark 'file://%s'",
        image_path, image_path
    );

    printf("[WALLPAPER] Executing: %s\n", cmd);
    
    // system() 함수를 사용하여 쉘 명령어 실행
    system_result = system(cmd);

    // system() 실행 결과 확인
    if (system_result == -1) {
         // 명령어 실행 자체가 실패했을 경우 (예: system call error)
        perror("[WALLPAPER] Failed to execute gsettings command");
        return -1;
    }
    // gsettings 명령 자체의 성공/실패 확인은 system_result를 통해 더 정밀하게 할 수 있으나, 여기서는 system call 실패만 확인합니다.

    printf("[WALLPAPER] Wallpaper changed successfully.\n");
    return 0;
}

/**
 * @brief 바탕화면 설정을 기본값(Default)으로 복구합니다.
 * 주로 GNOME 데스크톱 환경의 'gsettings reset' 명령을 사용합니다.
 * @return int 성공 시 0, 실패 시 -1 반환
 */
int restore_default_wallpaper()
{
    printf("[WALLPAPER] Restoring default wallpaper...\n");

    char cmd[2048];  // 실행할 쉘 명령어를 저장할 버퍼
    int system_result;  // system() 함수 실행 결과를 저장할 변수
    
    // gsettings reset 명령 문자열 생성:
    // picture-uri 및 picture-uri-dark 속성을 기본값으로 되돌립니다.
    snprintf(cmd, sizeof(cmd),
        "gsettings reset org.gnome.desktop.background picture-uri && "
        "gsettings reset org.gnome.desktop.background picture-uri-dark"
    );

    printf("[WALLPAPER] Executing: %s\n", cmd);
    
    // system() 함수를 사용하여 쉘 명령어 실행
    system_result = system(cmd);

    // system() 실행 결과 확인
    if (system_result == -1) {
        perror("[WALLPAPER] Failed to execute gsettings reset command");
        return -1;
    }

    printf("[WALLPAPER] Default wallpaper restored successfully.\n");
    return 0;
}

