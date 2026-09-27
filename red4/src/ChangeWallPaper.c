#include "ChangeWallPaper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ★★ 너가 미리 지정해 놓은 바탕화면 이미지 절대경로로 변경 ★★
// 반드시 절대경로로!
// 예시: /home/jjh/Pictures/mywall.png
static const char *FIXED_WALLPAPER = "/home/jjh/red4/test.png";

int change_wallpaper(const char *unused)
{
    printf("[WALLPAPER] Changing to fixed wallpaper: %s\n", FIXED_WALLPAPER);

    char cmd[2048];
    int system_result;

    // GNOME은 picture-uri, picture-uri-dark 두 가지를 모두 바꿔줘야 테마 전환에서도 유지됨
    snprintf(cmd, sizeof(cmd),
        "gsettings set org.gnome.desktop.background picture-uri 'file://%s' && "
        "gsettings set org.gnome.desktop.background picture-uri-dark 'file://%s'",
        FIXED_WALLPAPER, FIXED_WALLPAPER
    );

    printf("[WALLPAPER] Executing: %s\n", cmd);

    system_result = system(cmd);

    if (system_result == -1) {
        perror("[WALLPAPER] Failed to execute gsettings command");
        return -1;
    }

    printf("[WALLPAPER] Wallpaper changed successfully.\n");
    return 0;
}

