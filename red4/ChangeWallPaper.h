// ChangeWallPaper.h
#ifndef CHANGE_WALLPAPER_H
#define CHANGE_WALLPAPER_H

extern const char *FIXED_WALLPAPER;


/*
 * change_wallpaper()
 *
 * TODO:
 *  - 인자로 받은 image_path를 이용해 "바탕화면 배경 이미지"를 변경하는 기능
 *    OS / 데스크톱 환경(GNOME, KDE, XFCE 등)에 맞는 명령을
 *    ChangeWallPaper.c 안에서 system() 또는 해당 API를 호출해야 함.
 *
 *  - 예시 아이디어 (실제 코드는 ChangeWallPaper.c에 작성):
 *      GNOME:
 *        gsettings set org.gnome.desktop.background picture-uri "file:///절대/경로/이미지.png"
 */
int change_wallpaper(const char *image_path);
int restore_default_wallpaper();

#endif

