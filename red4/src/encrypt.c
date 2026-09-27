#include "encrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/*
 * encrypt.c
 *
 * 하이브리드 암호 구조:
 *   - 데이터: AES-128-CBC 로 암호화
 *   - 세션 키(AES 키): RSA 공개키로 암호화
 *
 * 파일 포맷 (출력 .enc 파일):
 *   [enc_header_t][enc_key(ek_len)][iv(iv_len)][cipher(cipher_len bytes)]
 */

#define AES_KEY_SIZE   16   // AES-128
#define AES_IV_SIZE    16   // CBC IV
#define AES_BLOCK_SIZE 16

// 헤더의 magic/버전 정의
static const char ENC_MAGIC[4] = { 'R', '4', 'E', 'N' }; // 예: "R4EN"
static const uint8_t ENC_VERSION = 1;

/* ---------------- 1) 세션 키 / IV 생성 ---------------- */

static int generate_session_key_iv(uint8_t *key_out, size_t key_len,
                                   uint8_t *iv_out,  size_t iv_len)
{
    if (!key_out || !iv_out) {
        fprintf(stderr, "[ENCRYPT] generate_session_key_iv: NULL buffer\n");
        return -1;
    }

    /* RAND_bytes:
     *  - OpenSSL CSPRNG
     *  - 성공 시 1 반환
     */
    if (RAND_bytes(key_out, (int)key_len) != 1) {
        fprintf(stderr, "[ENCRYPT] RAND_bytes(key) failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (RAND_bytes(iv_out, (int)iv_len) != 1) {
        fprintf(stderr, "[ENCRYPT] RAND_bytes(iv) failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    return 0;
}

/* ---------------- 2) AES-128-CBC 버퍼 암호화 ---------------- */

static int aes_encrypt_buffer(const uint8_t *plain, size_t plain_len,
                              const uint8_t *key, const uint8_t *iv,
                              uint8_t **out_cipher, size_t *out_cipher_len)
{
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *cipher = NULL;
    int len = 0;
    int cipher_len = 0;
    int ret = -1;

    if (!plain || !key || !iv || !out_cipher || !out_cipher_len) {
        fprintf(stderr, "[ENCRYPT] aes_encrypt_buffer: invalid args\n");
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[ENCRYPT] EVP_CIPHER_CTX_new failed\n");
        return -1;
    }

    /* 출력 버퍼: 평문 길이 + 블록 크기(패딩 최대) */
    cipher = (uint8_t *)malloc(plain_len + AES_BLOCK_SIZE);
    if (!cipher) {
        fprintf(stderr, "[ENCRYPT] malloc(cipher) failed\n");
        goto cleanup;
    }

    /* AES-128-CBC 초기화 */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "[ENCRYPT] EVP_EncryptInit_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* EncryptUpdate: 평문 -> 암호문 (부분 출력) */
    if (EVP_EncryptUpdate(ctx, cipher, &len, plain, (int)plain_len) != 1) {
        fprintf(stderr, "[ENCRYPT] EVP_EncryptUpdate failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    cipher_len = len;

    /* EncryptFinal: 패딩 처리 */
    if (EVP_EncryptFinal_ex(ctx, cipher + cipher_len, &len) != 1) {
        fprintf(stderr, "[ENCRYPT] EVP_EncryptFinal_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    cipher_len += len;

    *out_cipher = cipher;
    *out_cipher_len = (size_t)cipher_len;
    cipher = NULL; // 소유권 이동
    ret = 0;

cleanup:
    if (cipher) free(cipher);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ---------------- 3) RSA로 세션 키 암호화 ---------------- */

/*
 * RSA 공개키로 16바이트 세션 키를 암호화.
 *
 * 준비:
 *   openssl 명령으로 키 쌍 생성 (예시):
 *     $ openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
 *     $ openssl rsa -in private.pem -pubout -out public.pem
 *
 *   실행 디렉터리에 public.pem 을 두고 사용.
 */
static int rsa_encrypt_key(const uint8_t *key, size_t key_len,
                           uint8_t **out_ek, size_t *out_ek_len)
{
    int ret = -1;
    FILE *fp = NULL;
    RSA  *rsa = NULL;
    uint8_t *buf = NULL;

    if (!key || !out_ek || !out_ek_len) {
        fprintf(stderr, "[ENCRYPT] rsa_encrypt_key: invalid args\n");
        return -1;
    }

    fp = fopen("public.pem", "rb");
    if (!fp) {
        perror("[ENCRYPT] fopen public.pem");
        goto cleanup;
    }

    /* public.pem 이 "-----BEGIN PUBLIC KEY-----" 형식이면
     * PEM_read_RSA_PUBKEY 사용이 맞음.
     */
    rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    fp = NULL;

    if (!rsa) {
        fprintf(stderr, "[ENCRYPT] PEM_read_RSA_PUBKEY failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    int rsa_size = RSA_size(rsa);
    buf = (uint8_t *)malloc(rsa_size);
    if (!buf) {
        fprintf(stderr, "[ENCRYPT] malloc(buf) failed\n");
        goto cleanup;
    }

    /* OAEP 패딩 사용 */
    int enc_len = RSA_public_encrypt((int)key_len, key,
                                     buf, rsa, RSA_PKCS1_OAEP_PADDING);
    if (enc_len <= 0) {
        fprintf(stderr, "[ENCRYPT] RSA_public_encrypt failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    *out_ek = buf;
    *out_ek_len = (size_t)enc_len;
    buf = NULL;  // 소유권 이동

    printf("[ENCRYPT] RSA key encryption successful. Enc key len=%d bytes\n",
           enc_len);

    ret = 0;

cleanup:
    if (buf) free(buf);
    if (rsa) RSA_free(rsa);
    if (fp) fclose(fp);
    return ret;
}

/* ---------------- 4) 출력 파일 이름 만들기 ---------------- */

static int make_encrypted_path(const char *orig, char *out, size_t out_sz)
{
    if (!orig || !out || out_sz == 0) return -1;

    size_t len = strlen(orig);
    const char *suffix = ".enc";
    size_t suffix_len = strlen(suffix);

    if (len + suffix_len + 1 > out_sz) {
        fprintf(stderr, "[ENCRYPT] Output path buffer too small\n");
        return -1;
    }

    strcpy(out, orig);
    strcat(out, suffix);
    return 0;
}

/* ---------------- 5) 메인 엔트리: 파일 암호화 ---------------- */

int encrypt_file(const char *filepath)
{
    FILE *fp = NULL;
    uint8_t *plain = NULL;
    uint8_t *cipher = NULL;
    uint8_t *enc_key = NULL;
    size_t cipher_len = 0;
    size_t enc_key_len = 0;
    uint8_t aes_key[AES_KEY_SIZE];
    uint8_t iv[AES_IV_SIZE];
    int ret = -1;

    if (!filepath) {
        fprintf(stderr, "[ENCRYPT] encrypt_file: filepath is NULL\n");
        return -1;
    }

    printf("--- Encryption started: %s ---\n", filepath);

    /* 1) 원본 파일 열기 */
    fp = fopen(filepath, "rb");
    if (!fp) {
        perror("[ENCRYPT] fopen");
        return -1;
    }

    /* 파일 크기 계산 */
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("[ENCRYPT] fseek");
        goto cleanup;
    }
    long fsize = ftell(fp);
    if (fsize < 0) {
        perror("[ENCRYPT] ftell");
        goto cleanup;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror("[ENCRYPT] fseek(SET)");
        goto cleanup;
    }

    if (fsize == 0) {
        fprintf(stderr, "[ENCRYPT] File is empty, skip: %s\n", filepath);
        goto cleanup;
    }

    /* 2) 평문 읽기 */
    plain = (uint8_t *)malloc((size_t)fsize);
    if (!plain) {
        fprintf(stderr, "[ENCRYPT] malloc(plain) failed\n");
        goto cleanup;
    }

    size_t read_bytes = fread(plain, 1, (size_t)fsize, fp);
    if (read_bytes != (size_t)fsize) {
        fprintf(stderr, "[ENCRYPT] fread failed. read=%zu, expect=%ld\n",
                read_bytes, fsize);
        goto cleanup;
    }
    fclose(fp);
    fp = NULL;

    /* 3) 세션 키 / IV 생성 */
    if (generate_session_key_iv(aes_key, AES_KEY_SIZE, iv, AES_IV_SIZE) != 0) {
        fprintf(stderr, "[ENCRYPT] generate_session_key_iv failed\n");
        goto cleanup;
    }

    /* 4) AES-128-CBC 암호화 */
    if (aes_encrypt_buffer(plain, (size_t)fsize,
                           aes_key, iv,
                           &cipher, &cipher_len) != 0) {
        fprintf(stderr, "[ENCRYPT] aes_encrypt_buffer failed\n");
        goto cleanup;
    }

    /* 5) RSA로 세션 키 암호화 */
    if (rsa_encrypt_key(aes_key, AES_KEY_SIZE, &enc_key, &enc_key_len) != 0) {
        fprintf(stderr, "[ENCRYPT] rsa_encrypt_key failed\n");
        goto cleanup;
    }

    if (enc_key_len > UINT16_MAX || AES_IV_SIZE > UINT16_MAX) {
        fprintf(stderr, "[ENCRYPT] enc_key_len/iv_len too large for header\n");
        goto cleanup;
    }

    /* 6) 출력 파일 경로 생성 (예: original + ".enc") */
    char out_path[4096];
    if (make_encrypted_path(filepath, out_path, sizeof(out_path)) != 0) {
        fprintf(stderr, "[ENCRYPT] make_encrypted_path failed\n");
        goto cleanup;
    }

    /* 7) 헤더 구성 */
    enc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, ENC_MAGIC, sizeof(hdr.magic));
    hdr.version       = ENC_VERSION;
    hdr.original_size = (uint32_t)fsize;
    hdr.ek_len        = (uint16_t)enc_key_len;
    hdr.iv_len        = (uint16_t)AES_IV_SIZE;

    /* 8) .enc 파일 쓰기: [헤더][암호화된 키][IV][암호문] */
    fp = fopen(out_path, "wb");
    if (!fp) {
        perror("[ENCRYPT] fopen(out_path)");
        goto cleanup;
    }

    if (fwrite(&hdr, 1, sizeof(hdr), fp) != sizeof(hdr)) {
        fprintf(stderr, "[ENCRYPT] fwrite(header) failed\n");
        goto cleanup;
    }

    if (fwrite(enc_key, 1, enc_key_len, fp) != enc_key_len) {
        fprintf(stderr, "[ENCRYPT] fwrite(enc_key) failed\n");
        goto cleanup;
    }

    if (fwrite(iv, 1, AES_IV_SIZE, fp) != AES_IV_SIZE) {
        fprintf(stderr, "[ENCRYPT] fwrite(iv) failed\n");
        goto cleanup;
    }

    if (fwrite(cipher, 1, cipher_len, fp) != cipher_len) {
        fprintf(stderr, "[ENCRYPT] fwrite(cipher) failed\n");
        goto cleanup;
    }

    fclose(fp);
    fp = NULL;

    printf("[ENCRYPT] Wrote encrypted file: %s (orig=%ld bytes, cipher=%zu bytes)\n",
           out_path, fsize, cipher_len);

    /* 9) 원본 파일 삭제 (과제 정책에 따라 선택) */
    if (remove(filepath) != 0) {
        perror("[ENCRYPT] Failed to delete original file");
        // 여기서 실패했다고 전체 암호화를 실패로 치고 싶으면 goto cleanup 으로 바꿔도 됨
    }

    ret = 0; // 성공

cleanup:
    if (fp) fclose(fp);
    if (plain) free(plain);
    if (cipher) free(cipher);
    if (enc_key) free(enc_key);

    printf("--- Encryption process finished (status: %s) ---\n",
           (ret == 0 ? "SUCCESS" : "FAIL"));
    return ret;
}

