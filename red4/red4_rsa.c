#include "red4_rsa.h"
#include <stdio.h>
#include <fcntl.h>      // open
#include <unistd.h>

#include "red4_external/openssl/pem.h"
#include "red4_external/openssl/rsa.h"
#include "red4_external/openssl/err.h"
#include "red4_external/openssl/bn.h"

// RSA 키 파일 이름
#define PUBKEY_FILE  "red4_public.pem"
#define PRIVKEY_FILE "red4_private.pem"

#define AES_KEYLEN 16

// ------------------------------------------------------------
// RSA 2048-bit 키쌍 생성 (공개키/개인키) 및 파일로 저장
//   - 공개키: PUBKEY_FILE ("public.pem"), 2048bit
//   - 개인키: PRIVKEY_FILE ("private.pem"), 2048bit
//   - 지수(e) = 65537 (RSA_F4)  → 산업표준, 보안성과 속도 최적값
//   - 생성된 RSA 오브젝트는 이후 공개키 암호화 / 개인키 복호화에 사용
// ------------------------------------------------------------
int generate_rsa_keypair(void)
{
    int ret = -1;             // 함수의 최종 반환값 저장 변수
    RSA *rsa = NULL;          // RSA 키 정보(모듈러스, 지수 등)를 저장하는 구조체 포인터
    BIGNUM *bn = NULL;        // 공개 지수(e)를 저장하기 위한 Big Number 구조체 포인터
    FILE *fp = NULL;          // PEM 파일 쓰기를 위한 FILE 포인터

    rsa = RSA_new();          // RSA 구조체 동적 생성 (키 정보 저장할 공간)
    bn  = BN_new();           // BIGNUM 구조체 동적 생성 (RSA_F4 값을 담을 공간)
    if (!rsa || !bn) {        // 둘 중 하나라도 생성 실패하면 오류 처리
        printf("RSA/BIGNUM 생성 실패\n");
        goto cleanup;         // 아래 cleanup 블록으로 이동해 생성된 자원 해제
    }

    // RSA 지수(e) 값 설정 → 65537 (RSA_F4)
    // *RSA에서 e는 고정값(65537)이 가장 보안적/성능적 균형이 좋기 때문에 업계 표준
    if (!BN_set_word(bn, RSA_F4)) {
        printf("BN_set_word 실패\n");
        goto cleanup;
    }

    // ------------------------------------------------------------
    // RSA_generate_key_ex:
    //   - rsa 구조체에 2048-bit 길이의 공개키/개인키 쌍 생성
    //   - bn: e 값(65537)
    //   - NULL: 추가 콜백 없음
    // 생성되면 rsa안에 n(모듈러스), d(개인키), e(공개 지수) 등이 채워짐
    // ------------------------------------------------------------
    if (!RSA_generate_key_ex(rsa, 2048, bn, NULL)) {
        printf("RSA_generate_key_ex 실패: %s\n",
               ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    // ------------------------------------------------------------
    // 개인키 저장 (BEGIN RSA PRIVATE KEY)
    // ------------------------------------------------------------
    fp = fopen(PRIVKEY_FILE, "wb");     // 개인키 저장할 파일 열기 (쓰기 전용, 바이너리)
    if (!fp) {
        perror("개인키 파일 생성 실패"); // 파일 권한/경로 문제로 열기 실패
        goto cleanup;
    }

    // PEM_write_RSAPrivateKey:
    //   - rsa 내부의 개인키(d) 포함 전체 비밀키 정보를 PEM 형식으로 파일에 기록
    //   - 암호 없음(NULL, NULL) → 평문 PEM
    if (!PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL)) {
        printf("개인키 PEM 쓰기 실패: %s\n",
               ERR_error_string(ERR_get_error(), NULL));
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);       // 개인키 파일 닫기
    fp = NULL;        // 중복 close 방지 위해 NULL 처리

    // ------------------------------------------------------------
    // 공개키 저장 (BEGIN PUBLIC KEY)
    // PEM_write_RSA_PUBKEY:
    //   - 공개키(n, e)만 포함하는 표준 "SubjectPublicKeyInfo" 구조 저장
    //   - OpenSSH 등 대부분 환경에서 호환되는 공개키 형식
    // ------------------------------------------------------------
    fp = fopen(PUBKEY_FILE, "wb");   // 공개키 저장용 파일 열기
    if (!fp) {
        perror("공개키 파일 생성 실패");
        goto cleanup;
    }

    if (!PEM_write_RSA_PUBKEY(fp, rsa)) {
        printf("공개키 PEM 쓰기 실패: %s\n",
               ERR_error_string(ERR_get_error(), NULL));
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);
    fp = NULL;

    // RSA 키 생성 성공 메시지
    printf("[+] RSA 키쌍 생성 및 저장 완료: %s, %s\n", 
           PUBKEY_FILE, PRIVKEY_FILE);
    ret = 0;          // 성공

cleanup:
    if (fp) fclose(fp);  // 파일이 열려 있으면 닫기
    if (bn) BN_free(bn); // BIGNUM 자원 해제
    if (rsa) RSA_free(rsa); // RSA 구조체 자원 해제
    return ret;       // 성공(0) 또는 실패(-1)
}



// ------------------------------------------------------------
// RSA 공개키로 AES 키(16바이트)를 암호화하는 함수
//   - plain     : 암호화할 원본(AES 키 16바이트)
//   - plain_len : AES_KEYLEN (16)
//   - out       : RSA 암호문이 저장될 버퍼 (보통 256바이트)
//   - out_len   : 암호문 실제 길이를 저장할 변수
//   - 사용 알고리즘: RSA 2048bit + OAEP 패딩 (안전한 RSA 암호화 방식)
//   	- OAEP 패딩 : 원본 데이터(AES키)에 난수(random seed)를 추가하여, AES키가 변하지 않더라도 암호화 결과 매번 변화 되도록 
// ------------------------------------------------------------
int rsa_encrypt_key(unsigned char *plain, size_t plain_len,
                    unsigned char *out, size_t *out_len)
{
    // RSA 공개키 파일 열기 (확장자".pem")
    //   - "public.pem" 파일을 읽기 모드(rb)로 열어서 RSA 구조체를 만들기 위함
    FILE *fp = fopen(PUBKEY_FILE, "rb");
    if (!fp) {                           // 파일 열기 실패(파일 없음, 권한 문제 등)
        perror("공개키 파일 열기 실패");
        return -1;                      // 암호화 불가 → 실패
    }

    // ------------------------------------------------------------
    // PEM_read_RSA_PUBKEY:
    //   - public.pem 파일 내부의 "BEGIN PUBLIC KEY" 내용을 읽어 RSA 구조체 생성
    //   - 내부적으로 n(모듈러스), e(지수) 정보를 rsa 구조체에 채운다.
    // ------------------------------------------------------------
    RSA *rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);                         // 파일 사용 끝났으므로 바로 close

    if (!rsa) {                         // 공개키 읽기 실패 → RSA 구조체 생성 실패
        printf("RSA 공개키 읽기 실패: %s\n",
               ERR_error_string(ERR_get_error(), NULL));
        return -1;                      // 실패 반환
    }

    // ------------------------------------------------------------
    // RSA_public_encrypt:
    //   - RSA 공개키로 plain 데이터를 암호화하여 out 버퍼에 저장
    //   - plain_len : 16바이트(AES 키)
    //   - out       : 암호문 저장(2048bit RSA → 256바이트)
    //   - padding   : OAEP → 안전한 공개키 암호화의 표준 패딩
    //
    // 반환값(len) = 실제 암호문 길이 (성공 시 256)
    // ------------------------------------------------------------
    int len = RSA_public_encrypt(
        (int)plain_len,    // 입력 평문 길이 (AES_KEYLEN = 16)
        plain,             // 평문 데이터(AES 키)
        out,               // 암호문 출력 버퍼
        rsa,               // RSA 공개키 구조체
        RSA_PKCS1_OAEP_PADDING  // 안전한 패딩 방식 사용
    );

    RSA_free(rsa);         // RSA 구조체 사용 끝 → 메모리 해제

    // 암호화 실패 시 RSA_public_encrypt는 0 또는 음수를 반환
    if (len <= 0) {
        printf("RSA 공개키 암호화 실패: %s\n",
               ERR_error_string(ERR_get_error(), NULL));
        return -1;        // 암호화 실패 반환
    }

    // 성공 시 out_len에 실제 암호문 크기 저장 (보통 256바이트)
    *out_len = (size_t)len;
    return 0;             // RSA 공개키 암호화 성공
}



// ------------------------------------------------------------
// RSA 암호문 파일 저장
//   - red4_key.bin 파일에 RSA로 암호화된 AES 키(보통 256바이트)를 저장한다.
//   - 이 파일은 더 이상 평문 AES 키를 저장하지 않고, 반드시 RSA 암호문만 저장한다.
// ------------------------------------------------------------
int save_rsa_encrypted_keyfile(unsigned char *enc, size_t enc_len)
{
    // KEYFILE("red4_key.bin") 파일 생성 (또는 기존 파일 덮어쓰기)
    // O_WRONLY : 쓰기 전용
    // O_CREAT  : 파일이 없으면 생성
    // O_TRUNC  : 기존 파일 있으면 내용 비움
    // 0600     : 오직 owner만 읽기/쓰기 가능 (중요! 키 파일 보호 목적)
    int fd = open(KEYFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) {                       // 파일 열기 실패 시
        perror("RSA keyfile open 실패");
        return -1;
    }

    // enc(암호문) enc_len(길이) 만큼 파일에 실제로 쓰기
    // write() 반환값이 enc_len과 다르면 저장 중 오류 발생
    if (write(fd, enc, enc_len) != (ssize_t)enc_len) {
        perror("RSA key write 실패");
        close(fd);
        return -1;
    }

    // 파일 닫기 — 리소스 정리
    close(fd);

    printf("[+] RSA 암호화된 AES 키 파일 저장 완료: %s\n", KEYFILE);
    return 0;                              // 성공
}


// ------------------------------------------------------------
// RSA 개인키로 AES 키 복호화하는 함수
//   - enc      : RSA 암호문(보통 256바이트, 공개키로 암호화됨)
//   - enc_len  : 암호문 길이
//   - out      : 복호화된 평문(AES 키 16바이트)을 저장할 버퍼
//   - out_len  : 복호화된 평문 길이(AES_KEYLEN이어야 정상)
//   - RSA 개인키로 RSA_public_encrypt로 암호화된 데이터를 복호화한다.
// ------------------------------------------------------------
int rsa_decrypt_key(unsigned char *enc, size_t enc_len,
                    unsigned char *out, size_t *out_len)
{
    // 개인키 파일(private.pem) 열기
    //   - RSA_private_decrypt에 필요한 비밀키(d)를 얻기 위함
    //   - 공개키 암호문은 반드시 해당 개인키가 있어야 복호화 가능
    FILE *fp = fopen(PRIVKEY_FILE, "rb");
    if (!fp) {                         // 파일 열기 실패(없음, 권한 문제 등)
        perror("개인키 파일 열기 실패");
        return -1;                    // 개인키 없으면 복호화 불가
    }

    // ------------------------------------------------------------
    // PEM_read_RSAPrivateKey:
    //   - private.pem 파일에서 BEGIN RSA PRIVATE KEY 블록을 읽어서
    //     RSA 구조체(rsa)에 n(모듈러스) + d(개인 지수) + e(공개 지수) 등
    //     복호화에 필요한 전체 정보를 채운다.
    // ------------------------------------------------------------
    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);                       // 파일 사용 끝났으니 닫기

    if (!rsa) {                       // 개인키 읽기 실패 → RSA 구조체 생성 실패
        printf("RSA 개인키 읽기 실패: %s\n",
               ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // ------------------------------------------------------------
    // RSA_private_decrypt:
    //   - RSA_public_encrypt로 암호화된 데이터를 복호화하는 함수
    //   - enc      : 암호문(256바이트)
    //   - enc_len  : 암호문 길이
    //   - out      : 복호화 평문(AES 키 16바이트)
    //   - padding  : OAEP → 암호화 시 사용한 패딩 방식 동일하게 지정
    //
    // 반환값(len) = 복호화된 데이터 길이 (정상 시 16바이트)
    // ------------------------------------------------------------
    int len = RSA_private_decrypt(
        (int)enc_len,   // 입력 암호문 길이(보통 256)
        enc,            // RSA 암호문
        out,            // 복호화된 AES 키가 저장될 버퍼
        rsa,            // RSA 개인키 구조체
        RSA_PKCS1_OAEP_PADDING  // 암호화 시 사용한 패딩과 동일하게
    );

    RSA_free(rsa);                    // RSA 구조체 메모리 해제

    // 복호화 실패 → len <= 0
    if (len <= 0) {
        printf("RSA 복호화 실패: %s\n",
               ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // 정상 복호화 → AES 키 길이(16바이트)를 out_len에 저장
    *out_len = (size_t)len;
    return 0;                      
}


// ------------------------------------------------------------
// RSA 암호문 파일 로드 (+ RSA 개인키로 AES 키 복호화하는 함수 호출)
//   - red4_key.bin 에 저장된 RSA 암호문을 읽고
//   - private.pem(개인키)로 복호화하여 AES 키 16바이트를 복원한다.
//   - 복호화된 AES 키가 key[] 버퍼로 전달되어 이후 파일 복호화에 사용된다.
// ------------------------------------------------------------
int load_rsa_encrypted_keyfile(unsigned char *key)
{
    // RSA 암호문이 저장된 파일(red4_key.bin) 열기
    int fd = open(KEYFILE, O_RDONLY);
    if (fd == -1) {                       // 파일 없음, 권한 문제 등
        perror("RSA keyfile open 실패");
        return -1;                       // RSA 암호문 없으면 복호화 불가
    }

    // RSA 암호문 저장 버퍼 — 512바이트 정도 잡아둠
    // (2048-bit RSA = 256바이트 암호문이므로 충분한 크기)
    unsigned char enc[512];

    // 파일에서 RSA 암호문 읽기 (일반적으로 256바이트)
    ssize_t enc_len = read(fd, enc, sizeof(enc));
    close(fd);                            // 파일 다 읽었으니 닫기

    if (enc_len <= 0) {                    // 파일 비었거나 읽기 오류
        printf("RSA 암호문 읽기 실패\n");
        return -1;
    }

    // ------------------------------------------------------------
    // RSA 개인키로 암호문을 복호화하여 AES 키를 복원한다.
    //   enc      : 읽어온 RSA 암호문
    //   enc_len  : 암호문 길이
    //   key      : 복호화된 AES 키 저장 버퍼 (16바이트)
    //   out_len  : 실제 복호화된 데이터 길이 저장
    // ------------------------------------------------------------
    size_t out_len = 0;
    if (rsa_decrypt_key(enc, (size_t)enc_len, key, &out_len) != 0) {
        printf("RSA 복호화 실패 → AES 키 복원 불가\n");
        return -1;
    }

    // AES 키는 반드시 16바이트여야 정상 (128bit AES 키)
    if (out_len != AES_KEYLEN) {
        printf("복호화된 키 길이 오류\n");  // RSA 복호화는 됐으나 데이터 길이 이상
        return -1;
    }

    // RSA → AES 키 복원 성공 메시지
    printf("[+] RSA 복호화로 AES 키 로드 완료: %s\n", KEYFILE);
    return 0;                              
}









