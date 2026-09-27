#ifndef RED4_RSA_H
#define RED4_RSA_H

#include <stddef.h>

#define PUBKEY_FILE  "public.pem"
#define PRIVKEY_FILE "private.pem"
#define KEYFILE      "red4_key.bin"   // RSA로 암호화한 AES키, 저장 파일

// RSA 키쌍 생성 (public.pem / private.pem)
int generate_rsa_keypair(void);

// RSA 공개키로 AES 키 암호화
int rsa_encrypt_key(unsigned char *plain, size_t plain_len,
                    unsigned char *out, size_t *out_len);
// RSA 암호문 파일 저장
int save_rsa_encrypted_keyfile(unsigned char *enc, size_t enc_len);

// RSA 개인키로 AES 키 복호화
int rsa_decrypt_key(unsigned char *enc, size_t enc_len,
                    unsigned char *out, size_t *out_len);

// RSA 암호문 파일 로드 (RSA 개인키로 AES 키 복호화 함수 호출)
int load_rsa_encrypted_keyfile(unsigned char *key);

#endif
