#include "red4_util.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
// ------------------------------------------------------------
// AES-CTR 암호화에서 사용 할 안전한 난수(IV, Key) 생성 (/dev/urandom)
// 리눅스/우분투 환경에서 제공해주는 난수 생성기 /dev/urandom
// rand() 함수는 seed가 time이기 때문에 파일 생성 시간으로 키값 등을 예측할 수 있다.
// ------------------------------------------------------------

int generate_random(unsigned char *buffer, size_t len) // 랜덤 바이트 저장할 버퍼, 생성 랜덤 바이트 길이
{
    int fd = open("/dev/urandom", O_RDONLY);        	// /dev/urandom, open하여 파일디스크립터 반환
    if (fd < 0) {
        perror("urandom open 실패");
        return -1;
    }
    if (read(fd, buffer, len) != (ssize_t)len) {    	// buffer에 len길이 만큼 난수 채우기, 반환값은 랜덤 바이트 길이
        perror("urandom read 실패");			// ssize_t : signed로 -1도 할당 받을 수 있는 타입
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}




// ------------------------------------------------------------
// 공통 유틸 함수: 임시 파일 경로 생성 + open
//  - 원본 파일과 동일한 퍼미션을 stat으로 가져오는 대신
//    FUSE 대응: 기본 권한 0644로 생성
//      O_WRONLY : write 모드만 허용
//      O_CREAT  : 파일이 없으면 새로 생성
//      O_TRUNC  : 파일이 이미 존재한다면 내용을 날리고 빈 파일로 만든다.
// ------------------------------------------------------------
int create_tmp_file(const char *filepath, char *tmp_path, int *tmp_fd)
{
    // 임시 파일 경로(temp_path) 생성 : 원본 뒤에 ".tmp" 붙이기
    // 원본을 바로 수정하면 중간에 오류가 나도 복구 불가능하기 때문에 임시파일 생성
    snprintf(tmp_path, PATH_MAX, "%s.tmp", filepath);

    // 기본 권한 0644 부여 및 ".tmp" 파일 생성 및 open (원본 파일의 권한을 가져오는 stat함수 회피)
    *tmp_fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);	// 0644의 의미 파악하기 (특수 비트, 0이면 특수권한 없는 것, 4이면 userid에 특수권한 부여 + 8진수의미)
    if (*tmp_fd == -1) {
        perror("임시 파일 open 실패");
        return -1;
    }
    return 0;
}


// ------------------------------------------------------------
// 공통 유틸 함수: tmp 파일을 원본 파일로 교체
//  - 암호화 모드로 동작하는 경우 : tmp = [IV + 암호문] 생성
//  - 복호화 모드로 동작하는 경우 : tmp = [복호화된 평문] 생성
//  - 임시 파일의 이름(tmp_path)을 원본 파일의 이름(filepath)으로 변경
//  - rename은 시스템콜, 원본 파일을 자동 삭제(unlink)
// ------------------------------------------------------------
int commit_tmp_file(const char *tmp_path, const char *filepath)
{
    if (rename(tmp_path, filepath) != 0) {
        perror("rename 실패");
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

