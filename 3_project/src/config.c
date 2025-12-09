#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

// key=value 형태의 설정 파일 읽기
int load_config(const char *filename, ServerConfig *config) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;

    char line[256];
    char key[128], value[128];

    // 기본값 설정
    config->port = 9090;
    strcpy(config->log_dir, "./logs");
    strcpy(config->psk, "0001020304050607");
    config->max_queue_size = 100;

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || strlen(line) < 3) continue; // 주석이나 빈 줄 무시
        
        if (sscanf(line, "%[^=]=%s", key, value) == 2) {
            if (strcmp(key, "SERVER_PORT") == 0) config->port = atoi(value);
            else if (strcmp(key, "LOG_DIR") == 0) strcpy(config->log_dir, value);
            else if (strcmp(key, "PSK_KEY") == 0) strcpy(config->psk, value);
            else if (strcmp(key, "MAX_QUEUE_SIZE") == 0) config->max_queue_size = atoi(value);
        }
    }
    
    fclose(fp);
    return 0;
}