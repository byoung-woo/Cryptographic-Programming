#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "daemon.h"

void daemonize(const char *log_dir) {
    pid_t pid;

    // 1. 부모 프로세스 종료
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    // 2. 새로운 세션 생성 (터미널 분리)
    if (setsid() < 0) exit(EXIT_FAILURE);

    // 3. 자식 프로세스 재생성 (SIGHUP 방지)
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    // 4. 파일 권한 마스크 설정 및 작업 디렉토리 변경
    umask(0);
    // 로그 디렉토리 생성 시도
    mkdir(log_dir, 0755); 
    
    // 5. 표준 입출력 닫기 또는 리다이렉션
    int fd = open("/dev/null", O_RDWR);
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
}