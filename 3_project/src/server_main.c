#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // 추가
#include "config.h"
#include "daemon.h"
#include "server_core.h"

void sig_handler(int sig) {
    stop_server_core(); // running 플래그를 0으로 설정
}

int main(int argc, char *argv[]) {
    ServerConfig config;
    struct sigaction act; // sigaction 구조체 선언

    // 1. 설정 로드
    if (load_config("config/server.conf", &config) < 0) {
        fprintf(stderr, "Failed to load config/server.conf (Using defaults)\n");
    }

    printf("Starting Secure Log Server...\n");
    printf("Port: %d, LogDir: %s\n", config.port, config.log_dir);

    // 2. 데몬화
    if (argc > 1 && strcmp(argv[1], "-d") == 0) {
        printf("Running as daemon...\n");
        daemonize(config.log_dir);
    }

    // 3. 시그널 핸들러 등록 (핵심 수정 부분)
    act.sa_handler = sig_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0; // 중요: SA_RESTART 플래그를 뺌 (accept가 인터럽트 되도록 함)
    
    // SIGINT (Ctrl+C) 처리에 sigaction 사용
    sigaction(SIGINT, &act, 0);
    sigaction(SIGTERM, &act, 0);

    // 4. 서버 코어 시작
    start_server_core(&config);

    return 0;
}