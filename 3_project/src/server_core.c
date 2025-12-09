#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <time.h>
#include "server_core.h"

// [수정 1] 쓰레드에게 소켓과 IP를 같이 넘기기 위한 구조체
typedef struct {
    int socket;
    char ip_addr[INET_ADDRSTRLEN]; // IPv4 주소 문자열 (예: "192.168.0.1")
} ClientInfo;

// [수정 2] 로그 큐에도 실제 IP를 저장할 필드 추가
typedef struct {
    char client_ip[INET_ADDRSTRLEN]; // 실제 IP
    char client_id[32];              // 클라이언트가 주장하는 ID
    uint64_t timestamp;
    char *message;
} LogEntry;

static LogEntry *log_queue;
static int q_front = 0, q_rear = 0, q_count = 0;
static int q_size_limit = 0;

static pthread_mutex_t q_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t q_not_empty = PTHREAD_COND_INITIALIZER;
static pthread_cond_t q_not_full = PTHREAD_COND_INITIALIZER;

volatile int server_running = 1;
static char current_psk[32];
static char current_log_dir[256];

void rotate_log_file(const char *filename);
void *client_handler(void *arg);
void *logger_thread(void *arg);

void start_server_core(ServerConfig *config) {
    int serv_sock, clnt_sock;
    struct sockaddr_in serv_adr, clnt_adr;
    socklen_t clnt_adr_sz;
    pthread_t t_id, logger_tid;

    strcpy(current_psk, config->psk);
    strcpy(current_log_dir, config->log_dir);
    q_size_limit = config->max_queue_size;

    log_queue = (LogEntry*)malloc(sizeof(LogEntry) * q_size_limit);

    pthread_create(&logger_tid, NULL, logger_thread, NULL);

    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_adr.sin_port = htons(config->port);

    if (bind(serv_sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr)) == -1) {
        perror("bind() error"); exit(1);
    }
    if (listen(serv_sock, 5) == -1) {
        perror("listen() error"); exit(1);
    }

    while (server_running) {
        clnt_adr_sz = sizeof(clnt_adr);
        clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_adr, &clnt_adr_sz);
        
        if (clnt_sock == -1) {
            if (server_running) continue;
            else break;
        }

        // [수정 3] 접속한 클라이언트의 IP 추출 및 구조체 생성
        ClientInfo *info = (ClientInfo*)malloc(sizeof(ClientInfo));
        info->socket = clnt_sock;
        // inet_ntoa는 스레드 안전하지 않을 수 있으므로 복사해서 사용하거나 inet_ntop 권장
        // 여기서는 편의상 inet_ntoa 결과를 즉시 복사
        strncpy(info->ip_addr, inet_ntoa(clnt_adr.sin_addr), INET_ADDRSTRLEN);

        pthread_create(&t_id, NULL, client_handler, (void*)info);
        pthread_detach(t_id);
    }

    pthread_join(logger_tid, NULL);
    close(serv_sock);
    free(log_queue);
}

void stop_server_core() {
    server_running = 0;
    pthread_cond_broadcast(&q_not_empty);
    pthread_cond_broadcast(&q_not_full);
}

void *client_handler(void *arg) {
    // [수정 4] 인자를 구조체로 받아서 IP와 소켓 분리
    ClientInfo *info = (ClientInfo*)arg;
    int sock = info->socket;
    char my_ip[INET_ADDRSTRLEN];
    strcpy(my_ip, info->ip_addr);
    free(info); // 인자 메모리 해제

    LogHeader header;
    unsigned char *ciphertext = NULL;
    unsigned char *plaintext = NULL;
    int read_len;
    unsigned char hash[32];

    while (server_running) {
        int total_read = 0;
        char *ptr = (char*)&header;
        
        // 헤더 읽기
        while(total_read < sizeof(LogHeader)) {
            read_len = read(sock, ptr + total_read, sizeof(LogHeader) - total_read);
            if (read_len <= 0) goto DISCONNECT;
            total_read += read_len;
        }

        // 바디(암호문) 읽기
        ciphertext = (unsigned char*)malloc(header.data_len);
        total_read = 0;
        while(total_read < header.data_len) {
            read_len = read(sock, ciphertext + total_read, header.data_len - total_read);
            if (read_len <= 0) { free(ciphertext); goto DISCONNECT; }
            total_read += read_len;
        }

        // 해시 검증
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(mdctx, ciphertext, header.data_len);
        EVP_DigestFinal_ex(mdctx, hash, NULL);
        EVP_MD_CTX_free(mdctx);

        if (memcmp(hash, header.hash, 32) != 0) {
            free(ciphertext);
            continue; // 해시 불일치 시 저장 안 함
        }

        // 복호화
        plaintext = (unsigned char*)malloc(header.data_len + AES_BLOCK_SIZE);
        int p_len = decrypt_data(ciphertext, header.data_len, (unsigned char*)current_psk, header.iv, plaintext);
        plaintext[p_len] = '\0';
        free(ciphertext);

        // 큐 삽입 (Critical Section)
        pthread_mutex_lock(&q_mutex);
        while (q_count == q_size_limit && server_running) {
            pthread_cond_wait(&q_not_full, &q_mutex);
        }

        if (!server_running) {
            pthread_mutex_unlock(&q_mutex);
            free(plaintext);
            break;
        }

        log_queue[q_rear].timestamp = header.timestamp;
        strcpy(log_queue[q_rear].client_id, header.client_id);
        
        // [수정 5] 큐에 IP 정보도 함께 저장
        strcpy(log_queue[q_rear].client_ip, my_ip);
        
        log_queue[q_rear].message = (char*)plaintext;
        
        q_rear = (q_rear + 1) % q_size_limit;
        q_count++;
        
        pthread_cond_signal(&q_not_empty);
        pthread_mutex_unlock(&q_mutex);
    }

DISCONNECT:
    close(sock);
    return NULL;
}

void *logger_thread(void *arg) {
    char filepath[512];
    sprintf(filepath, "%s/server.log", current_log_dir);
    
    while (1) {
        pthread_mutex_lock(&q_mutex);
        while (q_count == 0) {
            if (!server_running) {
                pthread_mutex_unlock(&q_mutex);
                return NULL;
            }
            pthread_cond_wait(&q_not_empty, &q_mutex);
        }

        LogEntry entry = log_queue[q_front];
        q_front = (q_front + 1) % q_size_limit;
        q_count--;
        
        pthread_cond_signal(&q_not_full);
        pthread_mutex_unlock(&q_mutex);

        rotate_log_file(filepath);
        FILE *fp = fopen(filepath, "a");
        if (fp) {
            time_t t = (time_t)entry.timestamp;
            char time_str[64];
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&t));
            
            // [수정 6] 파일 포맷 변경: [시간] [IP] [ID]: 메시지
            fprintf(fp, "[%s] [%s] %s: %s\n", 
                    time_str, entry.client_ip, entry.client_id, entry.message);
            
            fclose(fp);
        }
        free(entry.message);
    }
}

void rotate_log_file(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0 && st.st_size > (5 * 1024 * 1024)) {
        char new_name[512];
        sprintf(new_name, "%s.old", filename);
        rename(filename, new_name);
    }
}