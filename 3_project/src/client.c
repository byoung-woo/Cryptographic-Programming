#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <time.h>
#include "common.h"

// ... (main 함수 및 로직은 이전과 동일, encrypt_data 함수 포함) ...
// encrypt_data 함수는 crypto_utils.c에 있는 것을 복사해서 사용하거나 링크해서 사용.
// 여기서는 편의상 crypto_utils.c와 별개로 구현하거나 Makefile에서 같이 링크.

// (테스트 편의를 위해 여기에 encrypt_data 구현 포함)
int encrypt_data(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext) {
    // ... (crypto_utils.c 내용과 동일) ...
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;
    if(!(ctx = EVP_CIPHER_CTX_new())) return -1;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

void error_handling(char *msg) {
    fputs(msg, stderr); fputc('\n', stderr); exit(1);
}

int main(int argc, char *argv[]) {
    // ... (이전 client.c main 함수 내용 그대로) ...
    // 단, 포트 접속 시 직접 하드코딩 대신 argv로 받거나 #define 사용
    // 여기서는 간단히 9090 접속
    int sock;
    struct sockaddr_in serv_addr;
    char message[BUF_SIZE];
    LogHeader header;
    
    if (argc != 3) { printf("Usage: %s <IP> <ID>\n", argv[0]); exit(1); }
    
    sock = socket(PF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(9090); // config와 맞춰야 함

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
        error_handling("connect() error");

    // ... (전송 로직) ...
    // 이전 코드 복사 붙여넣기 하되 encrypt_data 호출 부분 확인
    while (1) {
        fputs("Log Input (Q to quit): ", stdout);
        fgets(message, BUF_SIZE, stdin);
        if (!strcmp(message, "q\n") || !strcmp(message, "Q\n")) break;
        message[strcspn(message, "\n")] = 0;

        RAND_bytes(header.iv, 16);
        unsigned char *ciphertext = (unsigned char*)malloc(strlen(message) + 16);
        int c_len = encrypt_data((unsigned char*)message, strlen(message), (unsigned char*)"0001020304050607", header.iv, ciphertext);

        // 해시 생성
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(mdctx, ciphertext, c_len);
        EVP_DigestFinal_ex(mdctx, header.hash, NULL);
        EVP_MD_CTX_free(mdctx);

        strcpy(header.client_id, argv[2]);
        header.timestamp = (uint64_t)time(NULL);
        header.data_len = c_len;

        write(sock, &header, sizeof(LogHeader));
        write(sock, ciphertext, c_len);
        free(ciphertext);
    }
    close(sock);
    return 0;
}