#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#define BUF_SIZE 4096
#define AES_BLOCK_SIZE 16

// 구조체 패킹 (1바이트 단위)
#pragma pack(push, 1)
typedef struct {
    char client_id[32];     // 클라이언트 ID
    uint64_t timestamp;     // 타임스탬프
    uint32_t data_len;      // 암호문 데이터 길이
    uint8_t iv[16];         // AES 초기화 벡터 (IV)
    uint8_t hash[32];       // SHA-256 무결성 해시
} LogHeader;
#pragma pack(pop)

// 설정 정보 구조체
typedef struct {
    int port;
    char log_dir[256];
    char psk[32];
    int max_queue_size;
} ServerConfig;

// 공유 자원 (암호화 함수 프로토타입)
int encrypt_data(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext);
int decrypt_data(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext);

#endif