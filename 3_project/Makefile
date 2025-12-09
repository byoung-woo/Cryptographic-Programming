CC = gcc
CFLAGS = -Wall -I./include
LIBS = -lssl -lcrypto -lpthread

# 소스 및 오브젝트 정의
SRCS_SERVER = src/server_main.c src/server_core.c src/config.c src/daemon.c src/crypto_utils.c
OBJS_SERVER = $(SRCS_SERVER:src/%.c=obj/%.o)

SRCS_CLIENT = src/client.c
OBJS_CLIENT = $(SRCS_CLIENT:src/%.c=obj/%.o)

# 타겟 정의
all: directories server client

# 실행 파일 생성
server: $(OBJS_SERVER)
	$(CC) $(CFLAGS) -o server $(OBJS_SERVER) $(LIBS)

client: $(OBJS_CLIENT)
	$(CC) $(CFLAGS) -o client $(OBJS_CLIENT) $(LIBS)

# 오브젝트 파일 컴파일
obj/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# 디렉토리 생성
directories:
	@mkdir -p obj logs

clean:
	rm -rf obj server client logs/*.log

rebuild: clean all