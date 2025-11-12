CC = gcc
CFLAGS = -Wall -Wextra -g -pthread -D_BSD_SOURCE -D_DEFAULT_SOURCE -I/usr/include/libnl3
LDFLAGS = -lpcap -lpthread -lnl-3 -lnl-route-3

SRCS = main.c capture.c inject.c veth_manager.c print_alert.c
OBJS = $(SRCS:.c=.o)
TARGET = mini-ids

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "[BUILD] 완료: $@"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) veth_manager.o
	@echo "[CLEAN] 완료"

run: $(TARGET)
	@echo "[RUN] root 권한으로 실행 중..."
	sudo ./$(TARGET) eth0

.PHONY: all clean run
