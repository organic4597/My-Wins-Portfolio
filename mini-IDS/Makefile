CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -g -pthread -D_BSD_SOURCE -D_DEFAULT_SOURCE -I/usr/include/libnl3 -I/home/kali/snort3/src -I/usr/local/snort/include/snort
CXXFLAGS = -std=c++14 -fPIC -I/usr/local/snort/include/snort -I/home/kali/snort3/src
LDFLAGS = -lpcap -lpthread -lnl-3 -lnl-route-3

SRCS = main.c capture.c inject.c veth_manager.c alert_monitor.c
OBJS = $(SRCS:.c=.o)
TARGET = mini-ids
PLUGIN = session_stats.so
LEGACY_ALERT = print_alert_v2

all: $(TARGET) $(PLUGIN)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "[BUILD] 완료: $@"

$(PLUGIN): session_stats_inspector.cc
	$(CXX) $(CXXFLAGS) -shared -o $@ $<
	@echo "[BUILD] Snort3 플러그인 완료: $@"

# 레거시 독립 실행형 Alert Monitor (참고용)
$(LEGACY_ALERT): print_alert_v2.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[BUILD] 레거시 Alert Monitor 완료: $@"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) $(PLUGIN) $(LEGACY_ALERT) print_alert.o
	@echo "[CLEAN] 완료"

run: $(TARGET)
	@echo "[RUN] root 권한으로 실행 중..."
	sudo ./$(TARGET) eth0

.PHONY: all clean run
