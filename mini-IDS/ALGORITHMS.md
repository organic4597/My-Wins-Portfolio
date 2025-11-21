# Mini-IDS 사용 알고리즘 문서

## 📋 개요

이 문서는 Mini-IDS 프로젝트에서 사용된 주요 알고리즘과 데이터 구조를 설명합니다.

---

## 1. 해시 테이블 (Hash Table)

### 위치
- **파일**: `session_stats_inspector.cc`
- **구현**: `std::unordered_map<SessionKey, SessionStats>`

### 용도
- 세션 통계를 O(1) 평균 시간 복잡도로 저장 및 조회
- 각 세션(IP 주소, 포트, 프로토콜 조합)을 키로 사용하여 패킷 수와 바이트 수를 누적

### 시간 복잡도
- **삽입**: O(1) 평균, O(n) 최악
- **조회**: O(1) 평균, O(n) 최악
- **공간 복잡도**: O(n) (n = 세션 수)

### 코드 예시
```cpp
std::unordered_map<SessionKey, SessionStats> session_map;
auto& stats = session_map[key];  // O(1) 조회/삽입
stats.packet_count++;
stats.byte_count += p->pktlen;
```

---

## 2. 커스텀 해시 함수 (Custom Hash Function)

### 위치
- **파일**: `session_stats_inspector.cc` (lines 39-55)
- **알고리즘**: XOR 기반 해시 조합

### 알고리즘 설명
- **방법**: 각 필드(src_ip, dst_ip, src_port, dst_port, protocol)의 해시값을 XOR 연산으로 결합
- **상수**: `0x9e3779b97f4a7c15ULL` (골든 비율 기반 상수)
- **비트 시프트**: `(h<<6) + (h>>2)` - 해시 충돌 감소를 위한 비트 회전

### 시간 복잡도
- **계산**: O(1) - 고정된 필드 수에 대해 상수 시간

### 코드 예시
```cpp
struct hash<SessionKey> {
    size_t operator()(const SessionKey& k) const {
        size_t h = 0;
        h ^= hs(k.src_ip) + 0x9e3779b97f4a7c15ULL + (h<<6) + (h>>2);
        h ^= hs(k.dst_ip) + 0x9e3779b97f4a7c15ULL + (h<<6) + (h>>2);
        // ... (포트, 프로토콜도 동일하게)
        return h;
    }
};
```

---

## 3. 퀵소트 (Quicksort)

### 위치
- **파일**: `alert_monitor.c` (line 316)
- **함수**: `qsort()`

### 용도
- 위협 스코어를 기준으로 세션을 내림차순 정렬
- Top N 위협을 빠르게 추출하기 위해 사용

### 시간 복잡도
- **평균**: O(n log n)
- **최악**: O(n²) - 이미 정렬된 경우
- **공간**: O(log n) - 재귀 스택

### 비교 함수
```c
static int compare_score(const void *a, const void *b) {
    const combined_entry_t *ea = (const combined_entry_t *)a;
    const combined_entry_t *eb = (const combined_entry_t *)b;
    
    if (eb->score > ea->score) return 1;  // 내림차순
    if (eb->score < ea->score) return -1;
    return 0;
}
```

---

## 4. 선형 검색 (Linear Search)

### 위치
- **파일**: `alert_monitor.c` (lines 250-268, 288-306)

### 용도
1. **중복 세션 병합**: 세션 로그를 읽으면서 동일한 세션이 이미 배열에 있는지 확인
2. **Alert 매칭**: Alert 로그의 IP 주소와 프로토콜을 세션 배열에서 검색하여 매칭

### 시간 복잡도
- **평균**: O(n) - n은 현재 세션 수
- **최악**: O(n) - 모든 요소를 확인해야 함

### 코드 예시
```c
// 중복 세션 확인
int found = -1;
for (int i = 0; i < count; i++) {
    if (strcmp(entries[i].src_ip, temp.src_ip) == 0 &&
        entries[i].src_port == temp.src_port &&
        strcmp(entries[i].dst_ip, temp.dst_ip) == 0 &&
        entries[i].dst_port == temp.dst_port &&
        entries[i].protocol == temp.protocol) {
        found = i;
        break;
    }
}
```

---

## 5. 문자열 파싱 알고리즘

### 위치
- **파일**: `alert_monitor.c` (parse_session_log, parse_alert_log)

### 사용 함수
- **`strtok_r()`**: 토큰 분리 (세션 로그 파싱)
- **`strstr()`**: 부분 문자열 검색 (Alert 메시지, 프로토콜 추출)
- **`strchr()` / `strrchr()`**: 문자 검색 (IP:Port 분리, IPv6 처리)

### 알고리즘
1. **세션 로그 파싱**: `|` 구분자로 토큰 분리
2. **Alert 로그 파싱**: 정규표현식 대신 문자열 검색으로 IP, 포트, 프로토콜 추출
3. **IPv6 처리**: 마지막 `:`를 찾아 포트와 IP 주소 분리

### 시간 복잡도
- **strtok_r**: O(n) - n은 문자열 길이
- **strstr**: O(n*m) - n은 검색 대상, m은 패턴 길이
- **strrchr**: O(n) - 문자열 끝에서부터 검색

### 코드 예시
```c
// IPv6 주소에서 포트 분리
char *last_colon = strrchr(src_full, ':');
if (last_colon && strchr(last_colon + 1, ':') == NULL) {
    *last_colon = '\0';  // 포트 제거
}
```

---

## 6. 카운팅 알고리즘 (Counting Algorithm)

### 위치
- **파일**: `session_stats_inspector.cc` (lines 204-208)
- **함수**: `std::count_if()`

### 용도
- 세션 맵에서 프로토콜별(ICMP, UDP, TCP) 세션 수를 카운트

### 시간 복잡도
- **O(n)** - n은 세션 맵의 크기

### 코드 예시
```cpp
int icmp_count = std::count_if(session_map.begin(), session_map.end(), 
                               [](const auto& p) { 
                                   return p.first.protocol == 1 || 
                                          p.first.protocol == 58; 
                               });
```

---

## 7. 병합 알고리즘 (Merge Algorithm)

### 위치
- **파일**: `alert_monitor.c` (print_top_threats 함수)

### 용도
- 세션 통계 로그와 Alert 로그를 결합하여 통합 위협 정보 생성

### 알고리즘
1. 세션 로그를 읽어 배열에 저장 (중복 병합 포함)
2. Alert 로그를 읽어 각 Alert를 해당 세션에 매칭
3. 매칭된 세션에 Alert 정보 추가

### 시간 복잡도
- **세션 로드**: O(n) - n은 세션 로그 라인 수
- **Alert 매칭**: O(n*m) - n은 세션 수, m은 Alert 수
- **전체**: O(n*m) - 최악의 경우

### 최적화 가능성
- Alert 매칭을 해시 테이블로 변경하면 O(n+m)으로 개선 가능

---

## 8. 메모리 복사 알고리즘

### 위치
- **파일**: `capture.c`, `inject.c`
- **함수**: `memcpy()`, `memset()`

### 용도
- 패킷 데이터 복사 (UDS 전송용)
- MAC 주소 재작성
- 구조체 초기화

### 시간 복잡도
- **O(n)** - n은 복사할 바이트 수

### 코드 예시
```c
// 패킷 데이터 복사
memcpy(uds_pkt.packet_data, packet, pkthdr->caplen);

// MAC 주소 재작성
memcpy((void *)uds_pkt->packet_data, veth1_mac, 6);
memcpy((void *)(uds_pkt->packet_data + 6), veth0_mac, 6);
```

---

## 9. 스코어 계산 알고리즘

### 위치
- **파일**: `alert_monitor.c` (calculate_score 함수)

### 알고리즘
- **가중 합계 (Weighted Sum)**: 여러 요소에 가중치를 부여하여 점수 계산

### 공식
```
score = 0
if (has_alert):
    score += 1000
    if (protocol == ICMP/ICMPv6):
        score += 500
if (protocol == ICMP/ICMPv6):
    score += 500
else if (protocol == UDP):
    score += 200
score += packets * 10
score += bytes / 1024
```

### 시간 복잡도
- **O(1)** - 상수 시간 계산

---

## 10. 데이터 구조 요약

| 데이터 구조 | 위치 | 용도 | 시간 복잡도 |
|------------|------|------|------------|
| `std::unordered_map` | `session_stats_inspector.cc` | 세션 통계 저장 | O(1) 평균 |
| 배열 (`combined_entry_t[]`) | `alert_monitor.c` | 세션 목록 저장 | O(1) 접근 |
| 구조체 (`uds_packet_t`) | `common.h` | 패킷 데이터 전송 | O(1) |
| 연결 리스트 (내부) | `std::unordered_map` | 해시 충돌 처리 | O(k) k=충돌 수 |

---

## 알고리즘 선택 이유

### 1. 해시 테이블 선택 이유
- **빠른 조회**: 패킷 처리 시 세션 통계를 빠르게 업데이트해야 함
- **동적 크기**: 세션 수를 미리 알 수 없음

### 2. 퀵소트 선택 이유
- **표준 라이브러리**: `qsort()`는 C 표준 라이브러리로 안정적
- **충분한 성능**: Top 10만 필요하므로 O(n log n)으로 충분

### 3. 선형 검색 선택 이유
- **단순성**: 세션 수가 많지 않을 것으로 예상
- **구현 용이**: 복잡한 데이터 구조 없이 배열로 충분

### 4. 문자열 파싱 선택 이유
- **정규표현식 대신**: C 언어 환경에서 간단한 문자열 함수 사용
- **성능**: 정규표현식보다 빠름

---

## 성능 최적화 가능 영역

1. **Alert 매칭**: 선형 검색 → 해시 테이블 (O(n*m) → O(n+m))
2. **중복 세션 병합**: 선형 검색 → 해시 테이블 (O(n²) → O(n))
3. **부분 정렬**: 전체 정렬 대신 Top N만 선택 (O(n log n) → O(n log k))

---

## 참고 자료

- [Hash Table - Wikipedia](https://en.wikipedia.org/wiki/Hash_table)
- [Quicksort - Wikipedia](https://en.wikipedia.org/wiki/Quicksort)
- [Linear Search - Wikipedia](https://en.wikipedia.org/wiki/Linear_search)
- [C++ std::unordered_map](https://en.cppreference.com/w/cpp/container/unordered_map)

