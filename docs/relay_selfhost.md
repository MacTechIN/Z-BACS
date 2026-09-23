# Relay 셀프호스팅 가이드 (Z-1.R.4)

| 문서 버전 | 1.0 (2026-09-23) |
|---|---|
| 근거 | [specs/relay_protocol.md](specs/relay_protocol.md) §6~§8, [beta_test_automation.md](beta_test_automation.md) L2 |
| 대상 | 베타를 위해 Relay 한 대를 띄우는 사람(우리), 나중에 자체 Relay를 두려는 조직 |

## 0. Relay가 무엇이고 무엇이 아닌가

Relay는 두 Agent가 서로 직접 닿을 수 없을 때 **서명된 봉투를 잠시 맡아 두는 우체통**이다. 요청·허락·회수 메시지를 기기별 받은편지함에 최대 24시간 보관하고, 꺼내 가면 지운다.

Relay가 **가지지 않는 것**: 파일, 파일 키, 개인정보, 계정. 봉투 안은 열 수 없고(HPKE, T04), 발신자 서명은 Agent가 직접 확인한다(T05). 그래서 **설정 파일도 비밀도 볼륨도 없다** — 재시작하면 큐가 비고, 그게 전부다. Relay가 악의적이어도 할 수 있는 최악은 "배달을 안 하는 것"이며, Agent는 여러 Relay를 순서대로 시도한다(T21).

## 1. 빠른 시작 (Docker)

요구사항: Docker 24+ 와 Docker Compose v2.

```
git clone https://github.com/MacTechIN/Z-BACS && cd Z-BACS
docker compose up -d
curl http://localhost:8787/v1/health      # {"ok":true} 이면 끝
```

- 이미지는 저장소에서 빌드된다(`apps/relay/Dockerfile`, 멀티스테이지, 실행 이미지는 debian-slim + 바이너리 하나, 비특권 사용자, 읽기 전용 파일시스템).
- 포트 8787. 바꾸려면 `docker-compose.yml`의 `ports`만 고친다.
- 로그: `docker compose logs -f relay`. 종료: `docker compose down`.
- 업그레이드: `git pull && docker compose up -d --build`. 큐는 메모리에만 있으므로 재시작 시 대기 중이던 요청은 사라진다 — 요청한 쪽 Agent가 5분 뒤 "답이 없어요"로 알리고 다시 물어볼 수 있다.

Docker 없이: `cargo run -p zbacs-relay -- --bind 0.0.0.0:8787` (Rust만 있으면 된다).

## 2. 인터넷에 내놓을 때: TLS

LAN 밖이라면 반드시 HTTPS 뒤에 둔다. Relay 자체는 평문 HTTP만 하며, TLS는 리버스 프록시의 일이다. Caddy가 가장 짧다(인증서 자동):

```
# Caddyfile
relay.example.com {
    reverse_proxy zbacs-relay:8787
}
```

`docker-compose.yml`에 Caddy 서비스를 하나 더 붙이면 된다(80/443 공개, relay는 내부 네트워크만). 봉투는 이미 서명·암호화되어 있으므로 TLS는 **메타데이터**(누가 누구에게, 언제)를 가리는 용도다(T13, relay_protocol §7).

## 3. Agent 연결

Agent에는 사용자 설정이 없다. 배포본은 Relay 주소를 **내장**한다(Z-1.H.11에서 호스팅된 주소로 교체). 그 전까지, 그리고 개발·자체 호스팅에서는 환경변수로 준다:

```
ZBACS_RELAY_URL=https://relay.example.com,https://relay2.example.com   # 쉼표로 여러 개, 순서대로 시도
```

## 4. 운영 값

| 항목 | 값 | 어디서 |
|---|---|---|
| 큐 보관 | 24시간 | `apps/relay/src/state.rs` `QUEUE_TTL` |
| 기기별 할당량 | 분·시간 단위 (relay_protocol §6) | `state.rs` 상수 |
| 봉투 최대 크기 | 64 KiB | `zbacs-proto` `MAX_BODY_LEN` |
| 시계 오차 허용 | 120초 | `MAX_SKEW_SECS` — 서버 시계를 NTP로 맞출 것 |
| 처리량 | 100 req/s 이상 (CI perf 게이트) | `apps/relay/tests` `perf_*` |
| 메모리 | 기본 수십 MB; 큐는 기기 수 × 메시지 수에 비례 | — |

값을 바꾸려면 상수를 고쳐 다시 빌드한다 — 설정 파일을 두지 않는 것은 의도다(§0).

## 5. 무료로 한 대 띄우기 (베타용)

| 곳 | 방법 | 메모 |
|---|---|---|
| Fly.io | `fly launch --dockerfile apps/relay/Dockerfile`, 256 MB 머신 1대 | HTTPS 자동, 가장 간단. 무료 한도 확인 필요 |
| Oracle Cloud Always Free | ARM VM 1대에 Docker + Caddy | 영구 무료지만 손이 더 간다 |
| Render / Railway | 저장소 연결 후 Dockerfile 경로 지정 | 무료 티어는 유휴 시 잠들 수 있음 → 첫 요청 지연 |
| 집/사무실 PC | `docker compose up -d` + Cloudflare Tunnel | 고정 IP 불필요 |

어느 쪽이든 결과는 URL 하나이고, 그 URL을 Z-1.H.11에서 Agent에 내장한다. 계정 만들기는 사용자만 할 수 있다(beta_test_automation §5).

## 6. 확인 목록

```
curl -fsS https://relay.example.com/v1/health                      # 살아 있나
docker compose ps                                                   # healthy 인가
ZBACS_RELAY_URL=https://relay.example.com cargo test -p zbacs-relay-client   # 클라이언트가 붙나 (선택)
```
