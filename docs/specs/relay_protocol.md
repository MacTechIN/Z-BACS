# 스펙: Relay 프로토콜 v1 (Z-1.R.1)

| 상태 | Draft 1.0 (2026-09-19) |
|---|---|
| 구현 | `crates/zbacs-proto`(메시지 타입·서명), `apps/relay`(axum 서버, Z-1.R.2), `crates/zbacs-relay-client`(Z-1.R.5) |
| 전제 | Relay는 **무신뢰**다. 평문·DEK·개인키를 절대 보지 못하고, 검열·지연은 할 수 있다(T16, T21). 보안은 서명과 HPKE 봉투에서 나오고 Relay는 배달만 한다. |

## 1. 역할과 전송

| 역할 | 하는 일 |
|---|---|
| 수신자 Agent (Bob) | 열람 요청 전송, 승인 대기, `GrantMsg` 수신 |
| 소유자 Agent / 승인 앱 (Alice) | 대기 중 요청 수신, 승인·거부 전송, 회수 전송 |
| Relay | 서명 검증 → 큐 적재 → 상대에게 전달. 저장은 짧게, 내용은 불투명 |

- 전송: **HTTPS 1.1/2** (요청·응답) + **WebSocket** (푸시). 본문은 전부 **CBOR**(RFC 8949), `Content-Type: application/cbor`.
- 모든 요청·응답은 §3의 `Signed<T>` 봉투에 담긴다. 서명 없는 본문은 거부(`unauthenticated`).
- 시간: 모든 `ts`는 Unix 초(UTC). Relay는 `|now - ts| > 120s`를 거부(`stale`).

## 2. 엔드포인트

| 메서드 | 경로 | 본문 | 설명 |
|---|---|---|---|
| POST | `/v1/devices` | `Signed<DeviceAnnounce>` | 기기 공개키 등록/갱신. 같은 `kid` 재등록은 멱등 |
| POST | `/v1/requests` | `Signed<AccessRequest>` | Bob → 소유자 큐에 요청 적재 |
| POST | `/v1/grants` | `Signed<GrantMsg>` | Alice → 요청자에게 승인/거부 전달 |
| POST | `/v1/revocations` | `Signed<Revoke>` | Alice → 활성 세션에 회수 브로드캐스트 |
| GET | `/v1/inbox?since=<cursor>` | — | 폴링 수신(WebSocket 불가 환경 폴백) |
| GET | `/v1/stream` | WebSocket | 실시간 수신. 첫 프레임은 `Signed<Subscribe>` |
| GET | `/v1/health` | — | 상태 확인(서명 불필요) |

응답은 `Signed<Ack>` 또는 `Signed<Envelope[]>`(수신함). Relay의 서명 키는 `/v1/health`가 공개한다 — **Relay 서명은 배달 증거일 뿐 권한 근거가 아니다.**

## 3. 서명 봉투

```
Signed<T> {
  payload: bstr          // CBOR(T)
  kid:     bstr(16)      // 서명자 기기 키 id = SHA-256(ed25519_pub)[..16]
  ts:      uint          // Unix 초
  nonce:   bstr(16)      // 재전송 방지 (Relay가 5분간 기억)
  sig:     bstr(64)      // Ed25519("ZBACS-RLY-v1" ‖ kind ‖ ts ‖ nonce ‖ SHA-256(payload))
}
```
- `kind`는 메시지 종류 문자열(`"req"`, `"grant"`, `"revoke"`, `"announce"`, `"sub"`, `"ack"`)이며 서명 대상에 포함된다 — 한 메시지의 서명을 다른 종류로 재사용할 수 없다.
- Relay는 `kid`에 등록된 공개키로 검증한다. 미등록 `kid`는 `unknown_device`.
- **Relay는 `payload` 내용을 해석하지 않아도 배달할 수 있어야 한다.** 라우팅에 필요한 필드만 읽는다.

## 4. 메시지

### 4.1 DeviceAnnounce
```
DeviceAnnounce { x25519_pub: bstr(32), ed25519_pub: bstr(32), label: tstr(≤32)?, ts: uint }
```
`label`은 사용자에게 보일 기기 이름(예: "업무용 노트북"). Relay는 이를 저장하지만 소유자에게 전달할 때는 Phase 2에서 암호화한다(§7).

### 4.2 AccessRequest (Bob → Alice)
```
AccessRequest {
  fid:         bstr(32)      // 컨테이너의 FileId
  header_hash: bstr(32)      // 요청 대상 버전 (T19: 승인은 이 버전에 묶인다)
  owner:       bstr          // 소유자 계정 식별자 (컨테이너 헤더의 own)
  device_kid:  bstr(16)
  x25519_pub:  bstr(32)      // DEK 봉투 수신용
  requested:   uint          // 1 ReadOnly | 2 Edit
  nonce:       bstr(16)      // 요청 nonce, 승인 티켓에 그대로 들어간다
  hint:        bstr?         // 소유자 공개키로 암호화된 표시용 힌트(§7)
  ts:          uint
}
```
Relay는 `owner`로 큐를 고르고 나머지는 불투명하게 다룬다.

### 4.3 GrantMsg (Alice → Bob)
```
GrantMsg {
  request_nonce: bstr(16)   // 어느 요청에 대한 응답인지
  grant:    AccessGrant?    // approval_protocol §1.2 (permission == Deny 이면 생략 가능)
  owner_sig: bstr?          // OwnerSig (WebAuthn 또는 P256Raw, §1.5)
  envelope:  Envelope?      // HPKE(DEK → 요청자 x25519_pub), Deny면 없음
  tx_hash:   bstr(32)?      // 온체인 grant 트랜잭션(있으면)
  decision:  uint           // 0 Deny | 1 ReadOnly | 2 Edit
  ts:        uint
}
```

`grant`의 CBOR 형태(구현: `zbacs_proto::AccessGrantTerms`, 2026-09-21): EIP-712 `AccessGrant` 필드를 구조체 순서대로 snake_case 키로 담는다 — `file_id`, `header_hash`, `device_key_hash`, `permission`, `not_before`, `expiry`, `max_opens`, `request_nonce`, `grant_nonce`(순차 값이라 u64). `device_key_hash = keccak256(device_x25519_pub ‖ device_ed25519_pub)`.

수신자 검사 순서(Z-1.G.9, approval_protocol §2 규칙 1~3): `request_nonce`가 자기 것이 아니면 무시(다른 요청의 답), 자기 것인데 `file_id`·`header_hash`·`device_key_hash`·`permission`이 요청과 다르면 **거부하고 사용자에게 알린다**(바꿔치기, T05/T19). `owner_sig` 검증은 소유자 승인 키를 체인에서 읽는 Z-1.H.8/H.10 이후.

### 4.4 Revoke
```
Revoke { grant_id: bstr(32), fid: bstr(32), ts: uint }
```
수신자 Agent는 이를 받으면 즉시 세션을 종료한다. 받지 못해도 TTL과 주기적 `isValid()` 확인으로 닫힌다(T20).

### 4.5 Subscribe / Ack / Envelope
```
Subscribe { since: bstr?, kinds: [tstr] }        // WebSocket 첫 프레임
Ack       { ok: bool, id: bstr(16)?, error: Error? }
Envelope  { id: bstr(16), kind: tstr, body: bstr /* Signed<T> 원문 */, queued_at: uint }
```
`Envelope.body`는 **원본 서명 메시지 그대로**다. 수신 측은 Relay를 믿지 않고 자기가 다시 검증한다.

## 5. 오류

| 코드 | HTTP | 의미 |
|---|---|---|
| `unauthenticated` | 401 | 서명 없음/검증 실패 |
| `unknown_device` | 401 | `kid` 미등록 |
| `stale` | 400 | `ts` 허용 범위 밖 |
| `replayed` | 409 | `nonce` 재사용 |
| `malformed` | 400 | CBOR 파싱 실패, 필드 길이 위반 |
| `too_large` | 413 | 본문 상한(64 KiB) 초과 |
| `rate_limited` | 429 | 할당량 초과. `Retry-After` 포함 |
| `not_found` | 404 | 커서·메시지 없음 |
| `internal` | 500 | 서버 오류 |

## 6. 수명·할당량 (T16)

| 항목 | 값 |
|---|---|
| 본문 상한 | 64 KiB (봉투·서명 포함) |
| 큐 보관 | 24시간 또는 수신 확인 시까지 |
| nonce 기억 | 5분 |
| 기기당 요청 | 30/분, 300/시간 |
| IP당 연결 | 20 동시, 60 신규/분 |
| WebSocket 유휴 | 60초 ping, 180초 무응답 시 종료 |

초과는 `rate_limited`. Relay 장애·검열 시 Agent는 (1) 다른 Relay 엔드포인트, (2) 체인 이벤트 폴백(`Granted`/`Revoked` 구독), (3) 사용자에게 "지금은 연결이 어렵다"는 안내 순으로 대응한다(T16, T21).

## 7. 프라이버시

- Relay가 보는 것: `owner` 큐 키, `kid`, 메시지 크기·시각, 암호문. **보지 못하는 것**: 파일 내용, 파일명, DEK, 정책, 힌트 평문(Phase 2 암호화 후).
- `hint`(요청자 이름·기기명)는 v1에서 평문 허용, **Phase 2(Z-2.R.1)에서 소유자 공개키로 HPKE 암호화**한다. 그때까지 UI는 힌트를 "신뢰할 수 없는 표시값"으로 다룬다.
- Relay는 로그에 `kid`·`fid`를 남기지 않는다(해시 접두 8바이트까지만).

## 8. 셀프호스팅

Relay는 단일 바이너리 + Docker 이미지로 배포한다(Z-1.R.4). 기업은 자체 Relay를 띄워 §6 할당량과 보관 기간을 조정할 수 있고, 프로토콜은 동일하다. Agent는 `--relay <url>`로 복수 엔드포인트를 받고 순서대로 시도한다.
