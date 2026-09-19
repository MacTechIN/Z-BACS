# 스펙: `.zbacs` 컨테이너 포맷 v1

| 상태 | Draft 1.1 (2026-09-19, PoC 반영) |
|---|---|
| 구현 | `crates/zbacs-core/src/container/` |

## 1. 설계 목표
- 스트리밍 암·복호화(대용량), 부분 손상 탐지, 다중 수신자 봉투, 버전 체인, 헤더 서명, 전방 호환.

## 2. 전체 레이아웃

```
+----------------+----------------------+----------------------+--------------------------------+
| Magic+Version  | Header (CBOR, signed)| Chunk 0 … Chunk N    | Trailer (72 B)                 |
| 8 bytes        | LE u32 len + bytes   | AEAD frames          | hdr_hash(32) chunks(u64) b3(32)|
+----------------+----------------------+----------------------+--------------------------------+
```

### 2.1 Magic / Version
- `magic = b"ZBACS\x00"` (6B) + `major(u8)=1` + `minor(u8)=0`.

### 2.2 Header (CBOR, RFC 8949)
```
{
  "fid":   bstr(32)      // FileId = SHA-256(plaintext_hash || salt)
  "salt":  bstr(16)
  "ver":   uint          // 버전 번호 (1부터)
  "prev":  bstr(32)|null // 이전 버전 헤더 해시
  "own":   bstr          // 소유자 계정 식별자 (chainId || address)
  "pol":   { "def": 0|1|2, "ttl": uint, "max": uint, "pin": bool, "strict": bool }
  "cipher": 1            // 1 = XChaCha20-Poly1305 chunked
  "chunk": 65536
  "plen":  uint          // 평문 길이
  "np":    bstr(16)      // 청크 nonce prefix (§2.3)
  "name":  bstr          // AEAD로 암호화된 원본 파일명 (DEK 사용, AAD="name")
  "env":   [ { "kid": bstr(16), "alg": "hpke-x25519-chacha", "enc": bstr, "ct": bstr } ]
  "sigk":  bstr(32)      // Ed25519 서명 공개키 (소유자 컨테이너 서명키)
  "sig":   bstr(64)      // Ed25519 over ("ZBACS-HDR-v1" || CBOR(header without sig))
}
```
- `env`에는 최소 소유자 자기 봉투 1개. 승인 시 Bob의 봉투는 **컨테이너에 쓰지 않고** GrantMsg로 전달(파일 재배포 시 봉투 누적 방지).

**필드 제한 (파서가 강제, Z-1.C.2)** — 위반 시 `HeaderDecode`로 거부하고 어떤 청크도 복호화하지 않는다.

| 필드 | 제한 |
|---|---|
| `fid`, `salt`, `np`, `prev`, `sigk`, `sig` | 정확히 32 / 16 / 16 / 32 / 32 / 64 바이트 |
| `ver` | ≥ 1. `ver == 1` ⇔ `prev == null` |
| `own` | 1..=64 바이트 |
| `pol.def` | 0, 1, 2 |
| `cipher` | 1 |
| `chunk` | 1..=16 MiB |
| `name` | ≤ 1104 바이트 (패딩된 평문 1088 + 태그 16). 평문은 `u16 LE 길이 ‖ 이름 ‖ 0x00 패딩`을 64의 배수로 채운 것 — 파일명 **길이 노출을 막기 위한 패딩**(T13). 이름 자체는 ≤ 1024 바이트 |
| `env` | 1..=32개, 각 `kid` 16바이트, `enc`·`ct` ≤ 1024바이트 |
| 헤더 전체 | ≤ 1 MiB (길이 필드와 실제 인코딩 모두) |
| `minor` | 리더보다 큰 minor는 허용(추가 필드만 가능), major 불일치는 거부 |

### 2.2a 정책 해시
`policy_hash = SHA-256("ZBACS-POL-v1" ‖ CBOR(pol))`. 헤더 해시와 달리 **정책만** 커버하므로, 승인 UI가 "이 파일의 권한 설정"을 표시하거나 두 버전의 정책 동일성을 비교할 때 쓴다. 온체인 앵커는 여전히 `header_hash`(정책을 포함한 헤더 전체)다.

### 2.3 Chunk 프레임
- **nonce = np(16B, 버전마다 난수) || LE u64 index** (24B XChaCha nonce). 파일명 암호화는 index `u64::MAX` 예약.
- AAD = `header_hash(32) || index(u64) || is_last(u8)`.
- 마지막 청크 `is_last=1` 로 절단(truncation) 공격 방지.

### 2.4 Trailer
- `header_hash(32)` + `total_chunks(u64)` + BLAKE3(ciphertext) 32B.

## 3. 봉인(Seal) 알고리즘
1. `DEK ← CSPRNG 32B`, `salt ← 16B`, `nonce_prefix ← 16B`.
2. 평문 스트리밍: 청크 암호화하며 `plaintext_hash` 계산 → `fid`.
3. 헤더 생성 → 소유자 봉투 `HPKE.Seal(owner_pub, DEK, info="zbacs-dek-v1")`.
4. 헤더 서명 → 파일 원자적 쓰기(temp + rename).
5. 체인 `FileRegistry.register(fid, owner)` (비동기, 실패 시 재시도 큐).

## 4. 개봉(Open) 검증 순서
1. magic/version(major 일치) → 헤더 길이 필드 ≤ 1 MiB → 헤더 CBOR 파싱 → **서명 검증** → §2.2 필드 제한 검사. 어느 단계든 실패하면 키를 만지기 전에 중단한다.
2. 정책 해시와 온체인 `FileRegistry` 커밋 비교(오프라인 캐시 허용, `strict`면 필수).
3. AccessGrant 검증(§approval_protocol) → GrantMsg 봉투로 DEK 복원.
4. 파일명 복호화(실패 = 잘못된 DEK, 청크 복호화 전에 중단) → 청크 순차 복호화(AAD에 `header_hash‖index‖is_last`) → trailer 3항 일치 → **스트림 끝(EOF)** 확인. 잔여 바이트·누락 청크·트레일러 불일치는 모두 `Truncated`.
5. 오류가 나면 이미 출력된 부분 평문은 **폐기**한다(청크 단위로는 진본이지만 파일 전체의 무결성은 보장되지 않음). Agent는 임시 파일에 쓰고 성공 시에만 rename 한다.

## 5. 재봉인(Reseal)
- 새 DEK, 새 `np`, `ver+1`, `prev = 이전 header_hash`, 소유자 봉투는 **소유자 공개키로 다시 생성**(수신자는 소유자 공개키를 헤더의 `env[0].kid`로 알고 있음. 소유자 X25519 공개키를 헤더 `own_pub`에 포함하도록 v1.1 검토).
- **`fid`와 `salt`는 버전 간 불변**이다. `fid`는 파일의 정체성이고 온체인 `FileRegistry`의 키이며, `bumpVersion(fileId, newHeaderHash)`이 같은 `fid` 아래 최신 헤더 해시를 갱신한다. 따라서 `fid = SHA-256(plaintext_hash ‖ salt)` 유도는 **버전 1에만** 적용되고, 이후 버전의 내용 무결성은 `header_hash`(온체인 앵커)와 트레일러가 담당한다.
- 버전 체인 규칙(파서가 검사): `ver_{n} = ver_{n-1} + 1`, `prev_{n} = SHA-256(header_{n-1})`, `fid`·`salt` 동일. 체인이 끊기면 다운그레이드·교체 공격으로 간주한다(T19).
- 교체는 원자적이어야 한다: 같은 디렉터리에 임시 파일로 쓴 뒤 `rename`. 실패 시 이전 버전이 그대로 남는다.
- 수신자 Agent는 자신의 봉투를 넣지 않는다. 다음 열람도 재승인 필요.
- 새 DEK를 쓰므로 이전 버전의 DEK(승인으로 배포된 것 포함)로는 새 버전을 열 수 없다 — 회수(revoke) 이후 재봉인이 접근을 실제로 끊는 근거(T20).

## 6. 구현 상태
- v1 PoC: `crates/zbacs-core` (Z-0.C.1/C.2 완료, 2026-09-19). 상세: `docs/research/crypto_container_poc.md`.
- 헤더 CBOR 필드 순서 = 서명 정규화 규칙. 필드 순서·타입 변경 시 `minor`/`major` 상승 필수.

## 7. 테스트 벡터
- `crates/zbacs-core/tests/vectors/` 에 고정 키·평문으로 생성한 `.zbacs`와 기대 해시 보관.
