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
1. magic/version → 헤더 CBOR 파싱(길이 상한 1MiB) → 서명 검증.
2. 정책 해시와 온체인 `FileRegistry` 커밋 비교(오프라인 캐시 허용, `strict`면 필수).
3. AccessGrant 검증(§approval_protocol) → GrantMsg 봉투로 DEK 복원.
4. 청크 순차 복호화, `is_last`·trailer 검증.

## 5. 재봉인(Reseal)
- 새 DEK, `ver+1`, `prev = 이전 header_hash`, 소유자 봉투는 **소유자 공개키로 다시 생성**(수신자는 소유자 공개키를 헤더의 `env[0].kid`로 알고 있음. 소유자 X25519 공개키를 헤더 `own_pub`에 포함하도록 v1.1 검토).
- 수신자 Agent는 자신의 봉투를 넣지 않는다. 다음 열람도 재승인 필요.

## 6. 구현 상태
- v1 PoC: `crates/zbacs-core` (Z-0.C.1/C.2 완료, 2026-09-19). 상세: `docs/research/crypto_container_poc.md`.
- 헤더 CBOR 필드 순서 = 서명 정규화 규칙. 필드 순서·타입 변경 시 `minor`/`major` 상승 필수.

## 7. 테스트 벡터
- `crates/zbacs-core/tests/vectors/` 에 고정 키·평문으로 생성한 `.zbacs`와 기대 해시 보관.
