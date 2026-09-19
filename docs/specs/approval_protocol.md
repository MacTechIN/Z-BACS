# 스펙: 접근 요청·승인 프로토콜 v1

| 상태 | Draft 1.2 (2026-09-19: §3 버전 바인딩·retire·consumeOpen 기기 바인딩 — Z-1.H.1/H.2) |
|---|---|
| 구현 | `crates/zbacs-core/src/grant.rs`, `contracts/src/AccessPolicy.sol`, `apps/relay` |

## 1. 메시지

### 1.1 AccessRequest (Bob → Relay → Alice)
```
AccessRequest {
  fid:        bytes32
  header_hash: bytes32
  device_kid: bytes16          // Bob 기기 키 ID
  device_x25519_pub: bytes32   // DEK 봉투 수신용
  device_ed25519_pub: bytes32
  requested:  Permission        // ReadOnly | Edit
  nonce:      bytes16
  ts:         u64
  hint:       string(≤64)       // Bob 이름/기기명 (선택, Relay 통과 시 암호화 권장)
  sig:        Ed25519(device_ed25519, "ZBACS-REQ-v1" || CBOR(fields))
}
```

### 1.2 AccessGrant (EIP-712, Alice 서명)
```solidity
struct AccessGrant {
  bytes32 fileId;
  bytes32 headerHash;
  bytes32 deviceKeyHash;   // keccak(device_x25519_pub || device_ed25519_pub)
  uint8   permission;      // 0 Deny, 1 ReadOnly, 2 Edit
  uint64  notBefore;
  uint64  expiry;
  uint16  maxOpens;
  bytes16 requestNonce;
  uint256 grantNonce;      // 소유자 계정 nonce (재전송 방지)
}
// domain: name="Z-BACS", version="1", chainId, verifyingContract=AccessPolicy
```

### 1.3 GrantMsg (Alice → Relay → Bob)
```
GrantMsg { grant: AccessGrant, sig: bytes, envelope: { enc, ct } /* HPKE(DEK → device_x25519_pub) */,
           owner_account: address, tx_hash: bytes32|null }
```
- `permission == Deny` 이면 envelope 없음.

### 1.4 Revoke
```
Revoke { grantId = keccak(AccessGrant), sig } → 체인 revoke() + Relay 브로드캐스트
```

### 1.5 소유자 서명 방식 (ADR-0006)
소유자 계정은 서명자를 여러 개 가진다. `GrantMsg.sig`는 둘 중 하나이며 Bob Agent는 구분하지 않는다(ERC-1271 `isValidSignature`로 계정에 위임).
```
OwnerSig = WebAuthn { authenticatorData, clientDataJSON, r, s }   // A. 플랫폼 패스키 → Kernel WebAuthn Validator
         | P256Raw  { keyId: bytes32, r, s }                      // B. 등록 기기 키   → P256Validator (low-s 필수)
```
기기 등록·해지는 소유자 계정의 UserOp이며 체인 이벤트로 남는다:
```
DeviceEnroll { account, keyId = keccak(x‖y), x, y, kind: Passkey|DeviceKey, requireOsConfirm: bool, ts }  // 기존 서명자가 서명
DeviceRevoke { account, keyId, ts }                                                                        // 다른 등록 서명자가 서명
```
정책 기본값: `permission == Edit` 승인 또는 10분 내 5건 초과 승인은 서명자 종류와 무관하게 OS 확인(생체/PIN)을 요구한다(T23).

## 2. 검증 규칙 (Bob Agent)
1. `grant.fileId/headerHash` == 로컬 컨테이너 값.
2. `deviceKeyHash` == 자신의 키 해시.
3. `requestNonce` == 자신이 보낸 nonce (1회 사용 후 폐기).
4. 서명 검증: 소유자 계정이 EOA면 ECDSA, 스마트계정이면 ERC-1271 `isValidSignature` (체인 조회 또는 캐시).
5. 시간: `notBefore ≤ now ≤ expiry` (로컬 시계 ±5분 허용, `strict`면 체인 블록 시간 사용).
6. 체인: `AccessPolicy.isValid(grantId)` (`strict`면 필수, 아니면 best-effort + 주기 확인).
7. 봉투 개봉 성공 → 세션 시작. 실패 시 `Failed`.

## 3. 온체인 함수

```solidity
function grant(AccessGrant calldata g, bytes calldata ownerSig) external returns (bytes32 grantId);
function revoke(bytes32 grantId) external;                                    // onlyOwnerOf(fileId)
function isValid(bytes32 grantId) external view returns (bool);              // !revoked && 시간창 && opens 여유
function consumeOpen(bytes32 grantId, bytes calldata devicePubKeys) external; // maxOpens 카운트
// FileRegistry: register(fileId, headerHash) / bumpVersion(fileId, newHeaderHash) / retire(fileId)
//               currentVersion(fileId) -> (headerHash, version, retired)
```

`grant()` 검증 순서(Z-1.H.2): 등록 여부 → **폐기(retire) 여부** → **`g.headerHash`가 레지스트리의 현재 헤더 해시와 일치**(T19: 재봉인 이후 옛 버전은 다시 승인될 수 없다) → 권한 값 → 시간창 → 만료 → 소유자 nonce → 요청 nonce → 서명(ERC-1271 포함).

`consumeOpen(grantId, devicePubKeys)`은 `keccak256(devicePubKeys) == deviceKeyHash`를 요구해 카운터를 승인된 기기의 공개키를 아는 호출자에게 묶는다. 체인에 Ed25519 프리컴파일이 없어 **기기 자체의 서명 증명은 아니며**, 원격 어테스테이션은 `Z-3.H.3`이다. 카운터는 감사용이고 `maxOpens` 강제의 1차 책임은 수신자 Agent에 있다.
- 가스는 소유자 스마트계정 + 페이마스터 대납. Bob은 트랜잭션을 보내지 않는다(`AuditLog.Opened`는 Relay 또는 Bob Agent가 선택적으로 기록).

## 4. 타임아웃과 상태
| 상황 | 동작 |
|---|---|
| 승인 대기 > 120s | Bob 화면 "대기 중… 재요청" 유지, 300s 후 만료 |
| 소유자 오프라인 | 요청 큐 보관 24h, 소유자 복귀 시 알림. Phase 3: 정책 위임 |
| 세션 중 revoke 수신 | 즉시 앱 종료 요청 → 강제 재봉인 |

## 5. 프라이버시
- Relay는 `hint`를 소유자 공개키로 암호화한 형태로만 중계(Phase 2).
- 온체인 `Granted` 이벤트에는 `deviceKeyHash`만 노출.
