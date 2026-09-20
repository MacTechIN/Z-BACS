# Z-BACS 시스템 아키텍처 (Architecture)


| 문서 버전 | 1.0 (2026-09-18)                                                                                                                                                                                                   |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 관련 문서 | [project_definition.md](project_definition.md), [specs/container_format.md](specs/container_format.md), [specs/approval_protocol.md](specs/approval_protocol.md), [threat_model.md](threat_model.md), [adr/](adr/) |


## 1. 설계 원칙

0. **사용자가 아무것도 몰라도 쓸 수 있어야 한다.** 계정·키·가스·설치·설정은 시스템이 자동 처리하고 UI에는 기술 용어를 쓰지 않는다. 다른 원칙과 충돌 시 이 원칙이 설계를 바꾼다 ([ux_principles.md](ux_principles.md)).
1. **키는 절대 서버에 없다.** DEK(파일 데이터키)는 소유자 기기와 승인된 수신자 기기에만 존재한다. Relay와 체인은 키를 보관하지 않는다.
2. **승인 없는 개봉은 수학적으로 불가능해야 한다.** 정책 플래그가 아니라 암호학적 봉투(HPKE)가 통제한다.
3. **온체인에는 커밋만.** 파일명·내용·신원은 해시/커밋으로만 기록한다.
4. **벤더 격리.** BSA, Lit, 체인, 푸시는 모두 트레이트/인터페이스 뒤에 둔다.
5. **Windows 우선, 크로스플랫폼 코어.** 코어(`zbacs-core`)는 OS 독립 Rust, OS 의존 부분은 어댑터.
6. **검증된 암호 라이브러리만.** 자체 프리미티브 구현 금지.

## 2. 구성요소 다이어그램

```
┌──────────────────────────────┐          ┌──────────────────────────────┐
│  Owner (Alice) 기기           │          │  Recipient (Bob) 기기        │
│  ┌────────────────────────┐  │          │  ┌────────────────────────┐  │
│  │ zbacs-agent (Tauri 2)  │  │          │  │ zbacs-agent (Tauri 2)  │  │
│  │  - Seal / Reseal       │  │          │  │  - Open / Reseal       │  │
│  │  - Owner keystore      │  │          │  │  - Device keystore     │  │
│  │  - Session manager     │  │          │  │  - Protected workspace │  │
│  │  - Approval UI (desk)  │  │          │  │  - Watcher (save/exit) │  │
│  └───────┬────────────────┘  │          │  └───────┬────────────────┘  │
│  ┌───────┴────────────────┐  │          │          │                   │
│  │ zbacs-approve (mobile) │  │          │          │                   │
│  │  - BSA / Passkey       │  │          │          │                   │
│  └───────┬────────────────┘  │          │          │                   │
└──────────┼───────────────────┘          └──────────┼───────────────────┘
           │  EIP-712 서명, HPKE 봉투                │  AccessRequest
           │                                         │
     ┌─────┴─────────────────────────────────────────┴─────┐
     │  zbacs-relay (무신뢰)                                │
     │   - 요청/응답 큐, 푸시 발송(FCM/APNs/ntfy)             │
     │   - 봉투(암호문) 전달만, 복호화 불가                    │
     └─────┬─────────────────────────────────────────┬─────┘
           │                                         │
     ┌─────┴─────────────────────────────────────────┴─────┐
     │  Ledger (EVM L2: Base / 로컬 Anvil / 프라이빗 Besu)   │
     │   FileRegistry · AccessPolicy · AuditLog            │
     │   Owner = ERC-4337/7579 패스키 스마트계정             │
     └──────────────────────────────────────────────────────┘
                     (Phase 3) Guardian Nodes / Lit  ─ 오프라인 위임
```

## 3. 패키지(크레이트) 구조와 책임

```
Z-BACS/
├── crates/
│   ├── zbacs-core/      # 컨테이너 포맷, AEAD 스트림, HPKE 봉투, 정책/티켓 구조체, 서명
│   ├── zbacs-proto/     # Relay 와이어 프로토콜: CBOR 메시지 + Ed25519 Signed<T> 봉투
│   ├── zbacs-session/   # 세션 상태머신, 보호 작업공간, 안전 삭제
│   ├── zbacs-auth/      # AuthProvider 트레이트 + Passkey(Win/mac/Linux) + DeviceKey(TPM/Keystore/SE) + BSA + OTAK
│   ├── zbacs-chain/     # alloy 기반 컨트랙트 바인딩, EIP-712 타입, 이벤트 스트림
│   ├── zbacs-session/   # 열람 세션 상태머신, 보호 작업공간, 감시자, 재봉인
│   ├── zbacs-relay-client/ # Relay 프로토콜 클라이언트
│   └── zbacs-stub/      # Windows 자체실행 래퍼 (최소 의존성)
├── apps/
│   ├── agent/           # Tauri 2 데스크톱 Agent (crates 조합 + UI)
│   ├── approve/         # 소유자 승인 앱 (모바일/데스크톱)
│   └── relay/           # axum Relay 서버
├── contracts/           # Foundry: FileRegistry, AccessPolicy, AuditLog, 테스트
├── packages/
│   └── chain-ts/        # viem/permissionless 기반 TS SDK (승인 앱·웹 대시보드용)
├── tools/
│   └── audit/           # Slither + HF 모델 감사 파이프라인
└── docs/
```

### 3.1 zbacs-core 핵심 타입 (Z-1.C.1 구현)

```rust
pub struct FileId([u8; 32]);        // SHA-256(SHA-256(plaintext) || salt) — 온체인 커밋 (T13)
pub struct HeaderHash([u8; 32]);    // SHA-256(header CBOR) — 청크 AAD·트레일러·온체인 앵커
pub struct KeyId([u8; 16]);         // SHA-256(x25519_pk)[..16] — 봉투 수신자 id
pub struct Dek([u8; 32]);           // zeroize-on-drop
pub enum Permission { Deny = 0, ReadOnly = 1, Edit = 2 }
pub struct Policy { default: Permission, ttl: u32, max: u16, pin: bool, strict: bool }
pub struct Envelope { kid: KeyId, alg: String, enc: Vec<u8>, ct: Vec<u8> }        // HPKE DEK 봉투
pub struct HeaderBody { fid: FileId, salt, ver: u32, prev: Option<HeaderHash>, own: Vec<u8>, pol: Policy,
                        cipher: u8, chunk: u32, plen: u64, np: NoncePrefix, name: Vec<u8> /*enc*/, env: Vec<Envelope> }
pub struct Header { body: HeaderBody, sigk: [u8;32], sig: [u8;64] }               // Ed25519 over "ZBACS-HDR-v1"||CBOR(body)

pub trait Sealer { fn seal(&self, input: &mut dyn ReadSeek, out: &mut dyn Write, opts: &SealOptions) -> Result<Header>; }
pub trait Opener { fn open(&self, input: &mut dyn Read, out: &mut dyn Write) -> Result<Opened>; }
// impl Sealer for OwnerKeys; impl Opener for DeviceKeys (내장 봉투); impl Opener for GrantedDek (승인으로 받은 DEK)
```
와이어 포맷은 PoC(Z-0.C.1)와 동일(고정 길이 필드도 CBOR 바이트열). 공개 API는 `#![warn(missing_docs)]` + CI `cargo doc -D warnings`, 커버리지 게이트 90%(`cargo llvm-cov`).

### 3.2 zbacs-auth 트레이트 (Z-1.A.1 구현, ADR-0006)
```rust
pub trait AuthProvider: Send + Sync {
    fn kind(&self) -> SignerKind;                 // PlatformPasskey | DeviceKey | Bsa | Otak
    fn key_id(&self) -> KeyId;                    // keccak256(x‖y)
    fn public_key(&self) -> Option<P256PublicKey>;
    fn supports_os_confirmation(&self) -> bool;   // 생체/PIN 프롬프트를 앞에 둘 수 있는가
    fn sign(&self, c: &ApprovalChallenge, confirm: Confirmation) -> Result<ApprovalAssertion, AuthError>;
}
// ApprovalChallenge { digest: [u8;32] /* EIP-712 or userOpHash */, context: { permission, file_id } }
// ApprovalAssertion = WebAuthn{authenticator_data, client_data_json, r, s} | P256Raw{key_id, r, s} | Bsa{token} | Otak{key_id, mac}
// ConfirmationPolicy::required(ctx, device_setting, recent_ts, now) → NotRequired | OsUserVerification  (T23)
// verify_assertion(key, challenge, assertion): low-s 강제, UP/UV 플래그, clientData challenge 일치 검사
```
구현체: `PasskeyProvider`(Z-1.A.2), `DeviceKeyProvider`(Z-1.A.7), `BsaProvider`(Z-1.A.5), `OtakProvider`(Z-1.A.6). 테스트·데모용 `software::{SoftwareDeviceKey, SoftwarePasskey}`(feature `software-signer`).

### 3.3 zbacs-session 상태머신

```
Closed ──open()──▶ Requesting ──grant──▶ Decrypting ──▶ Active(ReadOnly|Edit)
   ▲                  │ deny/timeout            │ error        │ save/exit/ttl/revoke
   │                  ▼                         ▼              ▼
   └──────────── Denied                     Failed        Resealing ──▶ Closed
```

- `Active(Edit)`: `notify`로 작업공간 변경 감시, 열람 앱 PID 종료 감지(`sysinfo`).
- `Resealing`: 새 DEK 생성 → 청크 암호화 → 새 헤더(version+1, prev_version) → 원자적 교체 → 평문 안전 삭제(덮어쓰기 + 삭제, SSD는 best-effort 명시) → `AuditLog.Sealed`.
- `Active(ReadOnly)`: 작업공간 파일 읽기전용 ACL, 변경 감지 시 경고·폐기.

### 3.4 보호 작업공간(Protected Workspace)

- 위치: `%LOCALAPPDATA%\ZBACS\ws\<session-id>\` 사용자 전용 ACL(SYSTEM + 현재 사용자만), 인덱싱 제외, 백업 제외 속성.
- Phase 2: Dokan 가상 드라이브로 평문을 디스크에 쓰지 않는 모드.
- Phase 3: 미니필터로 허용 프로세스 외 접근 차단.

## 4. 데이터 흐름 (승인 시퀀스)

```
Bob.agent            Relay              Alice.approve/agent          Ledger
   │ 1. AccessRequest{fileId, deviceKid, devicePub, nonce, sig}      │
   ├────────────────▶│ 2. push(Alice)                                │
   │                 ├───────────────────▶│ 3. 표시: 파일/요청자/권한 │
   │                 │                    │ 4. AuthProvider.approve() │
   │                 │                    │ 5. EIP-712 AccessGrant 서명│
   │                 │                    │ 6. HPKE(DEK → devicePub)  │
   │                 │                    ├──── 7. grant tx/UserOp ──▶│
   │                 │◀── 8. GrantMsg{grant, sig, envelope} ─────────│
   │◀────────────────┤                                               │
   │ 9. 서명 검증 + 체인 이벤트 확인(옵션: 온체인 확인 대기)          │
   │ 10. HPKE 열기 → DEK → 복호화 → 앱 실행                          │
   ├──────────── 11. AuditLog.Opened ─────────────────────────────▶│
```

- 온체인 기록은 **감사·회수 용도**이며, 개봉 자체는 8번 봉투 수신으로 가능하다. 온체인 확정 대기 옵션(`strict_onchain`)은 정책으로 켠다.
- 회수: Alice가 `revoke(grantId)` → Relay 브로드캐스트 + 체인 이벤트 → Bob.agent 세션 종료·재봉인.

## 5. 키 계층


| 키                       | 생성 위치                            | 보관                              | 용도                   |
| ----------------------- | -------------------------------- | ------------------------------- | -------------------- |
| 소유자 승인키 A: 플랫폼 패스키 (Windows Hello/Touch ID/BSA) | OS 인증기 (TPM/Secure Enclave) | 하드웨어, 승인마다 생체·PIN 창 | EIP-712 승인 서명, 계정 서명자 (ADR-0006) |
| 소유자 승인키 B: 기기 바운드 키 (P-256, 등록 기기당 1개) | Agent가 TPM/Keystore/Secure Enclave에 생성, 내보내기 불가 | 하드웨어, 탭만으로 승인(기기별 OS 확인 옵션) | EIP-712 승인 서명, 계정 서명자 (ADR-0006) |
| 소유자 봉인키 (X25519)        | Agent                            | OS 키체인(DPAPI/Keychain) + 암호화 백업 | 자기 봉투(DEK 자기 복구)     |
| 기기 키 (X25519 + Ed25519) | 각 Agent                          | OS 키체인                          | 요청 서명, DEK 수신 봉투     |
| DEK (32B)               | Seal/Reseal 시 난수                 | 봉투 안에서만                         | 파일 청크 AEAD           |
| 컨테이너 서명키 (Ed25519)      | 소유자 Agent                        | OS 키체인                          | 헤더 무결성               |


복구: Phase 1은 **복구 코드 1개 + 암호화 백업 파일**(`export_backup`/`restore_backup`, Z-1.A.4). Phase 2에서 그 코드를 Shamir(2-of-3)로 분할해 다른 기기·클라우드(암호화)·인쇄 코드에 분산(Z-2.A.1).

## 6. 온체인 계약 개요


| 계약           | 함수                                                                          | 이벤트                               |
| ------------ | --------------------------------------------------------------------------- | --------------------------------- |
| FileRegistry | `register(fileId, owner)`, `bumpVersion(fileId, newHash)`, `retire(fileId)` | Registered, VersionBumped         |
| AccessPolicy | `grant(AccessGrant, sig)`, `revoke(grantId)`, `isValid(grantId)`            | Granted, Revoked                  |
| AuditLog     | `log(fileId, kind, actorCommit, detail)` — 이벤트 전용(스토리지·외부 호출 없음, 실측 25,515 gas/건). 항목은 `reporter`의 **주장**이며 증명이 아님(기기 서명 온체인 검증 불가 → Z-3.H.3) | `Logged(fileId, kind, reporter, actorCommit, detail)`, kind = Requested/Denied/Opened/Sealed/Failed |
| P256Validator | ERC-7579 검증기(모듈 타입 1): `enrollKey(x,y,requireOsConfirm)`, `revokeKey(keyId)`, `validateUserOp`, `isValidSignatureWithSender`. 계정별 기기 키 집합, 서명 `keyId‖r‖s`(96B), OZ `P256.verify`(프리컴파일+폴백, low-s 강제) | DeviceEnrolled, DeviceRevoked |


- 소유자 계정: ERC-7579 Kernel + WebAuthn Validator(플랫폼 패스키) + `P256Validator`(등록 기기 키 집합, add/remove = 기기 등록/해지). 둘 다 RIP-7212 프리컴파일, Daimo 폴백. 가스는 페이마스터 대납. (ADR-0006)
- 프라이버시: `actorCommit = H(deviceKid || salt)`. Phase 3에서 Semaphore 증명으로 교체.

## 7. 기술 스택 요약


| 계층       | 선택                                | 근거(ADR)                             |
| -------- | --------------------------------- | ----------------------------------- |
| 코어 언어    | Rust (stable)                     | 메모리 안전, 암호 생태계, Tauri 호환 (ADR-0001) |
| 데스크톱     | Tauri 2 + React/TS                | 파일 연결·경량·코드 서명 (ADR-0001)           |
| 암호       | RustCrypto + hpke-rs              | (ADR-0002)                          |
| 승인 인증    | AuthProvider: Passkey 우선, BSA 어댑터 | (ADR-0003)                          |
| 체인       | Base Sepolia → Base, 로컬 Anvil     | L2 지연, RIP-7212 (ADR-0005)          |
| 컨트랙트     | Solidity 0.8.x + Foundry + OZ v5  |                                     |
| Relay    | Rust axum + NATS(옵션)              |                                     |
| 푸시       | FCM/APNs, 셀프호스팅 ntfy 폴백           |                                     |
| PRE(3단계) | umbral-pre 자체 노드 또는 Lit v8        | (ADR-0004)                          |


## 8. 배포 형태

- Windows: NSIS 설치기(`.zbs` 파일 연결) + 선택적 `zbacs-stub.exe` 래퍼. Authenticode EV 서명.
- macOS: `.dmg` + notarization, Linux: AppImage/deb.
- Relay: Docker 컨테이너, 상태 최소(큐 + 푸시 토큰). 셀프호스팅 가능.
- 컨트랙트: Foundry 스크립트, UUPS 프록시 + 48h 타임락.

