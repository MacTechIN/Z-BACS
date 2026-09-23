# Z-BACS 개발 계획서 (Development Plan)

| 문서 버전 | 1.0 (2026-09-18) |
|---|---|
| 근거 | [project_definition.md](project_definition.md), [research.md](research.md), [architecture.md](architecture.md) |
| 원칙 | 모든 작업은 **마이크로 태스크(0.5~2일)** 단위로 정의하고, 각 태스크는 입력·산출물·완료 기준(DoD)을 가진다. 태스크 ID는 `Z-<phase>.<track>.<seq>` |

## 0. 트랙(병렬 작업 축)

| 트랙 | 코드 | 범위 |
|---|---|---|
| Core Crypto | C | `zbacs-core` 컨테이너·암호 |
| Auth | A | `zbacs-auth` 패스키/BSA/OTAK |
| Chain | H | 컨트랙트 + `zbacs-chain` + TS SDK |
| Agent | G | Tauri 데스크톱 Agent, 세션, 작업공간 |
| Relay | R | Relay 서버, 푸시 |
| Approve | P | 소유자 승인 앱 |
| Stub/Distribution | S | 자체실행 래퍼, 설치기, 코드 서명 |
| Security/QA | Q | 위협모델 검증, 퍼징, 감사 CI |
| Docs/DevEx | D | 문서, ADR, 개발 환경 |
| **UX** | U | 무입력 온보딩, 용어 린트, 사용성 테스트 — 최상위 원칙 [ux_principles.md](ux_principles.md) 집행 |

의존성 규칙: C → (A, H) → G → (R, P) → S. Q·D·U는 전 단계 병행. **U 트랙의 UX DoD는 각 Phase 종료 게이트다.**

---

## Phase 0 — 프로젝트 셋업 & 스파이크 (목표 2주)

### 목적
툴체인 확정, 핵심 리스크(패스키 네이티브 호출, 파일 연결, 컨테이너 PoC) 조기 검증.

| ID | 태스크 | 입력 | 산출물 | DoD |
|---|---|---|---|---|
| Z-0.D.1 ✅ | 리포지토리 초기화, 모노레포 레이아웃(`crates/ apps/ contracts/ packages/ tools/`), `.gitignore`, `CLAUDE.md` | architecture §3 | 디렉터리 골격 | `cargo build`가 빈 크레이트로 통과 |
| Z-0.D.2 ✅ | 툴체인 설치 스크립트: Rust stable, Node 22, Foundry, Tauri CLI, Python 3.10+ | - | `tools/setup.sh`, `tools/setup.ps1` | 스크립트 실행 후 `cargo tauri --version` 성공 (2026-09-19 완료) |
| Z-0.D.3 ✅ | CI 골격(GitHub Actions): fmt/clippy/test, forge test, npm test | - | `.github/workflows/ci.yml` | PR에서 녹색 |
| Z-0.C.1 ✅ | 컨테이너 PoC: 청크 XChaCha20-Poly1305 + CBOR 헤더 + Ed25519 서명 | specs/container_format | `zbacs-core` seal/open CLI | 100MB 파일 왕복 ≤ 2s, 변조 시 실패 (2026-09-19: 0.35s, 테스트 10종 통과) |
| Z-0.C.2 ✅ | HPKE 봉투 PoC (hpke-rs) | - | `envelope.rs` | DEK 왕복, 테스트 벡터 |
| Z-0.A.1 | Windows Hello 네이티브 스파이크: `webauthn.dll`로 MakeCredential/GetAssertion (windows-rs 또는 keyroost) | research §1.2 | `spikes/win-hello/` | 생체 프롬프트 뜨고 assertion 반환 |
| Z-0.A.2 | `webauthn-rs`로 위 assertion 검증 | Z-0.A.1 | 테스트 | 검증 통과 |
| Z-0.A.3 ◐ | BSA 샌드박스 Client Key 신청(OR-1), SDK 문서 수령·요약 | research §1.1 | `docs/research/bsa_sdk_notes.md` | API 흐름 문서화 (2026-09-19: 메모 작성 — 막힌 이유, **사용자가 할 신청 절차와 받아올 4가지 규격**, 대체 구현 현황. 신청은 조직 명의 외부 절차라 대행 불가) |
| Z-0.G.1 ✅ | Tauri 2 스파이크: `.zbacs` 파일 연결, `RunEvent::Opened` 로 경로 수신, 단일 인스턴스 | research §3 | `spikes/tauri-assoc/` | 더블클릭 시 앱 실행·경로 로그 (2026-09-19 Linux headless: 인자 수신·단일 인스턴스 전달·deb 파일연결 확인. Windows 실기 확인은 Z-0.A.1과 함께) |
| Z-0.H.1 ✅ | Foundry 프로젝트 + Anvil, `AccessGrant` EIP-712 서명·검증 PoC | specs/approval_protocol | `contracts/` | `forge test` 통과 (2026-09-19: 18 tests, T03/T14/T15/T20 매핑, 벡터 기록) |
| Z-0.H.2 ✅ | Base Sepolia RIP-7212 실측(OR-2), Kernel+Passkey Validator 계정 생성 스파이크(permissionless.js) | research §4 | `spikes/aa-passkey/` | 패스키로 UserOp 1건 성공 (2026-09-19: Base Sepolia·메인넷 P256VERIFY 활성 3,885 gas, Kernel v3.1+WebAuthn UserOp가 포크의 실제 EntryPoint v0.7 통과, 10 tests; Pimlico 번들러+페이마스터 실제 제출 2건 성공 757,792 / 418,432 gas) |
| Z-0.Q.1 ✅ | 위협모델 리뷰 워크숍, T01~T20 → 태스크 매핑 | threat_model | 매핑표(이 문서 §부록) | 누락 없음 (2026-09-19: T01~T23 전부 매핑, 사라진 ID(Z-2.S.1/2) 정정, 스파이크 근거 열 추가, T21·T22 신규) |

**Phase 0 종료 기준**: 5개 스파이크(C.1, A.1, G.1, H.1, H.2) 모두 성공 또는 대안 ADR 작성. — 2026-09-19: C.1, G.1, H.1, H.2 완료. A.1(Windows Hello)은 ADR-0006으로 게이트에서 제외(경로 B 기기 키가 H.2에서 체인까지 검증됨; A.1은 Phase 1 Z-1.A.2 선행으로 Windows 실기 확보 시 진행). **Phase 0 종료.**

---

## Phase 1 — MVP (Windows, 목표 10주)

### 1.1 Core (C)
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.C.1 ✅ | `zbacs-core` 크레이트 정식화: 타입, 에러, `Sealer/Opener` 트레이트 | 문서화된 공개 API, 단위 테스트 90% (2026-09-19: `FileId/HeaderHash/KeyId/Salt/NoncePrefix` 고정 길이 타입(와이어 호환), 객체 안전 `Sealer/Opener` + `GrantedDek`, 에러 문서화·`non_exhaustive`, `missing_docs` + CI rustdoc -D warnings, `cargo llvm-cov` 90% 게이트 CI) |
| Z-1.C.2 ✅ | 컨테이너 파서 견고화: 길이 상한, 버전 검사, 절단 방지(`is_last`), trailer | 악성 입력 테스트 20종 (2026-09-19: spec §2.2 필드 제한 명문화 → `validate_header`(서명 검증 후·키 사용 전: ver/prev 체인, own 1..64, name ≤1040, env 1..32·필드 ≤1024), 버전 오버플로 방지, `tests/malicious.rs` **31종**(프레이밍·서명·필드 제한·봉투·청크·트레일러·랜덤 변이 500회+전 길이 절단), 커버리지 게이트 유지) |
| Z-1.C.3 ✅ | `cargo-fuzz` 타깃(header, chunk) | 24h 퍼징 무크래시 (2026-09-20 완료: 타깃 4종 `header`/`header_signed`/`open_mutated`/`envelope`을 각 6시간·4 워커로 총 24시간 실행 — **누적 420,679,318회 실행, 크래시 0**, 아티팩트 0개. `tools/fuzz.sh 24h`로 재현, 야간 CI `fuzz.yml`이 타깃당 20분씩 계속 돌린다) |
| Z-1.C.4 ✅ | 재봉인(Reseal): 새 DEK, 버전 체인, 원자적 교체 | v1→v2→v3 체인 검증 테스트 (2026-09-19: spec §5 확장 — `fid`/`salt` 버전 불변(온체인 `bumpVersion` 키), 체인 규칙, 원자 교체, 새 DEK로 이전 승인 무효화(T20). `PrevVersion`, `reseal_to_path`, `verify_version_chain`, `decrypt_name`, CLI `zbacs reseal`; 테스트 10종) |
| Z-1.C.5 ✅ | 파일명 암호화, 정책 해시, 테스트 벡터 고정 | vectors 디렉터리 (2026-09-19: spec v1.2 — 파일명 64B 배수 패딩(길이 노출 차단, T13) + §2.2a `policy_hash = SHA-256("ZBACS-POL-v1"‖CBOR(pol))`; `crates/zbacs-core/tests/vectors/`(v1/v2 컨테이너·소유자 키·manifest) 고정 + 회귀 테스트 2종, 재생성은 `--ignored regenerate`) |
| Z-1.C.6 ✅ | 키 자료 zeroize 감사, `secrecy` 적용 | 리뷰 체크리스트 통과 (2026-09-19: `Dek`을 `secrecy::SecretBox`로 전환, 모든 키 타입에 마스킹 `Debug`, seal/open/파일명 평문 버퍼 wipe, `ZeroizeOnDrop` 컴파일 타임 단언, 감사 기록 `docs/research/key_hygiene_audit.md`) |

### 1.2 Auth (A)
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.A.1 ✅ | `AuthProvider` 트레이트 + `ApprovalChallenge/Assertion` 타입 | 문서화 (2026-09-19: `crates/zbacs-auth` — 두 서명 경로 타입, `ConfirmationPolicy`(T23), `verify_assertion`(low-s·UP/UV·challenge), `DeviceEnroll/Revoke` 다이제스트, 소프트웨어 서명기, 12 tests incl. JS 스파이크 교차 벡터) |
| Z-1.A.2 ◐ | `PasskeyProvider(Windows)` 구현 — 승인 서명 경로 A(플랫폼 패스키, ADR-0006) | 등록·승인 E2E (2026-09-19: `zbacs-auth::windows::passkey` — webauthn.dll MakeCredential/GetAssertion, COSE 공개키 파싱, DER→low-s, 취소 처리. `cargo check --target x86_64-pc-windows-gnu` 통과. **실기 확인 대기**: `cargo run -p zbacs-wincheck`, `docs/windows_checklist.md`) |
| Z-1.A.7 ◐ | `DeviceKeyProvider` — 승인 서명 경로 B: TPM(Windows CNG)/Android Keystore/Secure Enclave에 내보내기 불가 P-256 키 생성, raw 서명, 기기별 OS 확인 옵션 (ADR-0006) | Windows TPM 키 생성·서명, 내보내기 불가 확인, 재부팅 후 사용, T23 정책 테스트 (2026-09-19: `zbacs-auth::windows::device_key` — NCrypt 영속 키(내보내기 정책 없음), UI 정책=OS 확인, low-s 정규화, 소프트웨어 KSP 폴백 표시. 크로스 컴파일 통과, **실기 확인 대기**) |
| Z-1.A.3 ◐ | 기기 키(X25519/Ed25519) 생성 + DPAPI/keyring 보관 | 재부팅 후 복원 (2026-09-19: `zbacs-auth::store` — `KeyStore` 트레이트, `OsKeyStore`(Credential Manager/Keychain/Secret Service), `MemoryKeyStore`, `get_or_create`. **재부팅 확인만 Windows에서 대기**) |
| Z-1.A.4 ✅ | 소유자 봉인키 생성·보관·암호화 백업 파일 내보내기 | 백업 복원 테스트 (2026-09-20: `zbacs-core::backup` — **암호를 묻지 않고 복구 코드를 생성**(125비트, 헷갈리는 글자 제외 5×5 그룹)해 한 번 보여주고 Argon2id(64MiB·3패스)로 늘려 XChaCha20-Poly1305 봉인. 헤더는 AAD로 인증, KDF 파라미터 상한으로 악성 파일의 자원 소모 차단. 복원 시 잘못된 코드와 손상 파일을 같은 오류로 처리. 테스트 9종 + CLI `zbacs backup`/`restore` 실제 복구 리허설. 코드 입력은 복구 흐름에서만 — 온보딩·봉인·승인 흐름에는 여전히 입력 필드 없음) |
| Z-1.A.5 ✅ | `BsaProvider` 골격 (SDK 확보 시 연결, 미확보 시 mock) | 인터페이스 호환 테스트 (2026-09-19: `BsaClient` 트레이트 + `BsaProvider` + `MockBsaClient`, 테스트 4종 — 토큰이 다이제스트·신원에 묶임, 거부는 Cancelled, P-256 검증기는 BSA assertion 판정 거부) |
| Z-1.A.6 ✅ | `OtakProvider` 최소 구현(X.1284 흐름: 요청별 키 파생·폐기) | 재전송 테스트 (2026-09-19: 시드는 우리가 생성(발급기관 없음), 요청 다이제스트마다 HMAC-SHA256으로 일회용 키 파생 후 폐기, 서명자·검증자 양쪽이 독립적으로 1회 사용 강제 → 재전송 거부. 상수시간 MAC 비교, 시드 마스킹 Debug, 테스트 7종. 온체인 검증 불가(대칭키)라는 한계를 코드·문서에 명시) |

### 1.3 Chain (H)
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.H.1 ✅ | `FileRegistry.sol` (register/bumpVersion/retire) + 테스트 | 100% 브랜치 (2026-09-19: `retire`·`currentVersion`·동일 헤더 해시 거부 추가, `forge coverage` 라인·구문·브랜치·함수 **100%**) |
| Z-1.H.2 ✅ | `AccessPolicy.sol` (grant/revoke/isValid, EIP-712, ERC-1271 지원) | 재전송·만료·회수 테스트 (2026-09-19: T19 버전 바인딩(옛 헤더 해시 거부)·retire 차단·`consumeOpen`을 기기 공개키에 바인딩·grant 레코드에 deviceKeyHash/headerHash 저장, 22 tests, 브랜치 100%) |
| Z-1.H.3 ✅ | `AuditLog.sol` 이벤트 계약 | 가스 ≤ 30k/log (2026-09-19: 이벤트 전용 `Logged(fileId, kind, reporter, actorCommit, detail)`, 실제 Anvil 트랜잭션 **25,515 gas** — `tools/chain-demo.sh`가 매번 실측·검사. 초안의 레지스트리 조회(~4.7k)는 31,030으로 예산 초과라 제거) |
| Z-1.H.4 ✅ | UUPS 프록시 + Timelock 배포 스크립트(Anvil, Base Sepolia) | 주소 파일 생성 (2026-09-21: `src/Upgradeable.sol`(Initializable+AccessControl+UUPS, 업그레이드 권한은 Timelock만) + `script/Deploy.s.sol` → `contracts/deployments/<chainId>.json`. **Anvil 실배포로 확인**: 프록시로 register가 되고 구현 슬롯·admin이 맞는다. `AuditLog`·`P256Validator`는 **일부러 업그레이드 불가** — 후자는 남의 계정에 설치되는 모듈이라 우리가 바꿀 수 있으면 그 계정들 대신 서명할 수 있다는 뜻이다. 업그레이드 권한 **포기 거부**(한 트랜잭션으로 영영 못 고치는 사고 방지), `AccessPolicy` 업그레이드가 **다른 레지스트리를 가리키면 온체인 거부**. 테스트 11종. Rust는 `Deployment::from_file`로 그 파일을 읽고(단위 5종), `zbacs-chain` 통합 테스트도 **프록시를 거쳐** 배포하도록 바꿔 EIP-712 도메인이 프록시 주소로 만들어지는 것까지 확인) |
| Z-1.H.5 | Slither + Echidna 불변식 CI | CI 게이트 |
| Z-1.H.6 | HF 감사 파이프라인(`tools/audit`): Qwen3-Coder-Audit 로컬/원격 추론 → PR 코멘트 | 샘플 PR 리포트 |
| Z-1.H.7 ✅ | `zbacs-chain`(alloy): ABI 바인딩, 이벤트 구독, 오프라인 캐시 | 통합 테스트(Anvil) (2026-09-21: Foundry 아티팩트에서 바인딩 생성(ABI 드리프트 시 컴파일 실패), 읽기·쓰기·`AuditLog`, `EventWatcher`(폴링 — 프록시 뒤에서도 동작, 실패한 범위를 건너뛰지 않음), `Cache`(마지막 답과 나이를 함께 보관, **죽은 grant는 되살아나지 않음**, strict 파일은 stale 답으로 열리지 않음). Anvil 통합 7종 + 단위 3종, `tools/chain-it.sh`·CI 연결) |
| Z-1.H.8 | `packages/chain-ts`: viem 타입, EIP-712 서명 헬퍼, permissionless 계정 생성 | 승인 앱에서 사용 |
| Z-1.H.9 | 페이마스터 설정(Pimlico 샌드박스) | 가스 0 UserOp |
| Z-1.H.10 ✅ | `P256Validator`(ERC-7579): 계정당 키 집합 add/remove(= 기기 등록/해지 `DeviceEnroll/DeviceRevoke`), P256VERIFY + Daimo 폴백, low-s 강제; Kernel 설치·해지 스크립트 (ADR-0006) | 등록 기기 키로 UserOp 성공, 해지 후 AA24, T12/T22/T23 테스트 (2026-09-19: `contracts/src/P256Validator.sol` + 단위 16종, Base Sepolia 포크 통합 4종 — 실제 Kernel v3.1 팩토리로 계정 생성 후 기기 키 UserOp 성공 216,221 gas, 폰 등록→노트북 해지→해지 기기 AA24, 재전송 AA25) |

### 1.4 Relay (R)
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.R.1 ✅ | Relay 프로토콜 정의(`AccessRequest/GrantMsg/Revoke`, CBOR over HTTPS+WebSocket) | 스키마 문서 (2026-09-19: `docs/specs/relay_protocol.md` v1 — 엔드포인트 7개, `Signed<T>` 서명 봉투(kind 바인딩·ts·nonce), 메시지 8종, 오류 9종↔HTTP, 할당량·프라이버시·셀프호스팅. 실행 가능한 스키마로 `crates/zbacs-proto` 신설, 테스트 14종) |
| Z-1.R.2 ✅ | axum 서버: 큐, 기기 등록, 서명 검증, 레이트리밋 | 부하 테스트 100 req/s (2026-09-20: `apps/relay` — 엔드포인트 7개, 인증 순서(형식→크기→서명자→할당량→재전송)로 미등록 기기가 남의 할당량을 못 쓰고 나쁜 서명이 nonce를 태우지 못함, 요청 nonce로 답장 라우팅(소유자가 수신자를 말할 필요 없음), 24h 큐·5분 nonce·기기당 30/분. 테스트 16종. **실측 12,816 req/s**(release, DoD의 128배). CI perf 게이트가 `#[ignore]` 테스트를 건너뛰어 사실상 비어 있던 것도 함께 수정) |
| Z-1.R.3 | 푸시 연동: FCM(승인 앱), ntfy 폴백 | 푸시 도달 ≤ 10s |
| Z-1.R.4 ✅ | Docker 이미지, 셀프호스팅 문서 | `docker compose up` (2026-09-23: `apps/relay/Dockerfile` 멀티스테이지(rust 빌더 → debian-slim + 바이너리, 비특권 사용자, HEALTHCHECK `/v1/health`), 루트 `docker-compose.yml`(read_only, no-new-privileges), `docs/relay_selfhost.md`(빠른 시작·TLS(Caddy)·Agent 연결·운영 값·무료 호스팅 4곳). CI `relay-image` 잡이 이미지를 빌드해 health 스모크. 호스팅 계정은 사용자 결정 대기) |
| Z-1.R.5 ✅ | `zbacs-relay-client` 크레이트 | 재연결·재시도 (2026-09-20: 엔드포인트 장애 조치(T21), 지수 백오프+지터, **같은 바이트로 재시도**해 중복 큐잉을 구조적으로 차단(재전송 응답=이미 전달됨), 영구 거부는 즉시 반환·일시 거부만 재시도, 끊긴 Relay가 돌아오면 자동 복구, `poll_device_inbox`는 장애 중에도 죽지 않음. 실제 서버를 띄워 HTTP로 검증하는 테스트 10종) |

### 1.5 Agent (G)
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.G.1 ◐ | Tauri 앱 골격, 트레이, 단일 인스턴스, 파일 연결 | 설치 후 더블클릭 동작 (2026-09-21: `apps/agent` — 트레이(창 열기·종료, 창을 닫아도 상주), 단일 인스턴스(두 번째 더블클릭이 기존 창으로 전달), `.zbacs` 연결, 키 없이 헤더만 읽어 상태 표시. UI는 토큰만 사용(빌드 시 `tokens.css` 복사). **Linux 실측**: deb에 `Exec %U`·MIME 등록, 헤드리스 실행에서 첫 인자 수신과 두 번째 인스턴스 전달을 로그로 확인. 단위 4종. Windows 더블클릭 확인은 `docs/windows_checklist.md` §3. **2026-09-21 정정**: 웹뷰에 `capabilities/` 파일이 없어 `event.listen`이 거부되고 UI 시작 스크립트가 예외로 죽고 있었다 — 당시 증거는 백엔드 로그뿐이었고 웹뷰는 아무것도 받지 못했다. Z-1.G.2에서 `capabilities/default.json`(`core:event:default`만)을 추가해 고쳤고, 화면 전환을 로그로 남겨 같은 종류의 침묵을 다시 놓치지 않게 했다) |
| Z-1.G.2 ◐ | 온보딩 UI: 소유자 계정 생성, 승인 방식 선택(Z-1.U.7), 기기 등록 | 신규 사용자 3분 내 완료 (2026-09-21: 백엔드는 `zbacs-auth::setup`(루트 워크스페이스 = CI 대상), UI는 `apps/agent/ui` S1~S1d. **탭 2번**(시작하기 → 승인 방식)으로 기기 X25519/Ed25519·소유자 봉인/서명 키·승인 서명기를 만들고 기기 프로필(공개값만, 0600, 임시파일 rename)을 남긴다. 두 번째 실행은 같은 신원을 이어받는다(새 봉투 키를 만들면 어제 봉인한 파일이 안 열린다). 못 끝낸 것은 `Pending`으로 정직하게 돌려주고, 그중 **사용자가 알아야 할 둘**(보안 칩 없음·보관함 없음)만 화면에 띄운다. 테스트: setup 12종 + Agent 5종, 커버리지 91.7%. Linux 헤드리스에서 첫 화면 도달 확인(`screen: welcome`). **실제 Hello/TPM 2탭 확인은 `docs/windows_checklist.md` §3.5**) |
| Z-1.G.3 ✅ | Seal UI: 파일 선택/드래그, 정책 설정(기본 권한, TTL, 횟수) | `.zbacs` 생성 (2026-09-21: 화면 S3/S3b. 창 어디든 드롭 + [파일 고르기], 권한 2택, "고급"에 유효 시간·횟수 **프리셋**(숫자 입력 0). 백엔드 `apps/agent/src/seal.rs` — 잠그기 전에 경로를 먼저 검사해 폴더·빈 파일·이미 잠긴 파일·**이미 있는 결과 파일**을 이유와 함께 거절한다(덮어쓰면 이미 보낸 파일의 버전 체인이 깨진다). 통합 테스트로 **실제 왕복 확인**: 잠근 파일이 소유자 키로 다시 열리고 평문이 바이트 단위로 일치, 정책이 고른 그대로 들어가고, 원래 파일명이 컨테이너 안에서 읽히지 않는다(T13). 단위 5종 + 통합 2종) |
| Z-1.G.4 ✅ | 세션 상태머신(`zbacs-session`) 구현 | 상태 전이 테스트 (2026-09-19: `State`(Requested/Granted/Open/Resealing/Closed/Denied/Revoked/Failed) × `Event` → `Effect` 목록. 승인 창(T15)·회수(T20)·열람 횟수(T03)·ReadOnly 변경 폐기(T07)를 상태머신이 강제, 재시작 복구용 `Session::resume`, 테스트 18종) |
| Z-1.G.5 ◐ | 보호 작업공간: ACL 설정, 인덱싱·백업 제외 | ACL 검증 스크립트 (2026-09-19: `zbacs-session::Workspace` — 세션별 디렉터리, Unix 0700 검증 테스트, Windows는 `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED|TEMPORARY`(크로스 컴파일 통과). 남은 것: Windows 상속 ACL 제거(설치 단계)와 실기 ACL 검증 스크립트) |
| Z-1.G.6 ◐ | 열람 앱 실행 + PID 추적 + `notify` 저장 감지 | Word/메모장/PDF 3종 (2026-09-20: `zbacs-session::viewer` — 추적 실행(PID·생존 확인·정상 종료 요청은 SIGTERM/taskkill, 드롭 시 강제 종료)과 `SaveWatcher`(디렉터리 감시 + 디바운스: 평문 쓰기·**임시파일 rename**(Word 방식)·연속 쓰기 묶기·잠금파일 무시·삭제는 Vanished). 테스트 12종. **실제 3종 앱 확인은 Windows + Agent UI 이후** — `docs/windows_checklist.md` §4) |
| Z-1.G.7 ✅ | ReadOnly 모드: 읽기전용 속성, 변경 폐기 | 테스트 (2026-09-19: `mark_read_only`/`clear_read_only` + 쓰기 거부 확인, 상태머신이 ReadOnly 저장을 `DiscardChanges`로 처리하고 버전을 만들지 않음) |
| Z-1.G.8 ◐ | Edit 모드: 종료/TTL/revoke 시 재봉인, 안전 삭제 | 포렌식 스크립트 통과(T09) (2026-09-19: 상태머신의 Saved→Reseal→Resealed 흐름과 회수/만료 시 미봉인 변경 폐기, `Workspace::wipe`/`secure_delete`(0 덮어쓰기 후 삭제, 하드링크로 덮어쓰기 확인). 남은 것: Z-1.Q.2 디스크 포렌식 스크립트) |
| Z-1.G.9 ✅ | 승인 대기 UI, 거부/만료 처리 | UX 리뷰 (2026-09-21: `apps/agent` `request.rs` + S4 화면. 기기 등록→서명 요청→받은편지함 폴링→답 분류(파일·버전·기기·nonce 일치 검사, T05/T19)→세션 상태머신 구동. 120s 안내·300s 만료·취소·Relay 불통 처리. 실제 `zbacs-relay`를 띄운 통합 테스트 6종 + 단위 8종. 소유자 서명 검증은 `owner_signature_check` pending으로 표시 — Z-1.H.8/H.10) |
| Z-1.G.10 ✅ | 데스크톱 승인 UI(소유자가 PC에서 승인) — 패스키 프롬프트 + EIP-712 내용 표시 | T06 체크 (2026-09-22: `apps/agent` `approve.rs` + `ledger.rs` + S5 화면. 소유자 받은편지함 감시(3s) → 요청자 서명을 요청이 담은 키로 직접 검증(T05) → **로컬 잠금 기록**으로 파일명·정책 표시, 기록 없음/다른 버전이면 허락 불가(T06/T19) → [읽기만 허락][편집도 허락][거절] → EIP-712 digest(Solidity 벡터 일치)를 기기 서명기로 서명(T23 확인 정책) → DEK를 요청 기기 키로 재봉인(aad=grantId) → GrantMsg. 시나리오 B 왕복 통합 테스트 3종(두 SetupHost + 실제 Relay: 허락→Bob이 DEK 열고 복호화·서명 검증, 거절, 모르는 파일 허락 불가) + 단위 9종. 체인 기록은 Z-1.H.8) |
| Z-1.G.11 ✅ | 회수(Revoke) 기능 + 활성 세션 목록 | E2E (2026-09-22: 소유자 — 허락할 때 `sealed.json`에 기록, "내가 허락한 파일" 화면(남은 시간·[허락 거두기]) → Relay `Revoke` + 기록. Relay — revoke를 그 파일을 요청했던 모든 기기로 라우팅(이전엔 소유자 자신에게만 가던 버그 수정, T20 테스트). 수신자 — 허락 뒤에도 받은편지함을 계속 읽어 revoke면 `Revoked`, 만료면 `Closed`로 세션을 닫고 화면에 알림. 두 기기 통합 테스트: 회수 → 상대 세션 즉시 종료, 만료 자체 종료(T15). 체인 revoke는 Z-1.H.8) |
| Z-1.G.12 ◐ | 감사 로그 뷰어(체인 이벤트 조회) | 이벤트 5종 표시 (2026-09-22: `apps/agent` `audit.rs` + S10 화면 — 잠금·요청·허락·거절·거둠(+열람·만료·문제)을 append-only `audit.jsonl`에 기록하고 칩 필터·시간순으로 문장 표시. 파일명은 로컬 기록에서만(T06). **체인 이벤트 소스는 Z-1.H.8이 체인에 쓰기 시작해야 읽을 것이 생김** — `Source::Chain` 자리만 있고 개발 패널에 `chain_events` pending. 단위 4종) |
| Z-1.G.13 | 자동 업데이트(tauri-plugin-updater) | 서명된 업데이트 |

### 1.6 Approve App (P) — MVP는 데스크톱 승인(G.10)으로 대체 가능, 모바일은 1단계 후반
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.P.1 | 기술 선택 ADR(Tauri mobile vs React Native vs BSA Authenticator 위임) | ADR-0006 |
| Z-1.P.2 | 푸시 수신 → 요청 상세 표시 → 패스키/BSA 승인 → GrantMsg 생성 | Android 1대 E2E |

### 1.6b UX (U) — 최상위 원칙 집행
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.U.0 ◐ | 디자인 가이드 연결: 디자인 소스 보관(`docs/design/`), 토큰 코드 생성(`packages/design-tokens/` 완료 2026-09-19), 골격 가이드(`ui_guideline.md` 완료). 남은 것: Figma URL 연결 시 근사값 교체, Code Connect | 토큰 생성 ✅, 스크린샷 비교 1개 |
| Z-1.U.1 ✅ | 온보딩 흐름 설계: 설치 → 생체인증 1회 → 사용 시작. 계정(패스키 스마트계정)·기기키·Relay 등록 자동화, 입력 폼 0개 | 프로토타입 클릭 수 ≤ 3 (2026-09-21: 설계 = `ui_guideline.md` §5 S1~S1d, 구현 = Z-1.G.2. **탭 3번**(시작하기·승인 방식·내 파일 보기) 중 준비에 쓰이는 것은 2번. 입력 필드 0개를 `tools/ux-lint.sh`가 CI에서 강제. Relay 등록은 Z-1.R.2 배포 후 연결) |
| Z-1.U.2 ✅ | UI 문자열 사전 + 금지 용어 린트(`tools/ux-lint`) CI 통합 | U-5 통과 (2026-09-21: `docs/design/ui_strings.md`(쓰는 말/쓰지 않는 말 + 금지 용어 48개, 린트가 이 문서를 읽는다) + `tools/ux-lint.sh` + CI `ux` 잡. 검사 4종: 금지 용어(U-5), 텍스트 입력 0개(U-6), 토큰만 사용(규칙 8), JS가 참조하는 id·data-role이 마크업에 실제로 있는지. **일부러 위반을 넣어 네 검사가 모두 실패하는 것을 확인**했다. 한글이 든 줄만 보는 이유: 규칙 7이 주석·식별자를 영어로 못박으므로 한글 = 사용자에게 보이는 문구) |
| Z-1.U.3 ✅ | 봉인 다이얼로그 단순화: [읽기만] [편집 허용] + 보내기, 세부는 "고급" | U-1 (2026-09-21: 기본 화면은 파일 1개 + 버튼 2개 + [잠그기]. 유효 시간·횟수는 "고급" 뒤 프리셋이고 기본값(1시간·한 번·읽기만)으로 완결된다. 버튼이 "잠그고 보내기"가 아니라 **"잠그기"**인 이유는 전송을 앱이 하지 않기 때문 — `ui_guideline.md` §7. 결과 화면이 **"원본 파일은 그대로 남아 있어요"**를 말하고 2단계 확인 뒤 지울 수 있게 한다(T09): 잠갔다고 안심했는데 평문이 옆에 있으면 아무것도 지킨 게 아니다) |
| Z-1.U.4 ✅ | 오류 메시지 카탈로그: 모든 오류에 사용자 행동 안내 + 버튼 | 리뷰 (2026-09-23: `ui_strings.md` §7 카탈로그 27개 기계값 — 문장·화면·다음 행동 버튼. 백엔드 모듈마다 `*_PROBLEMS` 상수, `tests/errors.rs`가 백엔드↔app.js↔카탈로그 삼각 검사, `ux-lint.sh` §5가 카탈로그↔app.js 검사. 파일 카드의 한글 문장 3개를 기계값(`not_sealed`/`newer_version`/`missing`/`damaged`)으로 바꾸고 버튼([이 파일 잠그기]/[목록에서 지우기]) 부여) |
| Z-1.U.5 ◐ | 승인 알림 액션 버튼(Windows 토스트, 모바일 푸시) | U-3 (2026-09-23: `apps/agent` `notify.rs` — 요청 도착 시 데스크톱 알림. Windows: 토스트에 [읽기만 허락][편집도 허락][거절][앱에서 보기] 버튼(`tauri-winrt-notification`), 누르면 화면과 **같은** `decide` 경로(OS 확인 포함, T23) → 결과 토스트. 다른 OS: 버튼 없는 알림 + "앱에서 답해 주세요". 문구·버튼은 `Plan` 값으로 분리해 단위 4종(U-3, T06). **Windows 토스트 실기 확인은 `windows_checklist.md` §3.11** — AUMID/바로가기 조건. 모바일 푸시는 P 트랙(베타 제외)) |
| Z-1.U.6 | 사용성 테스트 라운드 1 (외부 참가자 5명, 설명 없이 U-1~U-4) | 성공률 ≥ 80% |
| Z-1.U.7 ◐ | 승인 방식 선택 UI: 온보딩 1화면 "얼굴/지문으로 확인하고 승인" / "이 기기에서 바로 승인", "내 기기"에서 변경·해지. 텍스트 입력 0, 기술 용어 0. **Figma에 화면 먼저 추가** (ADR-0006) | U-1, 용어 린트 통과 (2026-09-21: 온보딩 화면 S1b 구현, 용어 린트 통과. 기기가 못 하는 방식은 **버튼 자체가 비활성 + 이유 한 줄**이고, 백엔드도 그 방식을 거부한다(`Unsupported`). 기본 선택은 ADR-0006대로 OS 인증기가 있으면 생체. 남은 것: "내 기기"에서 변경·해지(Z-1.G.11 + Z-1.H.10), Figma 연결 시 화면 등록(Z-1.U.0)) |
| Z-1.S.1 | **(Phase 2에서 이동)** `zbacs-stub` Windows 자체실행 래퍼: Agent 감지·무인 설치·핸드오프 | U-2 통과 |
| Z-1.S.2 | **(Phase 2에서 이동)** EV 코드 서명, SmartScreen 평판 | 경고 없음 |
| Z-1.S.3 ✅ | **(신설 2026-09-21, beta_test_automation L1)** 설치 파일 CI: `release.yml`이 windows-latest에서 NSIS 설치 파일 + `zbacs-wincheck.exe`를 빌드해 아티팩트로 올리고 `v*` 태그면 GitHub Release 생성. 테스터는 다운로드·더블클릭만 | 설치 파일 1개로 `windows_checklist.md` §1~§3 수행 가능 (2026-09-21 첫 실행 성공 10분: `Z-BACS_0.0.1_x64-setup.exe` 2.4MB, `zbacs-wincheck.exe` 363KB, SHA256SUMS) |

### 1.7 Security/QA (Q)
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.Q.1 | E2E 테스트 하네스: Windows VM 2대 + Anvil + Relay 도커 | 시나리오 A~E 자동화 |
| Z-1.Q.2 | 평문 잔존 포렌식 스크립트(디스크 문자열 검색) | CI 야간 실행 |
| Z-1.Q.3 | 위협 T01~T20 대응 테스트 매핑 및 실행 | 100% 매핑 |
| Z-1.Q.4 | 의존성 감사(`cargo audit`, `npm audit`), SBOM | CI |

### 1.8 Docs (D)
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.D.1 | 사용자 가이드(봉인·열람·승인) | docs/user_guide.md |
| Z-1.D.2 | ADR 갱신, API 문서(`cargo doc`) | 링크 정상 |

**Phase 1 종료 기준**: project_definition §10 MVP DoD 5항목 + ux_principles.md UX DoD U-1~U-6 충족.

### 1.9 베타 컷 — "두 대에서 A~E가 돈다"까지 남은 것 (2026-09-21 기준)

Phase 1 전체(59태스크) 중 **24 완료, 10 진행중(◐), 25 미착수**. 하지만 *닫힌 베타*(참가자가 Agent를 직접 설치하는 소규모 테스트)에 필요한 것은 그보다 적다. 아래가 그 최소 집합이고, 나머지는 베타 **이후**로 미룰 수 있다.

**베타에 반드시 필요한 것 (코드)**

| 순서 | 태스크 | 왜 필요한가 |
|---|---|---|
| ~~1~~ ✅ | ~~`Z-1.H.4` 배포 스크립트~~ | 2026-09-21 완료 |
| ~~2~~ ✅ | ~~`Z-1.G.9` 열람 요청 UI~~ | 2026-09-21 완료 |
| ~~3~~ ✅ | ~~`Z-1.G.10` 데스크톱 승인 UI~~ | 2026-09-22 완료. 모바일 승인 앱(Z-1.P.2) 없이 베타 가능 |
| ~~4~~ ✅ | ~~`Z-1.G.11` 회수 + 활성 세션~~ | 2026-09-22 완료 |
| ~~5~~ ◐ | ~~`Z-1.G.12` 감사 로그 뷰어~~ | 2026-09-22 로컬 기록 완료. 체인 이벤트 병합은 Z-1.H.8 뒤 |
| ~~6~~ ✅ | ~~`Z-1.U.4` 오류 카탈로그~~ | 2026-09-23 완료 |
| ~~7~~ ◐ | ~~`Z-1.U.5` 알림 액션 버튼~~ | 2026-09-23 코드 완료. Windows 토스트 버튼 실기 확인만 남음(§3.11) |
| ~~8~~ ✅ | ~~`Z-1.R.4` Docker~~ | 2026-09-23 완료. 실제 호스팅(계정)은 사용자 차례 — `docs/relay_selfhost.md` §5 |
| 9 | `Z-1.Q.2` 포렌식 스크립트 | MVP DoD 4(평문 잔존 없음) |
| 10 | `Z-1.Q.1` E2E 하네스 | A~E를 **주장이 아니라 검사**로 만든다 |

**베타에 반드시 필요한 것 (사용자만 할 수 있는 일)**

| | 막고 있는 태스크 |
|---|---|
| Windows 실기 확인 (`docs/windows_checklist.md` §1~§4) | `Z-1.A.2` `Z-1.A.3` `Z-1.A.7` `Z-0.G.1` `Z-1.G.1` `Z-1.G.2` `Z-1.G.5` `Z-1.G.6` — 전부 코드는 끝났고 **실기 확인만** 남은 ◐ |

실기 확인에 `cargo`가 필요 없도록 `Z-1.S.3`이 설치 파일과 `zbacs-wincheck.exe`를 CI에서 만든다(Actions → release → Artifacts). 자동화 층별 계획은 [beta_test_automation.md](beta_test_automation.md).

이것이 **일정상 가장 큰 단일 리스크**다. Windows 우선 제품인데 개발 환경이 Linux여서, TPM·Hello·레지스트리·실제 열람 앱은 CI로도 크로스컴파일로도 대신할 수 없다.

**베타 이후로 미루는 것**

| 태스크 | 미루는 이유 |
|---|---|
| `Z-1.S.1` 자체실행 스텁 | U-2(수신자 무설치)는 공개 배포에 필요. 닫힌 베타는 참가자가 설치하면 된다 |
| `Z-1.S.2` EV 코드 서명 | 조직 명의·비용이 필요. 개인 프로젝트 방침상 보류(SmartScreen 경고는 베타에서 감수) |
| `Z-1.H.8` chain-ts, `Z-1.P.1/P.2` 모바일 승인 | 데스크톱 승인(G.10)이 베타를 커버한다 |
| `Z-1.H.9` 페이마스터 | 로컬 Anvil이나 테스트넷 faucet으로 베타 가능. "가스를 모르는 사용자" 목표에는 정식 출시 전 필요 |
| `Z-1.H.5/H.6` Slither·AI 감사, `Z-1.Q.3/Q.4` | 품질 게이트. 베타 참가자에게 보이지 않는다 |
| `Z-1.U.6` 사용성 테스트 | 베타 그 자체가 이 테스트다 |
| `Z-1.D.1/D.2` 문서 | 베타 직전에 |

**속도 근거**: Phase 1의 완료 태스크가 2026-09-19~21 사이 세션에서 나왔다(커밋 47). 남은 베타 코드 10태스크는 같은 밀도로 **2~3 세션 분량**이다. 다만 위 Windows 확인이 끝나기 전에는 "베타 가능"은 검사된 사실이 아니라 주장이다.

---

## Phase 2 — 배포성·크로스플랫폼·복구 (목표 8주)

| ID | 태스크 | DoD |
|---|---|---|
| Z-2.U.1 | 복구 UX: "내 기기" 목록, 기기 추가·복구 코드 한 번 제안 | U 테스트 |
| Z-2.U.2 | 사용성 테스트 라운드 2 (macOS/Linux 포함) | 성공률 ≥ 90% |
| Z-2.S.3 | NSIS 설치기 다듬기, 무인 설치 옵션 | |
| Z-2.G.1 | macOS Agent(Secure Enclave 패스키, 파일 연결, notarization) | 시나리오 A~E |
| Z-2.G.2 | Linux Agent(libfido2/TPM2, AppImage) | 시나리오 A~E |
| Z-2.G.3 | Dokan 가상 드라이브 모드(평문 디스크 미기록) 스파이크·구현 | T10 완화 |
| Z-2.G.4 | 워터마크(뷰어 내장 PDF/이미지) | |
| Z-2.A.1 | 다중 기기 등록·해지, 소셜 복구(Shamir 2-of-3) | T12 |
| Z-2.R.1 | Relay hint 암호화, libp2p/WebRTC 직접 전송 옵션 | |
| Z-2.H.1 | Base 메인넷 배포, 모니터링, 타임락 운영 | |
| Z-2.P.1 | iOS 승인 앱 | |
| Z-2.Q.1 | 외부 침투 테스트 1회 | 리포트 및 수정 |

---

## Phase 3 — 엔터프라이즈·탈중앙 위임·프라이버시 (목표 12주+)

| ID | 태스크 | DoD |
|---|---|---|
| Z-3.H.1 | 오프라인 위임 ADR 확정: umbral-pre Guardian 노드 vs Lit v8 (OR-5, OR-6) | ADR-0004 갱신 |
| Z-3.H.2 | Guardian 노드(`zbacs-guardian`) 또는 Lit Action 구현: 정책 조건 만족 시 재암호화 | 소유자 오프라인 E2E |
| Z-3.Z.1 | Semaphore 그룹 멤버십 증명으로 요청자 익명화 | 온체인 검증 가스 측정 |
| Z-3.Z.2 | 파일·소유자 커밋 은닉 강화, ZK 감사 증명 | |
| Z-3.G.1 | Windows 미니필터 DRM 모드(EaseFilter 또는 자체) — 허용 프로세스 외 접근 차단, 저장 시 강제 암호화 | T07 차단 |
| Z-3.G.2 | TEE/VBS 엔클레이브에서 DEK 처리 검토 | T11 |
| Z-3.A.1 | BSA 정식 계약·통합, X.1284 준수 검증 | 인증 마케팅 자료 |
| Z-3.H.3 | 원격 어테스테이션(Agent 무결성) | T20 |
| Z-3.Q.1 | CC/ISO 27001 대응 문서화 | |

---

## 부록 A. 위협 → 태스크 매핑 (Z-0.Q.1 리뷰 2026-09-19)

규칙: 위협마다 **완화 태스크**(구현)와 **현재 근거**(T-ID를 이름에 단 테스트·스파이크)를 유지한다. 새 위협을 추가하면 이 표와 `threat_model.md`를 같은 커밋에서 갱신한다. 태스크 ID가 이동하면 여기도 고친다.

| 위협 | 완화 태스크 | 현재 근거 (Phase 0) |
|---|---|---|
| T01 무차별 대입 | Z-1.C.1 (난수 DEK, 비밀번호 파생 없음) | `zbacs-core` DEK = OsRng 32B |
| T02 헤더 정책 변조 | Z-1.C.5 (정책 해시), Z-1.H.1 (온체인 커밋), Z-1.G.4 (양쪽 비교) | core `t02_header_tamper_policy_is_detected`, malicious `t02_10/11/12` |
| T03 티켓 재전송 | Z-1.H.2 (nonce·chainId), Z-1.R.1 (요청 nonce), Z-1.G.4 (세션 1회 소비), Z-1.A.6 (일회용 키 폐기) | contracts `test_t03_*` 3종, aa-passkey `test_t03_replay_rejected`, auth `t03_replay_is_refused_by_signer_and_verifier`, session `t03_*` |
| T04 Relay DEK 탈취 | Z-1.C.1 (HPKE 봉투 정식화), Z-1.R.2 (Relay는 암호문만) | core `t04_wrong_key_cannot_open`, `extra_recipient_envelope_opens` |
| T05 요청자 바꿔치기 | Z-1.A.3 (기기 키), Z-1.R.1 (요청 서명·devicePub 해시), Z-1.R.2 (서명자≠요청자 거부), Z-1.H.2 (티켓에 deviceKid), Z-1.G.9 (답의 deviceKeyHash·nonce 검사) | agent `t05_*` 2종 · proto `t05_*` 2종; relay `t05_a_request_about_another_device_is_refused`|
| T06 승인 피싱 | Z-1.G.10, Z-1.P.2 (EIP-712 구조화 표시), Z-1.U.5 (알림 액션에 파일·권한 표시) | contracts EIP-712 타입 해시 벡터, agent `t06_the_screen_shows_the_record_not_the_request`, `t06_a_file_this_machine_did_not_lock_cannot_be_allowed` |
| T07 승인 후 평문 복사 | Z-1.G.5/7 (ACL·읽기전용), Z-1.H.3 + Z-1.G.12 (감사 로그), Z-2.G.4 (워터마크), Z-3.G.1 (미니필터) | session `t07_read_only_marking_blocks_writes`, `workspace_is_private_*`; contracts `AuditLog.t.sol` 5종 agent `audit.rs` 로컬 기록(잠금·요청·허락·거절·거둠) |
| T08 화면 촬영 | 범위 밖(명시). 추적성만: Z-2.G.4 | — |
| T09 평문 잔존 | Z-1.G.8 (재봉인·안전 삭제), Z-1.Q.2 (포렌식 CI), Z-2.G.3 (가상 드라이브) | session `t09_wipe_overwrites_and_removes_everything`, `t09_secure_delete_overwrites_before_unlinking` |
| T10 앱 임시파일 | Z-1.G.6 (경로 고정·저장 감지), Z-1.G.8 (앱별 잔존 청소), Z-2.G.3 | session `a_temp_and_rename_save_is_detected`, `other_files_in_the_workspace_are_ignored` |
| T11 메모리 덤프 | Z-1.C.6 (zeroize·secrecy), Z-1.A.3 (DPAPI), Z-3.G.2 (TEE/VBS) | core `t11_key_types_zeroize_on_drop_and_redact_in_logs`; 감사 `research/key_hygiene_audit.md` |
| T12 소유자 기기 분실 | Z-1.A.4 (암호화 백업·복구 코드), Z-1.H.10 (다른 기기에서 해지), Z-2.A.1 (다중 기기·소셜 복구), Z-2.U.1 (복구 UX) | contracts `test_t12_*` 3종; 포크 `test_t12_enroll_second_device_then_revoke_first`; core `backup.rs` 9종 |
| T13 온체인 식별 | Z-1.C.5 (fileId 솔트, 파일명 길이 패딩), Z-1.H.9 (페이마스터), Z-3.Z.1/2 (ZK) | contracts fileId = H(hash‖salt); core `name_padding_hides_length_and_roundtrips` |
| T14 컨트랙트 검증 우회 | Z-1.H.2 (EIP-712·ERC-1271·low-s), Z-1.H.5 (Slither/Echidna), Z-1.H.6 (HF 감사), Z-1.H.8 (WebAuthn 서명 인코딩) | contracts `test_t14_*` 3종, aa-passkey `test_t14_tampered_signature_rejected`, proto `t14_struct_hash_matches_the_solidity_vector` |
| T15 만료 우회 | Z-1.H.2 (체인 시간), Z-1.G.4 (로컬 시계 병행) | contracts `test_t15_*` 2종, agent `t15_an_expired_grant_closes_the_session_on_its_own` |
| T16 Relay DoS | Z-1.R.1 (본문 상한·할당량 정의), Z-1.R.2 (서명·레이트리밋), Z-1.R.4 (셀프호스팅), Z-1.H.7 (체인 이벤트 폴백 — 구현됨), Z-2.R.1 | proto `oversized_bodies_are_refused_on_both_sides`; relay `t16_quota_stops_a_flood`, `an_oversized_body_is_refused` |
| T17 스텁 위장 | Z-1.S.1/S.2 (코드 서명·해시 고정), Z-1.C.2 (Agent는 컨테이너만 파싱), Z-1.G.13 (서명된 업데이트) | tauri-assoc: 파일 인자를 경로로만 취급, `inspect`만 수행 |
| T18 파서 취약점 | Z-1.C.2 (길이 상한·악성 입력 20종), Z-1.C.3 (cargo-fuzz) | core `tests/malicious.rs` 31종; 퍼징 24h 420,679,318회 무크래시 |
| T19 다운그레이드 | Z-1.C.2 (버전 검사·최소 버전 정책), Z-1.C.4 (`verify_version_chain`), Z-1.H.2 (온체인 버전 바인딩) | core `t19_*`; reseal `t19_*` 3종; contracts `test_t19_grant_must_name_the_current_version`, agent `t19_a_grant_for_another_version_is_refused` |
| T20 회수 무시 | Z-1.C.4 (재봉인 시 새 DEK), Z-1.G.4 (TTL·주기 확인), Z-1.G.11 (revoke), Z-1.H.7 (이벤트 구독), Z-1.G.13 (코드 서명), Z-3.H.3 (어테스테이션) | contracts `test_t20_revoke_only_owner`; core `t20_each_version_*`; session `t20_revoke_*`; chain `t20_the_watcher_sees_a_revoke_without_the_relay`, `t20_a_revoked_grant_is_never_resurrected_by_the_cache`, relay `t20_revocations_reach_the_devices_that_asked`, agent `t20_*` 2종 + `scenario_e_alice_revokes_and_bobs_session_ends` |
| T21 번들러·페이마스터 검열/지연 | Z-1.H.8 (다중 번들러 엔드포인트), Z-1.H.9 (페이마스터 폴백: 자체 예치), Z-1.G.4 (`strict_onchain` 아닌 경우 체인 확정 미대기), Z-1.R.5 (다중 Relay 장애 조치) | aa-passkey: EntryPoint 직접 `handleOps` + Pimlico 실제 제출; client `t21_a_dead_endpoint_falls_over_to_a_live_one` |
| T22 동기화 패스키 복제 | Z-1.A.2 (BE/BS 플래그 기록·정책), Z-1.A.7 (기기 바운드 키 대안), Z-1.H.10 (등록·해지 온체인), Z-1.U.7 (선택 UI) | auth `t22_synced_passkey_flags_detected`; contracts `test_t22_keys_are_scoped_to_the_enrolling_account` |
| T23 무프롬프트 기기 키 남용 | Z-1.A.7 (OS 확인 옵션·속도 제한), Z-1.G.10 (명시적 탭에만 키 사용), Z-1.H.10 (즉시 해지), Z-3.G.2 (VBS) | auth `t23_*` 2종; contracts `requireOsConfirm` 온체인 기록, agent `approve::answer`가 `ConfirmationPolicy::required` 적용 |

## 부록 B. 마일스톤 요약

| 마일스톤 | 시점(누적) | 내용 |
|---|---|---|
| M0 | 2주 | 스파이크 완료, 아키텍처 확정 |
| M1 | 6주 | Core+Auth+Chain 통합(CLI로 시나리오 A~E) |
| M2 | 12주 | Windows Agent MVP, 내부 알파 |
| M3 | 20주 | 자체실행 래퍼, macOS/Linux, 복구, 베타 |
| M4 | 32주+ | PRE/ZK/DRM 엔터프라이즈 |

## 부록 C. 작업 방식
- 각 태스크는 브랜치 `feat/Z-x.y.z-slug`, PR 템플릿에 DoD 체크리스트.
- 문서 변경은 코드 변경과 같은 PR에 포함(스펙 우선 원칙).
- 매 Phase 종료 시 `docs/`의 모든 문서 버전 갱신 + 회고.
