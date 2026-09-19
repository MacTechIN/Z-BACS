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
| Z-0.A.3 | BSA 샌드박스 Client Key 신청(OR-1), SDK 문서 수령·요약 | research §1.1 | `docs/research/bsa_sdk_notes.md` | API 흐름 문서화 |
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
| Z-1.C.3 ◐ | `cargo-fuzz` 타깃(header, chunk) | 24h 퍼징 무크래시 (2026-09-19: 타깃 4종 `header`/`header_signed`/`open_mutated`/`envelope` + `tools/fuzz.sh` + 야간 CI `fuzz.yml`. 스모크 150s×4 = 약 300만 실행 무크래시, cov 966 edges. **24h 실행은 `tools/fuzz.sh 24h`로 사용자 머신에서** — 완료 시 ✅) |
| Z-1.C.4 ✅ | 재봉인(Reseal): 새 DEK, 버전 체인, 원자적 교체 | v1→v2→v3 체인 검증 테스트 (2026-09-19: spec §5 확장 — `fid`/`salt` 버전 불변(온체인 `bumpVersion` 키), 체인 규칙, 원자 교체, 새 DEK로 이전 승인 무효화(T20). `PrevVersion`, `reseal_to_path`, `verify_version_chain`, `decrypt_name`, CLI `zbacs reseal`; 테스트 10종) |
| Z-1.C.5 ✅ | 파일명 암호화, 정책 해시, 테스트 벡터 고정 | vectors 디렉터리 (2026-09-19: spec v1.2 — 파일명 64B 배수 패딩(길이 노출 차단, T13) + §2.2a `policy_hash = SHA-256("ZBACS-POL-v1"‖CBOR(pol))`; `crates/zbacs-core/tests/vectors/`(v1/v2 컨테이너·소유자 키·manifest) 고정 + 회귀 테스트 2종, 재생성은 `--ignored regenerate`) |
| Z-1.C.6 ✅ | 키 자료 zeroize 감사, `secrecy` 적용 | 리뷰 체크리스트 통과 (2026-09-19: `Dek`을 `secrecy::SecretBox`로 전환, 모든 키 타입에 마스킹 `Debug`, seal/open/파일명 평문 버퍼 wipe, `ZeroizeOnDrop` 컴파일 타임 단언, 감사 기록 `docs/research/key_hygiene_audit.md`) |

### 1.2 Auth (A)
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.A.1 ✅ | `AuthProvider` 트레이트 + `ApprovalChallenge/Assertion` 타입 | 문서화 (2026-09-19: `crates/zbacs-auth` — 두 서명 경로 타입, `ConfirmationPolicy`(T23), `verify_assertion`(low-s·UP/UV·challenge), `DeviceEnroll/Revoke` 다이제스트, 소프트웨어 서명기, 12 tests incl. JS 스파이크 교차 벡터) |
| Z-1.A.2 | `PasskeyProvider(Windows)` 구현 — 승인 서명 경로 A(플랫폼 패스키, ADR-0006) | 등록·승인 E2E |
| Z-1.A.7 | `DeviceKeyProvider` — 승인 서명 경로 B: TPM(Windows CNG Platform Crypto Provider)/Android Keystore/Secure Enclave에 내보내기 불가 P-256 키 생성, raw 서명, 기기별 OS 확인 옵션 (ADR-0006) | Windows TPM 키 생성·서명, 내보내기 불가 확인, 재부팅 후 사용, T23 정책 테스트 |
| Z-1.A.3 | 기기 키(X25519/Ed25519) 생성 + DPAPI/keyring 보관 | 재부팅 후 복원 |
| Z-1.A.4 | 소유자 봉인키 생성·보관·암호화 백업 파일 내보내기 | 백업 복원 테스트 |
| Z-1.A.5 | `BsaProvider` 골격 (SDK 확보 시 연결, 미확보 시 mock) | 인터페이스 호환 테스트 |
| Z-1.A.6 | `OtakProvider` 최소 구현(X.1284 흐름: 요청별 키 파생·폐기) | 재전송 테스트 |

### 1.3 Chain (H)
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.H.1 ✅ | `FileRegistry.sol` (register/bumpVersion/retire) + 테스트 | 100% 브랜치 (2026-09-19: `retire`·`currentVersion`·동일 헤더 해시 거부 추가, `forge coverage` 라인·구문·브랜치·함수 **100%**) |
| Z-1.H.2 ✅ | `AccessPolicy.sol` (grant/revoke/isValid, EIP-712, ERC-1271 지원) | 재전송·만료·회수 테스트 (2026-09-19: T19 버전 바인딩(옛 헤더 해시 거부)·retire 차단·`consumeOpen`을 기기 공개키에 바인딩·grant 레코드에 deviceKeyHash/headerHash 저장, 22 tests, 브랜치 100%) |
| Z-1.H.3 ✅ | `AuditLog.sol` 이벤트 계약 | 가스 ≤ 30k/log (2026-09-19: 이벤트 전용 `Logged(fileId, kind, reporter, actorCommit, detail)`, 실제 Anvil 트랜잭션 **25,515 gas** — `tools/chain-demo.sh`가 매번 실측·검사. 초안의 레지스트리 조회(~4.7k)는 31,030으로 예산 초과라 제거) |
| Z-1.H.4 | UUPS 프록시 + Timelock 배포 스크립트(Anvil, Base Sepolia) | 주소 파일 생성 |
| Z-1.H.5 | Slither + Echidna 불변식 CI | CI 게이트 |
| Z-1.H.6 | HF 감사 파이프라인(`tools/audit`): Qwen3-Coder-Audit 로컬/원격 추론 → PR 코멘트 | 샘플 PR 리포트 |
| Z-1.H.7 | `zbacs-chain`(alloy): ABI 바인딩, 이벤트 구독, 오프라인 캐시 | 통합 테스트(Anvil) |
| Z-1.H.8 | `packages/chain-ts`: viem 타입, EIP-712 서명 헬퍼, permissionless 계정 생성 | 승인 앱에서 사용 |
| Z-1.H.9 | 페이마스터 설정(Pimlico 샌드박스) | 가스 0 UserOp |
| Z-1.H.10 ✅ | `P256Validator`(ERC-7579): 계정당 키 집합 add/remove(= 기기 등록/해지 `DeviceEnroll/DeviceRevoke`), P256VERIFY + Daimo 폴백, low-s 강제; Kernel 설치·해지 스크립트 (ADR-0006) | 등록 기기 키로 UserOp 성공, 해지 후 AA24, T12/T22/T23 테스트 (2026-09-19: `contracts/src/P256Validator.sol` + 단위 16종, Base Sepolia 포크 통합 4종 — 실제 Kernel v3.1 팩토리로 계정 생성 후 기기 키 UserOp 성공 216,221 gas, 폰 등록→노트북 해지→해지 기기 AA24, 재전송 AA25) |

### 1.4 Relay (R)
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.R.1 ✅ | Relay 프로토콜 정의(`AccessRequest/GrantMsg/Revoke`, CBOR over HTTPS+WebSocket) | 스키마 문서 (2026-09-19: `docs/specs/relay_protocol.md` v1 — 엔드포인트 7개, `Signed<T>` 서명 봉투(kind 바인딩·ts·nonce), 메시지 8종, 오류 9종↔HTTP, 할당량·프라이버시·셀프호스팅. 실행 가능한 스키마로 `crates/zbacs-proto` 신설, 테스트 14종) |
| Z-1.R.2 | axum 서버: 큐, 기기 등록, 서명 검증, 레이트리밋 | 부하 테스트 100 req/s |
| Z-1.R.3 | 푸시 연동: FCM(승인 앱), ntfy 폴백 | 푸시 도달 ≤ 10s |
| Z-1.R.4 | Docker 이미지, 셀프호스팅 문서 | `docker compose up` |
| Z-1.R.5 | `zbacs-relay-client` 크레이트 | 재연결·재시도 |

### 1.5 Agent (G)
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.G.1 | Tauri 앱 골격, 트레이, 단일 인스턴스, 파일 연결 | 설치 후 더블클릭 동작 |
| Z-1.G.2 | 온보딩 UI: 소유자 계정 생성, 승인 방식 선택(Z-1.U.7), 기기 등록 | 신규 사용자 3분 내 완료 |
| Z-1.G.3 | Seal UI: 파일 선택/드래그, 정책 설정(기본 권한, TTL, 횟수) | `.zbacs` 생성 |
| Z-1.G.4 | 세션 상태머신(`zbacs-session`) 구현 | 상태 전이 테스트 |
| Z-1.G.5 | 보호 작업공간: ACL 설정, 인덱싱·백업 제외 | ACL 검증 스크립트 |
| Z-1.G.6 | 열람 앱 실행 + PID 추적 + `notify` 저장 감지 | Word/메모장/PDF 3종 |
| Z-1.G.7 | ReadOnly 모드: 읽기전용 속성, 변경 폐기 | 테스트 |
| Z-1.G.8 | Edit 모드: 종료/TTL/revoke 시 재봉인, 안전 삭제 | 포렌식 스크립트 통과(T09) |
| Z-1.G.9 | 승인 대기 UI, 거부/만료 처리 | UX 리뷰 |
| Z-1.G.10 | 데스크톱 승인 UI(소유자가 PC에서 승인) — 패스키 프롬프트 + EIP-712 내용 표시 | T06 체크 |
| Z-1.G.11 | 회수(Revoke) 기능 + 활성 세션 목록 | E2E |
| Z-1.G.12 | 감사 로그 뷰어(체인 이벤트 조회) | 이벤트 5종 표시 |
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
| Z-1.U.1 | 온보딩 흐름 설계: 설치 → 생체인증 1회 → 사용 시작. 계정(패스키 스마트계정)·기기키·Relay 등록 자동화, 입력 폼 0개 | 프로토타입 클릭 수 ≤ 3 |
| Z-1.U.2 | UI 문자열 사전 + 금지 용어 린트(`tools/ux-lint`) CI 통합 | U-5 통과 |
| Z-1.U.3 | 봉인 다이얼로그 단순화: [읽기만] [편집 허용] + 보내기, 세부는 "고급" | U-1 |
| Z-1.U.4 | 오류 메시지 카탈로그: 모든 오류에 사용자 행동 안내 + 버튼 | 리뷰 |
| Z-1.U.5 | 승인 알림 액션 버튼(Windows 토스트, 모바일 푸시) | U-3 |
| Z-1.U.6 | 사용성 테스트 라운드 1 (외부 참가자 5명, 설명 없이 U-1~U-4) | 성공률 ≥ 80% |
| Z-1.U.7 | 승인 방식 선택 UI: 온보딩 1화면 "얼굴/지문으로 확인하고 승인" / "이 기기에서 바로 승인", "내 기기"에서 변경·해지. 텍스트 입력 0, 기술 용어 0. **Figma에 화면 먼저 추가** (ADR-0006) | U-1, 용어 린트 통과 |
| Z-1.S.1 | **(Phase 2에서 이동)** `zbacs-stub` Windows 자체실행 래퍼: Agent 감지·무인 설치·핸드오프 | U-2 통과 |
| Z-1.S.2 | **(Phase 2에서 이동)** EV 코드 서명, SmartScreen 평판 | 경고 없음 |

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
| T03 티켓 재전송 | Z-1.H.2 (nonce·chainId), Z-1.R.1 (요청 nonce), Z-1.G.4 (세션 1회 소비) | contracts `test_t03_*` 3종, aa-passkey `test_t03_replay_rejected` |
| T04 Relay DEK 탈취 | Z-1.C.1 (HPKE 봉투 정식화), Z-1.R.2 (Relay는 암호문만) | core `t04_wrong_key_cannot_open`, `extra_recipient_envelope_opens` |
| T05 요청자 바꿔치기 | Z-1.A.3 (기기 키), Z-1.R.1 (요청 서명·devicePub 해시), Z-1.H.2 (티켓에 deviceKid) | proto `t05_*` 2종 |
| T06 승인 피싱 | Z-1.G.10, Z-1.P.2 (EIP-712 구조화 표시), Z-1.U.5 (알림 액션에 파일·권한 표시) | contracts EIP-712 타입 해시 벡터 |
| T07 승인 후 평문 복사 | Z-1.G.5/7 (ACL·읽기전용), Z-1.H.3 + Z-1.G.12 (감사 로그), Z-2.G.4 (워터마크), Z-3.G.1 (미니필터) | contracts `AuditLog.t.sol` 5종; `tools/chain-demo.sh` 가스 예산 검사 |
| T08 화면 촬영 | 범위 밖(명시). 추적성만: Z-2.G.4 | — |
| T09 평문 잔존 | Z-1.G.8 (재봉인·안전 삭제), Z-1.Q.2 (포렌식 CI), Z-2.G.3 (가상 드라이브) | — |
| T10 앱 임시파일 | Z-1.G.6 (경로 고정·저장 감지), Z-1.G.8 (앱별 잔존 청소), Z-2.G.3 | — |
| T11 메모리 덤프 | Z-1.C.6 (zeroize·secrecy), Z-1.A.3 (DPAPI), Z-3.G.2 (TEE/VBS) | core `t11_key_types_zeroize_on_drop_and_redact_in_logs`; 감사 `research/key_hygiene_audit.md` |
| T12 소유자 기기 분실 | Z-1.A.4 (암호화 백업), Z-1.H.10 (다른 기기에서 해지), Z-2.A.1 (다중 기기·소셜 복구), Z-2.U.1 (복구 UX) | contracts `test_t12_*` 3종; 포크 `test_t12_enroll_second_device_then_revoke_first` |
| T13 온체인 식별 | Z-1.C.5 (fileId 솔트, 파일명 길이 패딩), Z-1.H.9 (페이마스터), Z-3.Z.1/2 (ZK) | contracts fileId = H(hash‖salt); core `name_padding_hides_length_and_roundtrips` |
| T14 컨트랙트 검증 우회 | Z-1.H.2 (EIP-712·ERC-1271·low-s), Z-1.H.5 (Slither/Echidna), Z-1.H.6 (HF 감사), Z-1.H.8 (WebAuthn 서명 인코딩) | contracts `test_t14_*` 3종, aa-passkey `test_t14_tampered_signature_rejected` |
| T15 만료 우회 | Z-1.H.2 (체인 시간), Z-1.G.4 (로컬 시계 병행) | contracts `test_t15_*` 2종 |
| T16 Relay DoS | Z-1.R.1 (본문 상한·할당량 정의), Z-1.R.2 (서명·레이트리밋), Z-1.R.4 (셀프호스팅), Z-1.H.7 (체인 이벤트 폴백), Z-2.R.1 | proto `oversized_bodies_are_refused_on_both_sides` |
| T17 스텁 위장 | Z-1.S.1/S.2 (코드 서명·해시 고정), Z-1.C.2 (Agent는 컨테이너만 파싱), Z-1.G.13 (서명된 업데이트) | tauri-assoc: 파일 인자를 경로로만 취급, `inspect`만 수행 |
| T18 파서 취약점 | Z-1.C.2 (길이 상한·악성 입력 20종), Z-1.C.3 (cargo-fuzz) | core `tests/malicious.rs` 31종 (`t17_*`, `t18_*`, `t19_*`), `t18_chunk_*` |
| T19 다운그레이드 | Z-1.C.2 (버전 검사·최소 버전 정책), Z-1.C.4 (`verify_version_chain`), Z-1.H.2 (온체인 버전 바인딩) | core `t19_*`; reseal `t19_*` 3종; contracts `test_t19_grant_must_name_the_current_version` |
| T20 회수 무시 | Z-1.C.4 (재봉인 시 새 DEK로 이전 승인 무효화), Z-1.G.4 (TTL·주기 확인), Z-1.G.11 (revoke), Z-1.H.7 (이벤트 구독), Z-1.G.13 (코드 서명), Z-3.H.3 (어테스테이션) | contracts `test_t20_revoke_only_owner`; core `t20_each_version_gets_a_fresh_dek_and_nonce_prefix` |
| T21 번들러·페이마스터 검열/지연 | Z-1.H.8 (다중 번들러 엔드포인트), Z-1.H.9 (페이마스터 폴백: 자체 예치), Z-1.G.4 (`strict_onchain` 아닌 경우 체인 확정 미대기) | aa-passkey: EntryPoint 직접 `handleOps` 경로 + Pimlico 실제 제출(프리컴파일 호출 허용 확인) |
| T22 동기화 패스키 복제 | Z-1.A.2 (BE/BS 플래그 기록·정책), Z-1.A.7 (기기 바운드 키 대안), Z-1.H.10 (등록·해지 온체인), Z-1.U.7 (선택 UI) | auth `t22_synced_passkey_flags_detected`; contracts `test_t22_keys_are_scoped_to_the_enrolling_account` |
| T23 무프롬프트 기기 키 남용 | Z-1.A.7 (OS 확인 옵션·속도 제한), Z-1.G.10 (명시적 탭에만 키 사용), Z-1.H.10 (즉시 해지), Z-3.G.2 (VBS) | auth `t23_*` 2종; contracts `requireOsConfirm` 온체인 기록 |

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
