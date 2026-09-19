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
| Z-0.G.1 | Tauri 2 스파이크: `.zbacs` 파일 연결, `RunEvent::Opened` 로 경로 수신, 단일 인스턴스 | research §3 | `spikes/tauri-assoc/` | 더블클릭 시 앱 실행·경로 로그 |
| Z-0.H.1 | Foundry 프로젝트 + Anvil, `AccessGrant` EIP-712 서명·검증 PoC | specs/approval_protocol | `contracts/` | `forge test` 통과 |
| Z-0.H.2 | Base Sepolia RIP-7212 실측(OR-2), Kernel+Passkey Validator 계정 생성 스파이크(permissionless.js) | research §4 | `spikes/aa-passkey/` | 패스키로 UserOp 1건 성공 |
| Z-0.Q.1 | 위협모델 리뷰 워크숍, T01~T20 → 태스크 매핑 | threat_model | 매핑표(이 문서 §부록) | 누락 없음 |

**Phase 0 종료 기준**: 5개 스파이크(C.1, A.1, G.1, H.1, H.2) 모두 성공 또는 대안 ADR 작성.

---

## Phase 1 — MVP (Windows, 목표 10주)

### 1.1 Core (C)
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.C.1 | `zbacs-core` 크레이트 정식화: 타입, 에러, `Sealer/Opener` 트레이트 | 문서화된 공개 API, 단위 테스트 90% |
| Z-1.C.2 | 컨테이너 파서 견고화: 길이 상한, 버전 검사, 절단 방지(`is_last`), trailer | 악성 입력 테스트 20종 |
| Z-1.C.3 | `cargo-fuzz` 타깃(header, chunk) | 24h 퍼징 무크래시 |
| Z-1.C.4 | 재봉인(Reseal): 새 DEK, 버전 체인, 원자적 교체 | v1→v2→v3 체인 검증 테스트 |
| Z-1.C.5 | 파일명 암호화, 정책 해시, 테스트 벡터 고정 | vectors 디렉터리 |
| Z-1.C.6 | 키 자료 zeroize 감사, `secrecy` 적용 | 리뷰 체크리스트 통과 |

### 1.2 Auth (A)
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.A.1 | `AuthProvider` 트레이트 + `ApprovalChallenge/Assertion` 타입 | 문서화 |
| Z-1.A.2 | `PasskeyProvider(Windows)` 구현 | 등록·승인 E2E |
| Z-1.A.3 | 기기 키(X25519/Ed25519) 생성 + DPAPI/keyring 보관 | 재부팅 후 복원 |
| Z-1.A.4 | 소유자 봉인키 생성·보관·암호화 백업 파일 내보내기 | 백업 복원 테스트 |
| Z-1.A.5 | `BsaProvider` 골격 (SDK 확보 시 연결, 미확보 시 mock) | 인터페이스 호환 테스트 |
| Z-1.A.6 | `OtakProvider` 최소 구현(X.1284 흐름: 요청별 키 파생·폐기) | 재전송 테스트 |

### 1.3 Chain (H)
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.H.1 | `FileRegistry.sol` (register/bumpVersion/retire) + 테스트 | 100% 브랜치 |
| Z-1.H.2 | `AccessPolicy.sol` (grant/revoke/isValid, EIP-712, ERC-1271 지원) | 재전송·만료·회수 테스트 |
| Z-1.H.3 | `AuditLog.sol` 이벤트 계약 | 가스 ≤ 30k/log |
| Z-1.H.4 | UUPS 프록시 + Timelock 배포 스크립트(Anvil, Base Sepolia) | 주소 파일 생성 |
| Z-1.H.5 | Slither + Echidna 불변식 CI | CI 게이트 |
| Z-1.H.6 | HF 감사 파이프라인(`tools/audit`): Qwen3-Coder-Audit 로컬/원격 추론 → PR 코멘트 | 샘플 PR 리포트 |
| Z-1.H.7 | `zbacs-chain`(alloy): ABI 바인딩, 이벤트 구독, 오프라인 캐시 | 통합 테스트(Anvil) |
| Z-1.H.8 | `packages/chain-ts`: viem 타입, EIP-712 서명 헬퍼, permissionless 계정 생성 | 승인 앱에서 사용 |
| Z-1.H.9 | 페이마스터 설정(Pimlico 샌드박스) | 가스 0 UserOp |

### 1.4 Relay (R)
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.R.1 | Relay 프로토콜 정의(`AccessRequest/GrantMsg/Revoke`, CBOR over HTTPS+WebSocket) | 스키마 문서 |
| Z-1.R.2 | axum 서버: 큐, 기기 등록, 서명 검증, 레이트리밋 | 부하 테스트 100 req/s |
| Z-1.R.3 | 푸시 연동: FCM(승인 앱), ntfy 폴백 | 푸시 도달 ≤ 10s |
| Z-1.R.4 | Docker 이미지, 셀프호스팅 문서 | `docker compose up` |
| Z-1.R.5 | `zbacs-relay-client` 크레이트 | 재연결·재시도 |

### 1.5 Agent (G)
| ID | 태스크 | DoD |
|---|---|---|
| Z-1.G.1 | Tauri 앱 골격, 트레이, 단일 인스턴스, 파일 연결 | 설치 후 더블클릭 동작 |
| Z-1.G.2 | 온보딩 UI: 소유자 계정(패스키) 생성, 기기 등록 | 신규 사용자 3분 내 완료 |
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
| Z-1.U.0 | Figma 디자인 가이드 연결: 파일 키 기록, 토큰(색·타이포·간격) 코드 생성, Code Connect 초기 매핑 | `tokens.ts` 생성, 스크린샷 비교 1개 |
| Z-1.U.1 | 온보딩 흐름 설계: 설치 → 생체인증 1회 → 사용 시작. 계정(패스키 스마트계정)·기기키·Relay 등록 자동화, 입력 폼 0개 | 프로토타입 클릭 수 ≤ 3 |
| Z-1.U.2 | UI 문자열 사전 + 금지 용어 린트(`tools/ux-lint`) CI 통합 | U-5 통과 |
| Z-1.U.3 | 봉인 다이얼로그 단순화: [읽기만] [편집 허용] + 보내기, 세부는 "고급" | U-1 |
| Z-1.U.4 | 오류 메시지 카탈로그: 모든 오류에 사용자 행동 안내 + 버튼 | 리뷰 |
| Z-1.U.5 | 승인 알림 액션 버튼(Windows 토스트, 모바일 푸시) | U-3 |
| Z-1.U.6 | 사용성 테스트 라운드 1 (외부 참가자 5명, 설명 없이 U-1~U-4) | 성공률 ≥ 80% |
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

## 부록 A. 위협 → 태스크 매핑

| 위협 | 태스크 |
|---|---|
| T01 | Z-1.C.1 |
| T02 | Z-1.C.5, Z-1.H.1 |
| T03 | Z-1.H.2 |
| T04, T05 | Z-1.C.2(HPKE), Z-1.R.2 |
| T06 | Z-1.G.10, Z-1.P.2 |
| T07 | Z-1.G.5/7, Z-2.G.4, Z-3.G.1 |
| T09, T10 | Z-1.G.8, Z-1.Q.2, Z-2.G.3 |
| T11 | Z-1.C.6, Z-3.G.2 |
| T12 | Z-2.A.1 |
| T13 | Z-1.C.5, Z-3.Z.1/2 |
| T14 | Z-1.H.2/5/6 |
| T15 | Z-1.H.2, Z-1.G.4 |
| T16 | Z-1.R.2, Z-2.R.1 |
| T17 | Z-2.S.1/2 |
| T18, T19 | Z-1.C.2/3 |
| T20 | Z-1.G.11, Z-3.H.3 |

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
