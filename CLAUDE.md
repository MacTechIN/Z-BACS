# Z-BACS — Claude Code 프로젝트 지침

## 프로젝트
**Z-BACS** (Zero-Knowledge & Blockchain-based Access Control System): BSA(블록체인 패스워드리스 인증) 기반 원격 파일 통제 시스템.
파일 소유자가 봉인한 파일을 수신자가 열면 소유자에게 실시간 승인(거부/읽기전용/편집)을 요청하고, 승인 범위에서만 복호화되며, 저장 시 자동 재봉인된다. Windows 우선.

## 최상위 개발 원칙
**사용자가 아무것도 몰라도 쓸 수 있어야 한다.** 블록체인·암호화·키·계정·설정·설치 절차를 사용자가 배우지 않아도 되도록, 복잡한 등록·절차·환경설정은 전부 시스템이 대신 한다. UI에 기술 용어 금지, 온보딩·봉인·승인·열람 흐름에 텍스트 입력 필드 금지. 설계·태스크가 이 원칙과 충돌하면 원칙이 이긴다. 상세: `docs/ux_principles.md`.

## 항상 참조할 문서 (작업 시작 전 필독)
- `docs/ux_principles.md` — 최상위 원칙과 UX DoD(U-1~U-6)
- `docs/design/ui_guideline.md` — UI/UX 기본 골격: 토큰, 상태↔시각 매핑, 컴포넌트, 화면 S1~S10
- `docs/design/ui_strings.md` — UI 문자열 사전·금지 용어(린트가 읽는 원본)
- `docs/README.md` — 문서 인덱스 (여기서 시작)
- `docs/project_definition.md` — 범위·요구사항·MVP DoD
- `docs/architecture.md` — 패키지 구조, 키 계층, 스택
- `docs/specs/*.md` — 컨테이너 포맷, 승인 프로토콜, 권한 모델 (구현의 단일 진실 원천)
- `docs/credentials.md` — 외부 키·자격 증명 발급 가이드(키 값은 저장소·대화에 올리지 않는다)
- `docs/windows_checklist.md` — Windows 실기 확인 절차(하드웨어 경로 작업 시)
- `docs/chain_guide.md` — 블록체인 가이드(Base, 작동 원리, 올라가는 데이터, 테스트 4단계, `tools/chain-demo.sh`)
- `docs/threat_model.md` — 위협 T01~T23. 보안 관련 코드는 해당 T-ID를 테스트 이름에 표기
- `docs/dev_plan.md` — 태스크 ID(`Z-<phase>.<track>.<seq>`). 작업은 태스크 ID 단위로 진행
- `docs/research.md` — 기술 리소스 카탈로그. 새 라이브러리 도입 시 여기와 `docs/adr/`에 기록
- `docs/dev_guidelines.md` — 보안 코딩·스타일·커밋 규칙

## 작업 규칙
1. **Spec-first**: 스펙과 코드가 다르면 스펙을 먼저 수정하고 ADR을 남긴다.
2. **암호 프리미티브 자체 구현 금지**: RustCrypto, hpke-rs, webauthn-rs, OpenZeppelin만 사용.
3. 키·평문은 절대 로그에 남기지 않는다. `secrecy`/`zeroize` 사용.
4. 새 외부 리소스(GitHub/Hugging Face 등)를 쓰면 `docs/research.md` 표에 출처·라이선스를 추가한다. GPL 코드는 `zbacs-*` 크레이트에 복사 금지.
5. 커밋 메시지는 Conventional Commits + 태스크 ID: `feat(core): Z-1.C.4 reseal version chain`.
6. 벤더(BSA, Lit, 체인, 푸시)는 항상 트레이트/인터페이스 뒤에 둔다.
7. 문서는 한국어, 코드 식별자·주석은 영어.
8. **UI는 디자인 가이드에서 생성한다.** 기본 골격은 `docs/design/ui_guideline.md`(D-GO Vault 키트 = 기본 테마, Foundations 올리브 = 대체 테마), 값은 `packages/design-tokens/tokens.css` 변수만 사용한다. Figma URL이 연결되면 `docs/reference/figma.md`의 파일을 Figma MCP로 열어 토큰·컴포넌트·프레임을 가져오고 그대로 구현한다. 가이드에 없는 화면은 Figma에 먼저 추가한 뒤 구현한다. 코드에서 임의의 색·간격·컴포넌트를 만들지 않는다.
9. **대화 기록 [원칙]**: 사용자와의 대화는 `history.md`에 원본 그대로 시계열로 기록한다. 모든 작업을 마무리할 때(최종 응답 직전) 그 작업의 사용자 메시지 원문과 Claude 최종 응답 원문을 `history.md` 끝에 추가한다. 도구 호출·중간 출력은 기록하지 않는다.
10. **단계별 커밋 [원칙]**: 태스크·스파이크·문서 갱신 등 작업 단계가 끝날 때마다 묻지 않고 바로 커밋하고 `origin main`에 푸시한다(사용자 지시 2026-09-19). 커밋 메시지는 Conventional Commits + 태스크 ID, `history.md` 갱신을 같은 커밋에 포함한다.
11. 사용자 대면 기능을 만들 때는 `docs/ux_principles.md` §6 체크리스트를 먼저 적용한다. 새로 "알아야 할 것"이 생기면 설계를 다시 한다.

## 스택 (ADR 참조)
Rust(stable) + Tauri 2 / RustCrypto + hpke-rs / Foundry + OpenZeppelin v5 / viem + permissionless.js / axum Relay / Base L2(Anvil 로컬)

## 현재 단계
Phase 1 (구현). Phase 0 완료: 컨테이너·HPKE PoC, EIP-712 승인 티켓, Tauri 파일 연결, 패스키 스마트계정(RIP-7212 3,885 gas 실측, Pimlico 실제 제출 2건), 위협 매핑 리뷰. Windows Hello 실기(Z-0.A.1)만 `docs/windows_checklist.md`로 이관.

Phase 1 완료: **C 트랙 전부**(컨테이너 v1.2, 재봉인 버전 체인, 24h 퍼징 420,679,318 runs·무크래시, 복구 코드 백업), **A 트랙 대부분**(`zbacs-auth`: AuthProvider·이중 경로·확인 정책 T23·OS 키저장소·OTAK, Windows Hello/TPM 코드는 크로스컴파일까지), **H 트랙**(FileRegistry/AccessPolicy/AuditLog/P256Validator, `zbacs-chain` 이벤트 감시·오프라인 캐시, **UUPS+Timelock 배포·주소 파일**), **R 트랙**(axum Relay, 장애 조치·멱등 재시도 클라이언트), **G 트랙**(세션 상태머신, 보호 작업공간, 열람 앱 실행·저장 감지, Agent 골격, **첫 실행 온보딩**, **잠그기 UI**, **열람 요청·대기 UI(G.9)**, **데스크톱 승인 UI(G.10, 시나리오 B 왕복 테스트)**, **회수·허락 목록(G.11)**, **기록 화면(G.12 로컬, 체인 병합은 H.8 뒤)**), **U 트랙**(디자인 토큰, 온보딩 흐름, 용어 린트, 승인 방식 선택, 봉인 다이얼로그).

**베타까지 남은 것은 `docs/dev_plan.md` §1.9 "베타 컷"에 정리돼 있다** — 코드 5태스크(U.4 → U.5 → R.4 → Q.2 → Q.1; G.12의 체인 병합은 H.8과 함께)와, 사용자만 할 수 있는 Windows 실기 확인. 후자가 ◐ 8개를 한꺼번에 막고 있는 가장 큰 일정 리스크다.

일반인 베타 자동화는 `docs/beta_test_automation.md`(5층). L1 `Z-1.S.3` 설치 파일 CI 완료(`release.yml`, Actions 아티팩트 `zbacs-windows-<sha>`에 설치 파일 + `zbacs-wincheck.exe`). L2(Relay 호스팅)는 사용자 계정 결정 대기.

다음: `Z-1.U.4` 오류 카탈로그(모든 오류에 다음 행동 + 버튼 — 지금 UI의 *_PROBLEMS 표를 `docs/design/ui_strings.md`로 승격하고 린트로 누락 검사), `Z-1.U.5` 알림 액션 버튼. 열기(G.7/G.8)는 승인 후 `Held.envelope`(aad=grantId)를 여는 것부터. Windows 실기 확인(`docs/windows_checklist.md` §0-A 설치 파일 경로, §1~§4, 특히 **§3.5 첫 실행 2탭**, **§3.6 잠그기**)은 사용자 차례.

## 디렉터리
`crates/zbacs-core`(컨테이너·암호) `crates/zbacs-auth`(승인 서명자) `crates/zbacs-proto`(Relay 프로토콜) `crates/zbacs-session`(세션·작업공간) `apps/relay`(Relay 서버) `apps/agent`(Tauri Agent, 루트 워크스페이스 제외) `crates/zbacs-relay-client`(Relay 클라이언트) `crates/zbacs-chain`(체인 클라이언트) `crates/zbacs-wincheck`(Windows 자가진단) `crates/zbacs-cli`(PoC CLI) `contracts/`(Foundry: FileRegistry, AccessPolicy, P256Validator) `packages/design-tokens/` `spikes/tauri-assoc/`(Tauri 스파이크) `spikes/aa-passkey/`(패스키 AA 스파이크, Node+Foundry; 스파이크는 루트 워크스페이스·CI 제외) `tools/`(셋업) `docs/` — 예정: `apps/`

## 빌드·테스트
```
cargo fmt --all --check && cargo clippy --workspace --all-targets   # RUSTFLAGS=-D warnings in CI
cargo test --workspace                     # 디버그 (perf 테스트는 ignore)
cargo test --workspace --release -- --include-ignored perf_  # 성능 게이트(100MB 왕복, Relay 처리량)
cd contracts && forge fmt --check && forge test  # 컨트랙트 (PATH에 ~/.foundry/bin)
cd contracts && forge script script/Deploy.s.sol --rpc-url anvil --broadcast --private-key $PK  # 배포 → deployments/<chainId>.json
tools/ux-lint.sh                                 # UI 용어·입력·토큰·마크업 일치 (CI `ux` 잡)
cd apps/agent/src-tauri && cargo test --features demo-signer   # Agent (루트 워크스페이스 밖, CI `agent` 잡)
gh workflow run release.yml   # Windows 설치 파일 + zbacs-wincheck.exe 아티팩트 (Z-1.S.3, `v*` 태그면 Release)
tools/chain-it.sh                          # 컨트랙트 빌드 + Anvil 통합 테스트
RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps          # 공개 API 문서 게이트
cargo llvm-cov -p zbacs-core -p zbacs-auth --fail-under-lines 90  # 커버리지 게이트
# Windows 전용 코드 컴파일 검증 (Linux에서). 네트워크 크레이트 둘은 제외 — rustls/ring이
# Windows용 C 크로스 툴체인을 요구하고, 둘 다 Windows 전용 코드가 없어 얻을 게 없다.
# 실제 Windows 빌드는 CI의 windows-latest 러너가 담당한다.
cargo check --target x86_64-pc-windows-gnu --workspace --exclude zbacs-relay-client --exclude zbacs-chain
tools/fuzz.sh [24h|5m] [target]            # 퍼징 (nightly + cargo-fuzz)
```
PoC 기록: `docs/research/crypto_container_poc.md`
