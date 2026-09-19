# Z-BACS — Claude Code 프로젝트 지침

## 프로젝트
**Z-BACS** (Zero-Knowledge & Blockchain-based Access Control System): BSA(블록체인 패스워드리스 인증) 기반 원격 파일 통제 시스템.
파일 소유자가 봉인한 파일을 수신자가 열면 소유자에게 실시간 승인(거부/읽기전용/편집)을 요청하고, 승인 범위에서만 복호화되며, 저장 시 자동 재봉인된다. Windows 우선.

## 최상위 개발 원칙
**사용자가 아무것도 몰라도 쓸 수 있어야 한다.** 블록체인·암호화·키·계정·설정·설치 절차를 사용자가 배우지 않아도 되도록, 복잡한 등록·절차·환경설정은 전부 시스템이 대신 한다. UI에 기술 용어 금지, 온보딩·봉인·승인·열람 흐름에 텍스트 입력 필드 금지. 설계·태스크가 이 원칙과 충돌하면 원칙이 이긴다. 상세: `docs/ux_principles.md`.

## 항상 참조할 문서 (작업 시작 전 필독)
- `docs/ux_principles.md` — 최상위 원칙과 UX DoD(U-1~U-6)
- `docs/design/ui_guideline.md` — UI/UX 기본 골격: 토큰, 상태↔시각 매핑, 컴포넌트, 화면 S1~S10
- `docs/README.md` — 문서 인덱스 (여기서 시작)
- `docs/project_definition.md` — 범위·요구사항·MVP DoD
- `docs/architecture.md` — 패키지 구조, 키 계층, 스택
- `docs/specs/*.md` — 컨테이너 포맷, 승인 프로토콜, 권한 모델 (구현의 단일 진실 원천)
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
Phase 0 (셋업·스파이크). 완료: Z-0.D.1 스캐폴드, Z-0.D.2 툴체인(`tools/setup.sh --check`), Z-0.D.3 CI(`.github/workflows/ci.yml`), Z-0.C.1/C.2 컨테이너·HPKE 봉투 PoC(`crates/zbacs-core`, CLI `zbacs`; 100MB 왕복 0.35s), Z-0.H.1 EIP-712 승인 티켓 PoC(`contracts/`: FileRegistry, AccessPolicy, 18 tests), Z-0.G.1 Tauri 파일 연결 스파이크(`spikes/tauri-assoc/`, 독립 워크스페이스), Z-0.H.2 패스키 스마트계정 스파이크(`spikes/aa-passkey/`: RIP-7212 활성 실측 3,885 gas, Kernel v3.1+WebAuthn UserOp가 Base Sepolia 포크의 실제 EntryPoint 통과, 10 tests, Pimlico 번들러 실제 제출 2건 성공). Z-0.Q.1 위협 매핑 리뷰(`docs/dev_plan.md` 부록 A: T01~T22 ↔ 태스크 ↔ 테스트 근거, threat_model v1.1). ADR-0006(2026-09-19): 소유자 승인 서명은 플랫폼 패스키(Windows Hello) **또는** 등록 기기 바운드 키(DeviceKey, `P256Validator`) 중 소유자 선택 — Z-0.A.1은 Phase 0 게이트에서 제외되어 **Phase 0 종료**. 다음: Phase 1 시작(Z-1.C.1 core 정식화, Z-1.A.1 `AuthProvider` 트레이트 + DeviceKeyProvider 설계), `Z-0.A.3` BSA Client Key 신청(외부), Z-0.A.1은 Windows 실기 확보 시.

## 디렉터리
`crates/zbacs-core`(컨테이너·암호) `crates/zbacs-cli`(PoC CLI) `contracts/`(Foundry: FileRegistry, AccessPolicy) `packages/design-tokens/` `spikes/tauri-assoc/`(Tauri 스파이크) `spikes/aa-passkey/`(패스키 AA 스파이크, Node+Foundry; 스파이크는 루트 워크스페이스·CI 제외) `tools/`(셋업) `docs/` — 예정: `apps/`

## 빌드·테스트
```
cargo fmt --all --check && cargo clippy --workspace --all-targets   # RUSTFLAGS=-D warnings in CI
cargo test --workspace                     # 디버그 (perf 테스트는 ignore)
cargo test --workspace --release -- perf_  # 100MB 성능 게이트
cd contracts && forge fmt --check && forge test  # 컨트랙트 (PATH에 ~/.foundry/bin)
```
PoC 기록: `docs/research/crypto_container_poc.md`
