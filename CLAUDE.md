# Z-BACS — Claude Code 프로젝트 지침

## 프로젝트
**Z-BACS** (Zero-Knowledge & Blockchain-based Access Control System): BSA(블록체인 패스워드리스 인증) 기반 원격 파일 통제 시스템.
파일 소유자가 봉인한 파일을 수신자가 열면 소유자에게 실시간 승인(거부/읽기전용/편집)을 요청하고, 승인 범위에서만 복호화되며, 저장 시 자동 재봉인된다. Windows 우선.

## 항상 참조할 문서 (작업 시작 전 필독)
- `docs/README.md` — 문서 인덱스 (여기서 시작)
- `docs/project_definition.md` — 범위·요구사항·MVP DoD
- `docs/architecture.md` — 패키지 구조, 키 계층, 스택
- `docs/specs/*.md` — 컨테이너 포맷, 승인 프로토콜, 권한 모델 (구현의 단일 진실 원천)
- `docs/threat_model.md` — 위협 T01~T20. 보안 관련 코드는 해당 T-ID를 테스트 이름에 표기
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

## 스택 (ADR 참조)
Rust(stable) + Tauri 2 / RustCrypto + hpke-rs / Foundry + OpenZeppelin v5 / viem + permissionless.js / axum Relay / Base L2(Anvil 로컬)

## 현재 단계
Phase 0 (셋업·스파이크). Z-0.D.1(스캐폴드), Z-0.D.2(툴체인: Rust 1.98, tauri-cli 2.11, Foundry 1.8.3, cargo-audit/fuzz — `tools/setup.sh --check`로 점검) 완료. 다음 태스크: `Z-0.D.3` CI 골격, `Z-0.C.1` 컨테이너 PoC, `Z-0.A.1` Windows Hello 스파이크.

## 디렉터리 (예정)
`crates/` `apps/` `contracts/` `packages/` `tools/` `spikes/` `docs/`
