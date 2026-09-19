# 개발 가이드라인 (Development Guidelines)

## 1. 문서 우선(Spec-first)
- 기능 구현 전 관련 스펙(`docs/specs/`)과 태스크 ID(`docs/dev_plan.md`)를 확인한다.
- 설계 변경은 ADR 추가 후 코드 변경. 스펙과 코드가 다르면 **스펙을 먼저 고친다**.

## 2. 보안 코딩 규칙
- 암호 프리미티브 자체 구현 금지. RustCrypto / hpke-rs / webauthn-rs / OpenZeppelin만 사용.
- 키·평문은 `SecretBox`/`secrecy` 타입으로만 다루고, 로그·에러 메시지에 절대 출력하지 않는다.
- 난수는 `rand::rngs::OsRng` 또는 `getrandom`만.
- 파일 쓰기는 temp + fsync + rename 원자적 교체.
- 입력 파싱은 길이 상한과 버전 검사를 먼저 한다.
- `unsafe`는 OS API 바인딩에 한정하고 주석으로 불변식을 적는다.
- Solidity: CEI 패턴, `ReentrancyGuard`, 커스텀 에러, 이벤트 필수, `block.timestamp` 의존 시 허용 편차 문서화.

## 3. 코드 스타일
- Rust: `cargo fmt`, `cargo clippy -D warnings`, 공개 API에 rustdoc.
- TS: ESLint + Prettier, strict 모드.
- Solidity: `forge fmt`, NatSpec.
- 커밋: Conventional Commits, 제목에 태스크 ID 포함 (`feat(core): Z-1.C.4 reseal version chain`).

## 4. 테스트
- 단위 + 통합 + E2E(Windows VM). 암호 관련 코드는 테스트 벡터 필수.
- 컨트랙트: `forge test`, 퍼즈, Slither, Echidna, HF 감사 리포트.
- 보안 회귀: `docs/threat_model.md`의 T-ID를 테스트 이름에 표기 (`t09_no_plaintext_residue`).
- 퍼징: `crates/zbacs-core/fuzz/` 타깃 4종(`header`, `header_signed`, `open_mutated`, `envelope`). `tools/fuzz.sh [24h|10m] [target]`, 야간 CI `fuzz.yml`(타깃당 20분). 크래시 입력은 `fuzz/artifacts/`에 남고 `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>`로 재현한다. 새 파서 코드는 타깃을 같이 추가한다.
- 커버리지: `zbacs-core`, `zbacs-auth`는 라인 커버리지 90% 이상 (`cargo llvm-cov -p zbacs-core -p zbacs-auth --fail-under-lines 90`, CI 게이트). 공개 API는 `#![warn(missing_docs)]` + `RUSTDOCFLAGS=-D warnings cargo doc`.

## 5. 리서치 반영
- 새 라이브러리·모델을 발견하면 `docs/research.md` 표에 추가하고 `docs/research/`에 출처·라이선스와 함께 스니펫 저장.
- GPL 코드는 `zbacs-*` 크레이트에 복사 금지.

## 6. 릴리스
- 모든 바이너리는 코드 서명. 업데이트는 서명 검증.
- 컨테이너 포맷·프로토콜 변경은 버전 필드 상승 + 마이그레이션 노트.
