# tools/

| 파일 | 용도 |
|---|---|
| `setup.sh` | Linux/macOS 개발 툴체인 설치·점검 (`--check`로 점검만). 태스크 Z-0.D.2 |
| `setup.ps1` | Windows 개발 툴체인 설치·점검 (`-Check`). 태스크 Z-0.D.2 |
| `audit/` | (예정) Slither + Hugging Face 모델 스마트컨트랙트 감사 파이프라인. 태스크 Z-1.H.6 |

설치 대상: Rust stable + clippy/rustfmt, tauri-cli 2, cargo-audit, cargo-fuzz, Foundry(forge/anvil/cast/chisel), Node 22+(별도), Tauri 시스템 의존성.

## chain-demo.sh
로컬 Anvil에서 봉인 등록 → EIP-712 승인 → 열람 → 재전송 거부 → 회수까지 실제 트랜잭션으로 실행하고 `cast`로 블록·이벤트·영수증을 보여 준다. `--keep`이면 Anvil을 켜 둔다. 설명: `docs/chain_guide.md`.

## fuzz.sh
`zbacs-core` 퍼즈 타깃 4종을 nightly + cargo-fuzz로 돌린다. `tools/fuzz.sh 24h`가 Z-1.C.3 게이트, 기본은 5분 스모크. 크래시가 있으면 `fuzz/artifacts/` 목록을 출력하고 실패한다.
