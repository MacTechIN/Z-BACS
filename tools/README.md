# tools/

| 파일 | 용도 |
|---|---|
| `setup.sh` | Linux/macOS 개발 툴체인 설치·점검 (`--check`로 점검만). 태스크 Z-0.D.2 |
| `setup.ps1` | Windows 개발 툴체인 설치·점검 (`-Check`). 태스크 Z-0.D.2 |
| `audit/` | (예정) Slither + Hugging Face 모델 스마트컨트랙트 감사 파이프라인. 태스크 Z-1.H.6 |

설치 대상: Rust stable + clippy/rustfmt, tauri-cli 2, cargo-audit, cargo-fuzz, Foundry(forge/anvil/cast/chisel), Node 22+(별도), Tauri 시스템 의존성.
