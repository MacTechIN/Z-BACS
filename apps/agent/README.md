# Z-BACS Agent (Z-1.G.1)

데스크톱 Agent. 트레이에 상주하다가 `.zbacs` 파일을 두 번 누르면 깨어나고, 소유자 승인을 받아 파일을 연다.

```
cd apps/agent/src-tauri
cargo tauri dev                    # 개발 실행
cargo tauri build --bundles deb    # Linux 패키지
cargo tauri build --bundles nsis   # Windows 설치 파일
cargo test                         # 백엔드 단위 테스트
```

루트 Cargo 워크스페이스에서 **제외**되어 있다(웹뷰 툴체인이 무겁고 시스템 라이브러리를 요구한다). 루트 CI의 Rust 잡은 이 앱을 빌드하지 않는다.

## 지금 하는 일 (골격)

| | |
|---|---|
| 트레이 | 창을 닫아도 계속 실행된다. 승인 요청이 왔을 때 거기 있어야 하기 때문이다. "종료"를 눌러야 끝난다 |
| 단일 인스턴스 | 두 번째 더블클릭은 새 창을 띄우지 않고 실행 중인 Agent에 경로를 넘긴다 |
| 파일 연결 | `.zbacs` 확장자와 `application/x-zbacs` MIME. Linux는 `Exec %U`와 shared-mime-info, Windows는 NSIS |
| 파일 읽기 | 키 없이 헤더만 읽어 "잠긴 파일인지, 몇 번째 버전인지, 주인이 기본으로 어디까지 허용했는지"를 보여준다 |

## 아직 하지 않는 일

온보딩(Z-1.G.2), 봉인(Z-1.G.3), 승인 요청·열람(Z-1.G.9)은 아직이다. UI가 "다음 단계에서 연결됩니다"라고 말하고 버튼을 비활성으로 둔다 — 되는 것처럼 보이게 하지 않는다.

## UI 규칙

`ui/`는 `packages/design-tokens/tokens.css`의 변수만 쓴다(CLAUDE.md 규칙 8). 그 파일은 빌드 때 `build.rs`가 복사하므로 `ui/tokens.css`를 손으로 고치지 말 것(gitignore 대상).
