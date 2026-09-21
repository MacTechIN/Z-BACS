# Z-BACS Agent (Z-1.G.1, Z-1.G.2)

데스크톱 Agent. 트레이에 상주하다가 `.zbacs` 파일을 두 번 누르면 깨어나고, 소유자 승인을 받아 파일을 연다.

```
cd apps/agent/src-tauri
cargo tauri dev                    # 개발 실행
cargo tauri build --bundles deb    # Linux 패키지
cargo tauri build --bundles nsis   # Windows 설치 파일
cargo test --features demo-signer  # 백엔드 단위 테스트 (Linux)
cargo test                         # Windows: 실제 Hello/TPM 경로
```

루트 Cargo 워크스페이스에서 **제외**되어 있다(웹뷰 툴체인이 무겁고 시스템 라이브러리를 요구한다). 루트 CI의 Rust 잡은 이 앱을 빌드하지 않는 대신, CI에 **별도 `agent` 잡**(ubuntu + windows)이 있다.

## 기능 플래그

| 플래그 | 하는 일 |
|---|---|
| `os-keystore` (기본 켬) | 비밀을 OS 자격 증명 저장소에 둔다. 없으면 실행할 때마다 첫 실행이 다시 나오므로, 런타임에 사용 가능 여부를 확인하고 안 되면 사용자에게 그 사실을 알린다 |
| `demo-signer` | Windows Hello·TPM이 없는 개발 기기용 **소프트웨어 대역 서명기**. 승인 키가 평범한 프로세스 메모리에 있으므로 **릴리스 빌드에 넣지 않는다.** Windows에서는 필요 없다 |

## 지금 하는 일 (골격)

| | |
|---|---|
| 트레이 | 창을 닫아도 계속 실행된다. 승인 요청이 왔을 때 거기 있어야 하기 때문이다. "종료"를 눌러야 끝난다 |
| 단일 인스턴스 | 두 번째 더블클릭은 새 창을 띄우지 않고 실행 중인 Agent에 경로를 넘긴다 |
| 파일 연결 | `.zbacs` 확장자와 `application/x-zbacs` MIME. Linux는 `Exec %U`와 shared-mime-info, Windows는 NSIS |
| 파일 읽기 | 키 없이 헤더만 읽어 "잠긴 파일인지, 몇 번째 버전인지, 주인이 기본으로 어디까지 허용했는지"를 보여준다 |
| 첫 실행 | 탭 2번(시작하기 → 승인 방식). 기기·소유자 키와 승인 서명기를 만들고 기기 프로필을 남긴다. 입력 폼 0개 |

웹뷰 권한은 `capabilities/default.json` 하나이고 `core:event:default`만 허용한다 — 파일·셸·대화상자·네트워크는 웹뷰에서 쓸 수 없다.

## 아직 하지 않는 일

봉인(Z-1.G.3), 승인 요청·열람(Z-1.G.9)은 아직이다. UI가 "다음 단계에서 연결됩니다"라고 말하고 버튼을 비활성으로 둔다 — 되는 것처럼 보이게 하지 않는다.

계정을 체인에 만드는 일(Z-1.H.8)과 이 기기를 그 계정에 등록하는 일(Z-1.H.10)도 아직이다. 첫 실행은 이것을 `pending`으로 돌려주며, **사용자에게는 보여주지 않는다** — 우리가 끝낼 일이지 사용자가 알 일이 아니다(ux_principles §2). 개발용 정보 패널에는 그대로 나온다.

## UI 규칙

`ui/`는 `packages/design-tokens/tokens.css`의 변수만 쓴다(CLAUDE.md 규칙 8). 그 파일은 빌드 때 `build.rs`가 복사하므로 `ui/tokens.css`를 손으로 고치지 말 것(gitignore 대상).

사용자에게 보이는 문구는 전부 `ui/`에 있다. 백엔드는 `"biometric"`, `"volatile_key_store"` 같은 **기계값만** 돌려주고 문장을 만들지 않는다 — 그래야 `tools/ux-lint.sh`가 화면의 말을 한곳에서 검사할 수 있다.

```
tools/ux-lint.sh   # 금지 용어(U-5), 텍스트 입력 0개(U-6), 토큰만 사용, id/data-role 일치
```
