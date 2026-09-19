# Spike Z-0.G.1 — Tauri 2 `.zbacs` 파일 연결

`.zbacs` 파일 더블클릭이 각 OS에서 Agent에 어떻게 도달하는지 검증하는 스파이크. 독립 Cargo 워크스페이스(루트 워크스페이스에서 `spikes/*` 제외)라 CI와 루트 빌드에 영향을 주지 않는다.

## 경로 전달 방식
| OS | 첫 실행 | 이미 실행 중 |
|---|---|---|
| Windows / Linux | 셸이 exe에 파일 경로를 인자로 전달 → `std::env::args()` | `tauri-plugin-single-instance` 콜백이 새 프로세스의 argv를 기존 창에 전달, 새 프로세스는 즉시 종료 |
| macOS | Launch Services → `RunEvent::Opened { urls }` | 동일 |

받은 경로는 키 없이 `zbacs_core::container::inspect`로 헤더만 읽어 `zbacs://opened` 이벤트로 웹뷰에 보낸다(잠김 상태·버전·크기·정책·봉투 수). 웹뷰가 뜨기 전에 도착한 파일은 `take_pending` 커맨드로 회수한다.

## 파일 연결 설정
`src-tauri/tauri.conf.json` → `bundle.fileAssociations`: ext `zbacs`, MIME `application/x-zbacs`, role Editor.
- Windows(NSIS): 레지스트리 ProgId 등록. `installMode: currentUser`라 관리자 권한 불필요(UX 원칙).
- Linux(deb): `.desktop`의 `MimeType=` + `/usr/share/mime/packages/*.xml`.
- macOS(dmg): `Info.plist` `CFBundleDocumentTypes` + `UTExportedTypeDeclarations`.

## 실행
```bash
cd spikes/tauri-assoc/src-tauri
cargo build && cargo test
# GUI 없는 리눅스에서 스모크: 세션 D-Bus 필수(single-instance가 D-Bus 사용)
WEBKIT_DISABLE_DMABUF_RENDERER=1 ZBACS_SPIKE_AUTOEXIT_MS=5000 \
  xvfb-run -a dbus-run-session -- ./target/debug/zbacs-spike-assoc /path/a.zbacs
# 번들
cd .. && cargo tauri build --bundles deb   # Windows: --bundles nsis
```

## 확인 결과 (2026-09-19, Ubuntu 22.04 headless)
- 첫 실행 인자 2개(정상 컨테이너, 깨진 파일) 모두 수신·검사·이벤트 발행 후 자동 종료.
- 두 번째 인스턴스: 70ms 내 종료, 첫 인스턴스 로그에 `second instance argv` + `opened` 기록.
- 단위 테스트 2개 통과(인자 필터, 비컨테이너 오류).
- Windows 더블클릭 실제 확인은 Windows 머신 필요(Z-0.A.1과 함께).

## 배운 것
- Linux에서 single-instance 플러그인은 세션 D-Bus가 없으면 시작이 멈춘다. 헤드리스 테스트는 `dbus-run-session`으로 감싼다.
- crates.io의 최신 `tauri`는 3.0.0-alpha. 반드시 `tauri = "2"`로 고정.
- `withGlobalTauri: true`면 번들러 없이 정적 HTML만으로 `window.__TAURI__` 사용 가능 → 스파이크·설치기 화면에 적합.
