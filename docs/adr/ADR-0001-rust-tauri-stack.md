# ADR-0001: 코어 언어 Rust, 데스크톱 프레임워크 Tauri 2

- 상태: Accepted (2026-09-18)

## 컨텍스트
Windows 우선, 이후 macOS/Linux를 지원하는 상주 Agent가 필요하다. 평문·키를 다루므로 메모리 안전성이 중요하고, 파일 연결(더블클릭 실행)과 코드 서명 배포가 필수다.

## 결정
- 코어 라이브러리(`zbacs-core`, `zbacs-auth`, `zbacs-session`)는 Rust.
- 데스크톱 Agent는 Tauri 2 (Rust 백엔드 + WebView UI, React/TypeScript).
- Relay는 Rust(axum). 체인 TS SDK는 viem 기반.

## 근거
- Tauri 2는 Win/mac/Linux 파일 연결을 공식 지원하고 `RunEvent::Opened`로 경로를 전달한다.
- RustCrypto, hpke-rs, webauthn-rs, alloy 등 필요한 생태계가 Rust에 있다.
- Electron 대비 바이너리가 작고 메모리 사용이 적어 상주 프로그램에 적합.

## 대안
- .NET(WPF) + webauthn-interop: Windows 통합은 우수하나 크로스플랫폼 비용 큼.
- Electron: 크기·메모리·네이티브 암호 연동 불리.
- Go + Wails: 암호 생태계 양호하나 Tauri 대비 파일 연결·모바일 확장 미흡.

## 결과
- 현재 머신에 Rust 툴체인 미설치 → Z-0.D.2 설치 스크립트 필요.
- UI 개발자는 TS/React, 코어 개발자는 Rust 역량 필요.
