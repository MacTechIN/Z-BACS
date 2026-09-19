# Windows 실기 확인 체크리스트

| 문서 버전 | 1.0 (2026-09-19) |
|---|---|
| 대상 | Z-1.A.2(Windows Hello), Z-1.A.7(TPM 기기 키), Z-1.A.3(자격 증명 저장소), Z-0.G.1(파일 연결) |
| 도구 | `crates/zbacs-wincheck` — 한 번에 전부 검사하고 PASS/FAIL을 출력 |

Linux CI에서는 이 네 가지를 검증할 수 없다(TPM·Hello·레지스트리). 코드는 `cargo check --target x86_64-pc-windows-gnu`로 컴파일까지 확인했고, **실제 동작 확인만 Windows에서 필요**하다.

## 0. 준비 (한 번만)

| 항목 | 확인 방법 |
|---|---|
| Windows 10 1903 이상 또는 11 | `winver` |
| TPM 2.0 | `tpm.msc` → "TPM 사용할 준비가 됨", 사양 버전 2.0 |
| Windows Hello 설정됨 | 설정 → 계정 → 로그인 옵션에 얼굴·지문·PIN 중 하나 등록 (없으면 **PIN만 등록해도 됨**) |
| Rust 툴체인 | `tools\setup.ps1` 실행 후 `cargo --version` |
| 저장소 | `git clone` 후 저장소 루트에서 아래 명령 실행 |

## 1. 자동 검사 (약 2분)

저장소 루트에서:

```
cargo run -p zbacs-wincheck
```

중간에 Windows Hello 창이 **두 번** 뜬다(자격 증명 생성 1회, 서명 1회). 얼굴·지문·PIN 중 하나로 통과시키면 된다.

기대 출력:

```
[1] Z-1.A.3  credential store ...   [PASS] keychain round-trip
[2] Z-1.A.7  device-bound key ...   [PASS] TPM key / [PASS] TPM key signature
[3] Z-1.A.2  Windows Hello ...      [PASS] webauthn.dll / [PASS] Hello credential / [PASS] Hello assertion
[4] Z-0.G.1  .zbacs file association ...
summary: passed N  failed 0  skipped M
```

- `[SKIP] TPM key ... fell back to the software KSP` → TPM이 없거나 비활성. BIOS에서 TPM/PTT를 켜고 다시 실행.
- `[FAIL]`이 하나라도 나오면 **출력 전체를 그대로 붙여 달라.** 오류 코드(`0x8009xxxx`)로 원인을 특정할 수 있다.

## 2. 재부팅 후 재실행 (중요)

```
(재부팅)
cargo run -p zbacs-wincheck
```

- Z-1.A.3 DoD가 "재부팅 후 복원"이고, TPM 키도 재부팅을 넘겨야 한다.
- 2회차에는 `keychain round-trip`이 PASS이고 TPM 키의 **keyId가 1회차와 같아야** 한다. 달라지면 키가 새로 생성된 것이므로 알려 달라.
- Windows Hello 자격 증명은 이 도구가 매번 새로 만들므로 keyId가 달라도 정상이다(Agent는 credentialId를 저장해 재사용한다).

## 3. 파일 연결 더블클릭 (Z-0.G.1 Windows 확인)

Linux에서는 deb 패키지로만 확인했다. Windows 확인:

```
cd spikes\tauri-assoc
npm install
npx tauri build
```

`src-tauri\target\release\bundle\nsis\` 의 설치 파일을 실행한 뒤:

1. 아무 파일이나 `test.zbacs`로 이름을 바꾼다.
2. 더블클릭한다.
3. 앱이 뜨고 화면에 **그 파일 경로**가 보이면 성공.
4. 앱이 떠 있는 상태에서 다른 `.zbacs`를 더블클릭하면 **새 창이 아니라 기존 창**이 경로를 받아야 한다(단일 인스턴스).

결과를 알려 주면 `docs/dev_plan.md`의 Z-0.G.1 항목에 Windows 확인을 기록한다.

## 4. 결과 보고

아래만 알려 주면 된다:

- `cargo run -p zbacs-wincheck` 1회차 출력 전체
- 재부팅 후 2회차의 summary 줄과 TPM keyId
- 3번 더블클릭 결과 (성공/실패)

## 부록: 무엇이 실제로 검사되나

| 검사 | 확인하는 것 |
|---|---|
| keychain round-trip | Credential Manager(DPAPI)에 비밀을 쓰고 그대로 읽는다 — 사용자가 키를 관리하지 않아도 재부팅을 넘기는 근거 |
| TPM key | `NCryptCreatePersistedKey`가 Platform Crypto Provider에 P-256 키를 만들고, 개인키는 프로세스 메모리에 **존재하지 않는다**(내보내기 불가) |
| TPM key signature | TPM 서명을 low-s로 정규화해 `zbacs-auth` 검증기가 통과 — 온체인 `P256Validator`와 같은 규칙 |
| Hello credential | `webauthn.dll`이 플랫폼 인증기로 P-256 자격 증명을 만들고, COSE 공개키를 뽑아낸다 |
| Hello assertion | 실제 생체 승인 → authenticatorData/clientDataJSON/DER 서명 → UP·UV 플래그와 challenge 일치까지 로컬 검증 |
| .zbacs association | 레지스트리에 확장자가 등록되어 있는지 |
