# Windows 실기 확인 체크리스트

| 문서 버전 | 1.3 (2026-09-21: §3.6 잠그기 추가) |
|---|---|
| 대상 | Z-1.A.2(Windows Hello), Z-1.A.7(TPM 기기 키), Z-1.A.3(자격 증명 저장소), Z-0.G.1(파일 연결), Z-1.G.2(첫 실행), Z-1.G.3(잠그기), Z-1.G.6(열람 앱 저장 감지) |
| 도구 | `crates/zbacs-wincheck` — 한 번에 전부 검사하고 PASS/FAIL을 출력 |

Linux CI에서는 이것들을 검증할 수 없다(TPM·Hello·레지스트리). Windows 전용 코드는 `cargo check --target x86_64-pc-windows-gnu --workspace --exclude zbacs-relay-client --exclude zbacs-chain`로 컴파일까지 확인했고, **실제 동작 확인만 Windows에서 필요**하다.

`zbacs-relay-client`와 `zbacs-chain`을 제외하는 이유: rustls의 암호 백엔드가 Windows용 C 크로스 툴체인을 요구하는데, 이 크레이트에는 Windows 전용 코드가 한 줄도 없어 크로스체크로 얻을 것이 없다. 실제 Windows 빌드는 CI의 `windows-latest` 러너가 확인한다(기본 백엔드 대신 `ring`을 쓰는 것도 Windows에서 cmake·NASM 없이 빌드되게 하려는 선택이다).

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

## 3. 파일 연결 더블클릭 (Z-0.G.1 / Z-1.G.1 Windows 확인)

이제 스파이크가 아니라 **실제 Agent**로 확인한다. Linux에서는 deb로 확인했다(Exec %U·MIME 등록, 인자 수신, 단일 인스턴스 전달). Windows 확인:

```
cd apps\agent\src-tauri
cargo tauri build --bundles nsis
```

`target\release\bundle\nsis\` 의 설치 파일을 실행한 뒤:

1. 아무 파일이나 `test.zbacs`로 이름을 바꾼다.
2. 더블클릭한다.
3. 앱이 뜨고 화면에 **그 파일 경로**가 보이면 성공.
4. 앱이 떠 있는 상태에서 다른 `.zbacs`를 더블클릭하면 **새 창이 아니라 기존 창**이 경로를 받아야 한다(단일 인스턴스).
5. 창을 닫아도 트레이 아이콘이 남아야 하고, 트레이 메뉴의 "창 열기"로 다시 열려야 한다. "종료"로만 완전히 끝난다.

결과를 알려 주면 `docs/dev_plan.md`의 Z-0.G.1 항목에 Windows 확인을 기록한다.

## 3.5 첫 실행 2탭 (Z-1.G.2 / Z-1.U.1 / Z-1.U.7 DoD)

설치 직후 처음 실행하면 나오는 흐름이다. **여기서 아무것도 입력하지 않아야 한다.** Linux에서는 첫 화면이 뜨는 것까지 확인했고(소프트웨어 대역 서명기 사용), 실제 Hello·TPM 경로는 Windows에서만 확인된다.

1. 앱을 처음 실행하면 **"내 파일을 잠글 준비가 됐어요"** 화면이 나온다. → [시작하기] (**탭 1**)
2. **"누군가 파일을 열려고 하면"** 화면에 버튼이 두 개 나온다.
   - "얼굴이나 지문으로 확인하고 승인" — Hello가 설정돼 있으면 **추천** 표시가 붙어 있어야 한다.
   - "이 기기에서 바로 승인"
   - Hello를 설정하지 않은 PC에서는 첫 번째 버튼이 **흐리게 비활성**이고 그 이유가 적혀 있어야 한다.
3. 하나를 누른다 (**탭 2**). 얼굴/지문을 고르면 **Windows Hello 창이 한 번** 뜬다.
4. "준비 끝" 화면이 나오면 성공. 여기서 **"전용 보안 칩이 없어요" 문구가 보이면 안 된다**(TPM이 있는 PC이므로).
5. [내 파일 보기] (**탭 3**) → 홈 화면.
6. **앱을 완전히 종료(트레이 → 종료)하고 다시 실행**한다. 첫 실행 화면이 **다시 나오면 안 된다** — 바로 홈이어야 한다. 다시 나온다면 자격 증명 저장소나 기기 키가 유지되지 않은 것이므로 알려 달라.
7. Hello 창에서 **취소**를 눌러 보고, "확인이 취소됐어요. 다시 눌러 주세요."가 나오는지 확인한다.

확인할 것을 한 줄로: **탭 3번 안에 끝나고, 타이핑이 0번이고, 두 번째 실행에서는 첫 실행 화면이 안 나온다.**

로그(앱 실행 콘솔)에 `screen: welcome → choice → working → done → home` 순서와 `setup complete: style=... hardware=true`가 남는다. 문제가 생기면 이 줄들을 그대로 붙여 달라.

## 3.6 파일 잠그기 (Z-1.G.3 DoD)

첫 실행을 마친 뒤 홈에서 [파일 잠그기]. Linux에서 왕복(잠근 파일이 다시 열리고 평문이 일치)은 통합 테스트로 확인했고, Windows에서 확인할 것은 **탐색기에서 끌어다 놓기**와 **파일 고르기 창**이다.

1. 아무 문서 파일을 탐색기에서 **창 안으로 끌어다 놓는다**. 끄는 동안 점선 영역이 반응하고, 놓으면 파일 이름과 크기가 보여야 한다.
2. [파일 고르기]로도 같은 파일을 고를 수 있어야 한다.
3. 기본값 그대로 [잠그기] → 같은 폴더에 `<원래이름>.zbacs`가 생긴다.
4. **같은 파일을 한 번 더 잠가 본다.** "같은 이름으로 잠근 파일이 이미 있어요"가 나와야 하고, 먼저 만든 `.zbacs`가 **그대로 남아 있어야** 한다(크기·수정시각 확인).
5. 결과 화면에 "원본 파일은 그대로 남아 있어요"가 보인다. [원본 지우기] → 확인 문구 → [지우기]. 원본이 사라지고 `.zbacs`는 남아야 한다.
6. "고급"을 펼쳐 유효 시간·횟수를 바꿔 다른 파일을 잠가 본다. **어디에도 숫자를 입력하는 칸이 없어야 한다.**
7. 잠근 `.zbacs`를 더블클릭하면 §3의 흐름대로 Agent가 그 파일을 집어야 한다.

## 4. 열람 앱 3종 저장 감지 (Z-1.G.6 DoD)

Word·메모장·PDF 뷰어가 실제로 파일을 어떻게 저장하는지는 Windows에서만 확인할 수 있다. Agent가 아직 없으므로 지금은 **감지 메커니즘만** 확인한다.

```
cargo test -p zbacs-session --test viewer
```

Linux에서 통과한 것과 같은 12개가 Windows에서도 통과해야 한다(`cmd /C timeout` 프로세스로 대체 실행). 그다음 실제 앱으로:

1. 임시 폴더에 `test.txt`를 만들고 **메모장**으로 연 뒤 저장 → Agent가 붙으면 저장 1회가 감지되어야 한다.
2. `test.docx`를 **Word**로 열고 저장 → Word는 `~$test.docx` 잠금 파일을 만들고 임시 파일을 rename 한다. 우리 감시자는 디렉터리를 보고 rename 대상만 인정하므로 **저장 1회**로 보여야 한다(잠금 파일은 무시).
3. PDF 뷰어(Acrobat/Edge)로 주석을 달고 저장 → 위와 같은 패턴.

Agent UI가 나오기 전(Z-1.G.1~G.3)에는 이 항목을 ◐로 두고, Agent가 생기면 세 앱으로 실제 세션을 돌려 확정한다.

## 5. 결과 보고

아래만 알려 주면 된다:

- `cargo run -p zbacs-wincheck` 1회차 출력 전체
- 재부팅 후 2회차의 summary 줄과 TPM keyId
- 3번 더블클릭 결과 (성공/실패)
- 3.5번 첫 실행: 탭 횟수, 두 번째 실행에서 첫 화면이 나왔는지, `screen:` 로그 줄
- 3.6번 잠그기: 끌어다 놓기·파일 고르기·중복 거절·원본 지우기 결과
- 4번 `cargo test -p zbacs-session --test viewer` 결과

## 부록: 무엇이 실제로 검사되나

| 검사 | 확인하는 것 |
|---|---|
| keychain round-trip | Credential Manager(DPAPI)에 비밀을 쓰고 그대로 읽는다 — 사용자가 키를 관리하지 않아도 재부팅을 넘기는 근거 |
| TPM key | `NCryptCreatePersistedKey`가 Platform Crypto Provider에 P-256 키를 만들고, 개인키는 프로세스 메모리에 **존재하지 않는다**(내보내기 불가) |
| TPM key signature | TPM 서명을 low-s로 정규화해 `zbacs-auth` 검증기가 통과 — 온체인 `P256Validator`와 같은 규칙 |
| Hello credential | `webauthn.dll`이 플랫폼 인증기로 P-256 자격 증명을 만들고, COSE 공개키를 뽑아낸다 |
| Hello assertion | 실제 생체 승인 → authenticatorData/clientDataJSON/DER 서명 → UP·UV 플래그와 challenge 일치까지 로컬 검증 |
| .zbacs association | 레지스트리에 확장자가 등록되어 있는지 |
