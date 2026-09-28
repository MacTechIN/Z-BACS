# Z-BACS Agent (Z-1.G.1~G.3, G.7~G.12, H.8, U.5)

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
| 잠그기 | 창 어디든 드롭하거나 [파일 고르기]. 권한 2택 + "고급"에 유효 시간·횟수 프리셋. `<원래이름>.zbacs`를 옆에 만들고, 이미 있으면 덮어쓰지 않고 거절한다 |
| 원본 처리 | 잠근 뒤에도 **원본 평문은 그대로 남는다.** 결과 화면이 그 사실을 말하고, 2단계 확인 뒤 덮어쓰고 지울 수 있다(T09) |
| 주인에게 물어보기 (G.9) | 잠긴 파일 카드의 [주인에게 물어보기] → 진행 링 + "주인의 허락을 기다리는 중…" + [취소]. 기기를 Relay에 등록하고 서명한 요청을 보낸 뒤 2초마다 받은편지함을 읽는다. 답이 오면 파일·버전·기기·요청이 내 것과 맞는지 확인하고(T05/T19) 허락받음/거절/시간 초과(300s)/취소/연결 불가를 각각 한 문장 + 다음 행동으로 보여 준다. 120초가 지나면 "아직 답이 없어요"로 바꾸고 계속 기다린다 |
| 허락하기 (G.10) | 준비가 끝난 Agent는 3초마다 주인 받은편지함을 읽는다. 요청이 오면 창을 앞으로 가져와 S5 화면: 파일명·정책은 **이 컴퓨터의 잠금 기록**(`sealed.json`)에서, 요청에서는 "무엇을·언제"만 가져온다(T06). 기록에 없거나 버전이 다른 파일은 [거절]만 보인다. [읽기만 허락]/[편집도 허락]은 EIP-712 digest를 기기 서명기로 서명하고(편집·연속 승인은 OS 확인, T23) 파일 키를 요청 기기용으로 다시 싸서 보낸다 |
| 허락 거두기 (G.11) | 홈의 [내가 허락한 파일] → 카드마다 남은 시간과 [허락 거두기]. 누르면 Relay가 그 파일을 요청했던 모든 기기에 알리고 기록에 "거둠"으로 남는다. 받은 쪽 Agent는 허락 뒤에도 받은편지함을 계속 읽어 거둬지면 즉시, 시간이 끝나면 스스로 세션을 닫고 "주인이 허락을 거뒀어요"/"허락한 시간이 끝났어요"를 보여 준다 |
| 기록 (G.12) | 홈의 [기록] → S10: 잠금·요청·허락·거절·거둠(+열람·만료·문제)을 최근 순으로, 칩으로 걸러 본다. `audit.jsonl`에 한 줄씩 덧붙이는 로컬 기록이며 파일명은 이 컴퓨터의 잠금 기록에서만 온다(받은 파일은 "받은 파일"). 키·내용·상대 신원은 적지 않는다. 체인이 연결돼 있으면 공개 기록의 `Granted`/`Revoked`/`VersionBumped`가 이 컴퓨터의 파일에 한해 "· 확인됨"으로 합쳐진다 |
| 공개 기록 (H.8, `chain.rs`) | `ZBACS_CHAIN_RPC`가 있으면 연결한다(아래 표). 잠그면 `register`, 허락하면 `grant`(소유자 계정 자신이 호출하므로 두 번째 서명 없음 — ADR-0008), 수신자의 저장을 받아들이면 `bumpVersion`, 거두면 `revoke`. 허락 답에 `tx_hash`가 실리고, 받은 쪽은 그것으로 `isValid`를 읽어 소유자의 말을 확인한다; 체인의 revoke만으로도 세션이 끝난다(T20). 첫 실행에 소유자 주소가 프로필에 확정된다. 체인이 거부하거나 닿지 않아도 잠금·허락은 그대로 되고 `pending`으로 말한다 |
| 열기 단계 (G.7, `open.rs`) | 허락받은 봉투를 이 기기 키로 열어 DEK를 얻고, 파일이 허락받은 그 버전인지 확인한 뒤(T19) 보호 작업공간에 복호화한다. 읽기만이면 읽기전용 속성, 저장은 폐기(T07). 세션이 어떻게 끝나든 wipe(T09). 편집 허락이면 저장 시 `save`가 이 기기 키로 새 버전을 재봉인하고(소유자 봉투는 헤더의 `opub`으로, ADR-0007) 주인에게 버전 통지를 보낸다 — 주인은 파일 없이 그 통지의 봉투로 새 버전을 다시 허락할 수 있다. 아직 UI·뷰어 실행에 연결되지 않았고 E2E 하네스가 헤드리스로 검사한다 |
| 열기 (S6, `session.rs`) | 허락받은 카드의 [열기] → 작업공간에 복호화 → 그 파일 종류의 연결 프로그램 실행(개발·테스트는 `ZBACS_VIEWER="prog args"`) → 저장 감지: 편집이면 새 버전으로 재봉인하고 주인에게 알림, 읽기만이면 폐기 → 앱 종료·[지금 잠그기]·회수·만료 중 먼저 오는 것으로 끝나고 항상 wipe. 화면은 열린 금고 + 남은 시간 + [지금 잠그기] → "다시 잠겼어요" |
| 알림에서 바로 답하기 (U.5) | 요청이 오면 데스크톱 알림. Windows 토스트에는 [읽기만 허락][편집도 허락][거절][앱에서 보기]가 있고, 누르면 화면과 같은 경로로 처리된다(OS 확인 포함) → "허락했어요" 토스트. 다른 OS는 버튼 없이 "앱에서 답해 주세요". 토스트가 안 보이면 설치 바로가기(AUMID)가 없는 개발 빌드일 수 있다 — `ZBACS_TOAST_POWERSHELL=1`로 임시 확인 |

웹뷰 권한은 `capabilities/default.json` 하나이고 `core:event:default`와 `dialog:allow-open`만 허용한다 — 파일 읽기·쓰기·셸·네트워크는 웹뷰에서 쓸 수 없다. 파일 내용은 항상 Rust 쪽에서만 다룬다.

## Relay 주소

사용자 설정은 없다. 호스팅된 Relay가 생기면 그 주소를 내장한다(Z-1.H.11, `docs/beta_test_automation.md` L2). 그 전까지 기본값은 `http://127.0.0.1:8787`이고, 개발자는 `ZBACS_RELAY_URL`(쉼표로 여러 개)로 바꾼다:

```
cargo run -p zbacs-relay                                  # 다른 터미널
ZBACS_RELAY_URL=http://127.0.0.1:8787 cargo tauri dev
```

## 체인 연결

| 변수 | 뜻 |
|---|---|
| `ZBACS_CHAIN_RPC` | 노드 주소. 없으면 체인 없이 동작 |
| `ZBACS_CHAIN_DEPLOYMENT` | `deployments/<chainId>.json` 경로(기본: 체크아웃의 `contracts/deployments/31337.json`) |
| `ZBACS_CHAIN_KEY` | 개발용 자금 키(hex) → 일반 트랜잭션. 사람의 기기에는 절대 두지 않는다 |
| `ZBACS_BUNDLER_URL` | 번들러(+페이마스터) → 소유자 스마트계정 UserOp. 쉼표로 여러 개, 순서대로(T21) |
| `ZBACS_PAYMASTER_POLICY` | Pimlico 스폰서 정책 id |

배포본에는 이 값들이 **빌드 때 내장**된다(Z-1.H.11): `ZBACS_BUILD_RELAY_URL`/`ZBACS_BUILD_CHAIN_RPC`/`ZBACS_BUILD_BUNDLER_URL`/`ZBACS_BUILD_PAYMASTER_POLICY`/`ZBACS_BUILD_DEPLOYMENT`(json 파일 경로)를 `build.rs`가 `ZBACS_EMBEDDED_*`로 굽고, 런타임 변수가 있으면 그것이 우선한다. 자금 키는 내장하지 않는다. 플랫폼 패스키 기기에서는 수신자 저장에 따른 `bumpVersion`이 다음 탭의 UserOp에 배치로 묶인다(ADR-0008 §5).

```
anvil &  (cd ../../contracts && forge script script/Deploy.s.sol --rpc-url anvil --broadcast --private-key $PK)
ZBACS_CHAIN_RPC=http://127.0.0.1:8545 ZBACS_CHAIN_KEY=$PK ZBACS_RELAY_URL=http://127.0.0.1:8787 cargo tauri dev
cargo test --features demo-signer --test chain    # 헤드리스: Anvil을 스스로 띄워 잠금→허락→저장→회수를 공개 기록과 맞춰 본다
```

## 아직 하지 않는 일

OS 기본 연결 프로그램으로 열면(`ZBACS_VIEWER` 없음) 프로세스를 추적할 수 없어 앱 종료를 알 수 없다 — 그때는 [지금 잠그기]·회수·만료가 세션을 끝낸다(Windows에서는 ShellExecuteEx 추적이 후속). 체인 설정이 없는 기기에서는 허락이 Relay로만 전달되고(`tx_hash` 없음) EIP-712 서명은 Anvil 배포(`Deployment::DEV`)에 묶이며, 수신자의 소유자 확인은 `owner_signature_check` pending으로 개발 패널에만 나온다. 스마트계정 경로(`ZBACS_BUNDLER_URL`)는 코드가 있지만 테스트넷 배포와 그 값들(Relay 주소·Pimlico 키 — 사용자)이 있어야 실제로 돈다.

파일을 체인에 등록하는 일(Z-1.H.4/H.8), 계정을 체인에 만드는 일(Z-1.H.8), 이 기기를 그 계정에 등록하는 일(Z-1.H.10)도 아직이다. 첫 실행은 이것을 `pending`으로 돌려주며, **사용자에게는 보여주지 않는다** — 우리가 끝낼 일이지 사용자가 알 일이 아니다(ux_principles §2). 개발용 정보 패널에는 그대로 나온다.

## UI 규칙

`ui/`는 `packages/design-tokens/tokens.css`의 변수만 쓴다(CLAUDE.md 규칙 8). 그 파일은 빌드 때 `build.rs`가 복사하므로 `ui/tokens.css`를 손으로 고치지 말 것(gitignore 대상).

사용자에게 보이는 문구는 전부 `ui/`에 있다. 백엔드는 `"biometric"`, `"volatile_key_store"` 같은 **기계값만** 돌려주고 문장을 만들지 않는다 — 그래야 `tools/ux-lint.sh`가 화면의 말을 한곳에서 검사할 수 있다.

```
tools/ux-lint.sh   # 금지 용어(U-5), 텍스트 입력 0개(U-6), 토큰만 사용, id/data-role 일치, 오류 카탈로그 일치
```

오류는 기계값으로만 넘어오고(`relay_unreachable`, `not_sealed`…) 문장과 버튼은 `ui/app.js`의 `*_PROBLEMS` 표에 있다. 전체 목록과 각 오류의 다음 행동은 `docs/design/ui_strings.md` §7. 새 기계값은 백엔드 모듈의 `*_PROBLEMS` 상수 → app.js → §7 순서로 넣는다; 빠지면 `tests/errors.rs`나 린트가 잡는다.
