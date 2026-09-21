# Z-BACS 대화 기록 (history.md)

> **[원칙]** 사용자와의 대화를 원본 그대로 시계열로 이 파일에 기록한다. 작업을 마무리할 때마다 그 작업의 사용자 메시지와 Claude 최종 응답을 추가한다. 도구 호출·중간 출력은 기록하지 않는다.
> 표기: `[U]` 사용자, `[C]` Claude. 원칙 지정(#19) 이전은 백필이며 Claude 응답은 요약(`[C·요약]`)이다. 사용자 메시지 원문은 이 세션의 각 커밋 메시지와 `docs/`에 반영돼 있다.

---

## 2026-09-18

| # | 발화 | 내용 |
|---|---|---|
| 1 | [U] | 타당성 분석 보고서를 바탕으로 프로젝트 정의서(project_definition.md), 기술 검토(research.md), 개발 계획서(dev_plan.md)와 개발에 필요한 모든 문서를 docs 아래 생성하고 향후 개발 시 항상 참조하도록 프로젝트를 설정할 것. 코드명 Z-BACS(Zero-Knowledge & Blockchain-based Access Control System). 핵심 요구: BSA 파일 암호화, 전달된 파일이 열릴 때 소유자 승인(읽기전용/거부/편집), 자체 실행 기능(Windows 우선), 저장 시 재암호화·재승인 |
| 1 | [C·요약] | 웹 리서치 후 docs/ 문서 세트(정의서·기술검토·개발계획·아키텍처·위협모델·specs·ADR·가이드라인·용어집·인덱스), CLAUDE.md, git init |

## 2026-09-19

| # | 발화 | 내용 |
|---|---|---|
| 2 | [U] | `Rust 설치와 Foundary 설치 방법알려줘` |
| 2 | [C·요약] | rustup, Tauri 의존성, cargo 도구, foundryup 설치 안내 |
| 3 | [U] | `깃 허브 : https://github.com/MacTechIN/Z-BACS.git` |
| 3 | [C·요약] | origin 연결, 저장소 로컬 git 사용자 설정, main 초기 커밋 4c008be 푸시 |
| 4 | [U] | Rust와 Foundry 설치를 실행하고 tools/setup.sh로 정리, foundryup 단계만 남았으니 전체 시스템 확인 후 설치 |
| 4 | [C·요약] | 시스템 점검, Foundry 1.8.3·cargo-audit·cargo-fuzz 설치, PATH 등록, tools/setup.sh·setup.ps1·README |
| 5 | [U] | `커밋하고 푸시해줘` |
| 5 | [C·요약] | 9ff58c9 푸시 |
| 6 | [U] | `Z-0.D.3 CI 골격이랑 Z-0.C.1 컨테이너 PoC 진행해줘` |
| 6 | [C·요약] | crates/zbacs-core(컨테이너 v1 + HPKE 봉투), zbacs-cli, 테스트 10종, 100MB 왕복 0.35s, ci.yml, 스펙 1.1, 연구 노트 |
| 7 | [U] | `커밋하고 푸시해줘` |
| 7 | [C·요약] | 735cfde 커밋. 푸시 거부(workflow 스코프 없음) → gh auth refresh 요청 |
| 8 | [U] | 프로젝트 목표 [개발원칙]: 사용자가 아무것도 몰라도 쓸 수 있는 UX가 최종 목표. 복잡한 등록·절차·환경설정을 하나도 몰라도 사용 가능하게 |
| 9 | [U] | UI도 Figma의 현재 디자인 가이드를 열어 가져오고 그 가이드대로 생성하여 사용 |
| 8·9 | [C·요약] | docs/ux_principles.md, 정의서·아키텍처·dev_plan·CLAUDE.md 반영, reference/figma.md, Figma 연결 확인, 파일 URL 요청 |
| 10 | [U] | `gh auth refresh 완료했어, 커밋하고 푸시해줘` |
| 10 | [C·요약] | bf2a635 푸시. CI audit 실패(hpke-rs 0.2 권고 4건, 액션 권한) → hpke-rs 0.7, 권한 수정, ea5e74e 푸시, CI 통과 |
| 11 | [U] | `.orca/drops/Foundations (A안 올리브).pdf` 경로 전달 |
| 12 | [U] | `.orca/drops/D-GO Vault UI 디자인 설계 화면.zip` 경로 전달 |
| 13 | [U] | `UI UX용으로 기본 골격을 위한 가이드 라인으로 설정해줘` |
| 11~13 | [C·요약] | 두 소스 분석, D-GO Vault 기본 테마·올리브 대체 테마, docs/design/ui_guideline.md, packages/design-tokens, 원본 보관, 패스워드 UI 충돌 명시, 기본 테마 확인 요청 |
| 14 | [U] | `커밋하고 푸시해줘` |
| 14 | [C·요약] | 2d18813 푸시 |
| 15 | [U] | `커밋하고 푸시해줘` |
| 15 | [C·요약] | 변경 없음, 이미 푸시됨 안내 |
| 16 | [U] | `Z-0.H.1 Foundry EIP-712 PoC 진행해줘` |
| 16 | [C·요약] | contracts/ (AccessGrantLib, FileRegistry, AccessPolicy), 테스트 18개, Anvil 배포 확인, CI 서브모듈, 연구 노트 |
| 17 | [U] | `커밋 해야하나 ?` |
| 17 | [C·요약] | 커밋 권장과 이유 |
| 18 | [U] | `커밋 푸쉬 해줘` |
| 18 | [C·요약] | 6a8c2a4 푸시, CI 감시 시작 |

---

## 원문 기록 (원칙 지정 이후)

### #19 [U] 2026-09-19
```
지금부터 대화 내용은 원본 그대로 시계열로 history.md 파이롤 기록하고 모든 작업 마무리하면 대화 내용 기록 하도록 [원칙]
```

### #20 [U] 2026-09-19 (작업 중 추가 메시지)
```
다음 진행
```

### #19·#20 [C] 2026-09-19
```
대화 기록 원칙을 설정했습니다.

- `history.md`(프로젝트 루트)를 만들었습니다. 원칙 지정 이전 대화 18건은 사용자 메시지 요지와 제 응답 요약으로 백필했고, 원칙 지정 메시지(#19)부터는 사용자 메시지와 제 최종 응답을 원문 그대로 기록합니다.
- `CLAUDE.md` 작업 규칙 9번에 이 원칙을 넣었습니다. 작업을 마무리할 때마다 최종 응답 직전에 `history.md` 끝에 추가합니다. 도구 호출과 중간 출력은 기록하지 않습니다.
- 메모리에도 저장해 다음 세션에서도 지켜집니다.

앞선 시도에서 이전 대화 전체를 원문으로 옮기던 중 출력이 중단돼 파일이 만들어지지 않았습니다. 그래서 백필은 요약 표로 줄였고, 원문 기록은 #19부터 시작합니다.

CI 결과: 커밋 6a8c2a4의 실행이 전부 통과했습니다. foundry 잡이 처음으로 실제로 돌았고 서브모듈 체크아웃, 포맷 검사, 빌드, 테스트 18개가 GitHub 환경에서도 성공했습니다.

`history.md`와 `CLAUDE.md` 변경은 아직 커밋하지 않았습니다. 앞으로는 각 작업 커밋에 `history.md` 갱신을 함께 포함하겠습니다. 다음 태스크는 Z-0.G.1 Tauri 파일 연결 스파이크 또는 Z-0.H.2 패스키 스마트계정 스파이크입니다.
```

### #21 [U] 2026-09-19
```
커밋하고 푸시해줘
```

### #21 [C] 2026-09-19
```
커밋하고 푸시했습니다.

- 커밋: docs: add history.md conversation log principle (CLAUDE.md rule 9)
- 포함: history.md 신규, CLAUDE.md 규칙 9번
- 원격 main이 최신 커밋으로 갱신됐습니다.
```

### #22 [U] 2026-09-19
```
Z-0.G.1 Tauri 파일 연결 스파이크 진행해줘
```

### #23 [U] 2026-09-19 (작업 중 추가 메시지)
```
계속 바로 진행 내가 결정할 것만 알려줘
```

### #24 [U] 2026-09-19
```
단계별로 커밋 을 모두 해줘
```

### #22~#24 [C] 2026-09-19 (1단계 커밋: 스파이크 본체)
```
Z-0.G.1 Tauri 파일 연결 스파이크를 spikes/tauri-assoc/에 만들었습니다(독립 워크스페이스, 루트 CI 영향 없음).
- tauri.conf.json fileAssociations(.zbacs, application/x-zbacs), NSIS currentUser 설치.
- 첫 실행 인자(std::env::args) + tauri-plugin-single-instance 콜백(Windows/Linux) + RunEvent::Opened(macOS)로 경로 수신, zbacs-core inspect로 헤더 요약을 zbacs://opened 이벤트로 웹뷰 전달, take_pending으로 조기 도착 파일 회수.
- 검증(Ubuntu headless, xvfb + dbus-run-session): 인자 2개 수신·검사·자동 종료, 두 번째 인스턴스 70ms 종료 후 첫 인스턴스가 파일 수신, 단위 테스트 2개 통과.
- 규칙 추가: CLAUDE.md 10번 "단계별 커밋", 메모리 저장.
deb 번들 빌드는 진행 중이며 결과는 다음 커밋에 반영합니다.
```

### #22~#24 [C] 2026-09-19 (2단계 커밋: deb 파일 연결)
```
deb 번들을 빌드해 파일 연결 등록을 확인했습니다. Tauri 기본 .desktop 템플릿은 Exec에 %U가 없어 Linux 더블클릭 시 경로가 앱에 전달되지 않는 문제가 있었고, 커스텀 템플릿(Exec %U)과 shared-mime-info XML(*.zbacs, ZBACS 매직)을 번들에 추가해 해결했습니다. 재빌드한 deb에 Exec %U, MimeType, zbacs.xml이 들어간 것을 확인했습니다.
```

### #25 [U] 2026-09-19
```
현재 진행 상황
```

### #25 [C] 2026-09-19
```
테스트까지 돌려서 실제 상태를 확인했습니다.

## 현재 위치: Phase 0 (셋업·스파이크), 종료 기준 5개 중 3개 완료

완료 (main 클린, 원격 동기화됨 — 최신 28be090)
- Z-0.D.1/D.2/D.3 모노레포 스캐폴드, tools/setup.sh, GitHub Actions CI
- Z-0.C.1/C.2 컨테이너(XChaCha20-Poly1305 청크 + CBOR 헤더 + Ed25519) + HPKE 봉투 — cargo test 9 passed / 1 ignored(perf), 100MB 왕복 0.35s
- Z-0.H.1 FileRegistry, AccessPolicy, EIP-712 AccessGrant — forge test 18 passed (T03/T14/T15/T20 매핑)
- Z-0.G.1 Tauri 2 .zbacs 파일 연결 스파이크 — Linux headless 확인(인자 수신, 단일 인스턴스 전달, deb Exec %U + MIME 등록)
- Z-1.U.0 ◐ docs/design/ui_guideline.md, packages/design-tokens/tokens.css — 부분(Figma URL 연결·Code Connect 남음)

남은 Phase 0 항목
- Z-0.H.2 — Base Sepolia RIP-7212 실측 + permissionless.js 패스키 스마트계정. Linux에서 지금 바로 가능한 유일한 게이트 스파이크.
- Z-0.A.1/A.2 — Windows Hello webauthn.dll 네이티브 호출. Windows 실기 필요(Z-0.G.1 Windows 더블클릭 확인도 같이).
- Z-0.A.3 — BSA 샌드박스 Client Key 신청(OR-1, 외부 의존).
- Z-0.Q.1 — 위협 T01~T20 → 태스크 매핑 검토(문서 작업).

결정이 필요한 것 두 가지
1. 다음 작업으로 Z-0.H.2(체인 스파이크)를 진행할지, Z-0.Q.1(위협모델 매핑)을 먼저 정리할지. 추천은 Z-0.H.2 — 게이트 항목이고 Windows 없이 끝낼 수 있는 마지막 스파이크.
2. BSA Client Key 신청(OR-1)은 제가 할 수 없는 외부 절차. 진행 여부를 알려주시면 Z-1.A.5를 mock 기반으로 설계할지 판단.

참고로 CLAUDE.md의 "5개 스파이크 중 4개 완료"는 실제로는 3개(C.1, G.1, H.1)입니다 — C.2를 게이트 항목으로 중복 계산한 것으로 보입니다. 다음 커밋에서 같이 고칠까요?
```

### #26 [U] 2026-09-19
```
Z-0.H.2 진행하고 CLAUDE.md도 같이 고쳐줘
```

### #27 [U] 2026-09-19 (작업 중 추가 메시지)
```
개발 진행 상황
```

### #26~#27 [C] 2026-09-19
```
Z-0.H.2 완료, 커밋·푸시했습니다. spikes/aa-passkey/ (Node + Foundry, 루트 CI 제외).

결과
- OR-2: P256VERIFY(0x…0100)가 Base Sepolia·Base 메인넷·OP Sepolia·Ethereum Sepolia 모두 활성. 포크 실측 3,885 gas vs Daimo Solidity 폴백 334,897 gas.
- 패스키 UserOp: permissionless.js toKernelSmartAccount(Kernel v3.1 + WebAuthn 검증기)로 소프트웨어 패스키 계정 생성 → 서명된 UserOp → Base Sepolia 포크의 실제 EntryPoint v0.7 handleOps 통과(계정 배포 + 호출 실행). 10/10 tests. T14 변조 → AA24, T03 재전송 → AA25, viem userOpHash == 온체인 해시.
- 가스: permissionless 기본(Solidity P-256) 789,620 → usePrecompiled=true 450,310 (−43%).

발견
1. permissionless.js 0.4.1이 Kernel WebAuthn 서명에 usePrecompiled=false를 하드코딩(소스 TODO) — Phase 1 Z-1.H.8에서 서명 인코딩을 직접 제어해야 함.
2. 프리컴파일은 high-s 서명을 거부하지 않음 — low-s 정규화는 클라이언트(ox가 처리)·검증기 책임.
3. node:crypto sign(null, digest)가 digest를 다시 SHA-256 함 — 온체인 검증기 교차검증으로 발견, 벡터 생성기 수정.

미실행: 실제 번들러 제출은 PIMLICO_API_KEY 필요 → --send 옵션만 구현, Z-1.H.8로 이관. 포크의 EntryPoint 직접 호출과 번들러 경로의 차이는 mempool 규칙(ERC-7562)뿐.

문서: CLAUDE.md(3/5→4/5 정정, 스파이크·다음 작업 반영), dev_plan Z-0.H.2 ✅, research.md OR-2 ✅, ADR-0005 실측치, docs/research/aa_passkey_spike.md 신규.

Phase 0 남은 것: Z-0.A.1(Windows 실기 필요), Z-0.A.3(BSA Client Key 신청 — 외부, 결정 필요), Z-0.Q.1(위협 매핑 리뷰, 바로 가능).
```

### #28 [U] 2026-09-19
```
실제 번들러 제출 문제 있나 ?
```

### #28 [C] 2026-09-19
```
짧게: 테스트를 안 했을 뿐, 알려진 막힘은 없습니다. 다만 실제 제출 전에 해결해야 할 것이 셋 있습니다.

1. 가스 지불 — 포크에서는 vm.deal로 EntryPoint에 예치했지만 실제 체인의 카운터팩추얼 계정은 잔고가 0입니다. 해법은 (a) Pimlico 테스트넷 페이마스터(무료 스폰서) 또는 (b) 계정 주소에 Base Sepolia ETH 소량 입금. 현재 --send 경로는 (b)만 가정하고 있어 페이마스터 필드가 없습니다 — 실제로 쓰려면 paymaster 연결을 추가해야 합니다.
2. 번들러 API 키 — PIMLICO_API_KEY가 없어서 --send가 미실행입니다. 무료 티어면 충분합니다.
3. ERC-7562 mempool 규칙 리스크 — usePrecompiled=true는 검증 단계에서 0x…0100을 호출합니다. 번들러가 이 주소를 허용 프리컴파일 목록에 넣어놨는지가 관건입니다(Pimlico alto는 Base에서 RIP-7212 지원으로 알려져 있지만 실측 전). permissionless 기본값(usePrecompiled=false, Solidity 폴백)은 금지 opcode를 안 쓰므로 이 리스크가 없습니다. 그래서 첫 실제 제출은 기본값으로, 프리컴파일 변형은 두 번째로 시험하는 순서가 맞습니다.

Kernel v3.1 + WebAuthn 검증기 자체는 Pimlico가 공식 지원하는 조합이고, 포크에서 EntryPoint 검증·실행이 통과했으므로 서명·인코딩 문제는 없습니다.

키를 주시면(PIMLICO_API_KEY=…) 페이마스터 스폰서 경로를 붙여서 바로 1건 제출해 보겠습니다. 없으면 이대로 Z-1.H.8에 남겨둡니다.
```

### #29 [U] 2026-09-19
```
Z-0.Q.1 위협 매핑 리뷰 진행해줘
```

### #30 [U] 2026-09-19 (작업 중 추가 메시지)
```
PIMLICO_API_KEY 키 등록 방법 알려줘
```

### #29~#30 [C] 2026-09-19
```
Z-0.Q.1 완료, 커밋·푸시했습니다.

리뷰 결과 (docs/dev_plan.md 부록 A 전면 개정, threat_model.md v1.1)
- 누락: T08(화면 촬영)이 표에 없었음 → "범위 밖, 추적성만 Z-2.G.4"로 명시.
- 깨진 참조: T17이 Z-2.S.1/2를 가리켰는데 이 태스크는 Phase 1(Z-1.S.1/2)로 이동해 존재하지 않는 ID였음 → 정정.
- 잘못된 매핑: T04/T05가 "Z-1.C.2(HPKE)"를 가리켰으나 C.2는 파서 견고화. HPKE 정식화는 Z-1.C.1, T05(요청자 바꿔치기)는 기기 키(Z-1.A.3)+요청 서명(Z-1.R.1)이 실제 완화 → 정정.
- 완화 항목이 있는데 태스크가 빠진 것 보강: T03 세션 1회 소비(G.4), T06 알림 액션 표시(U.5), T07 감사 로그(H.3/G.12), T10 저장 감지(G.6), T11 DPAPI(A.3), T12 백업·복구 UX(A.4/2.U.1), T13 페이마스터(H.9), T16 체인 이벤트 폴백(H.7), T20 이벤트 구독·코드 서명(H.7/G.13).
- "현재 근거" 열 신설: Phase 0 테스트 이름(t02/t04/t18/t19 core, t03/t14/t15/t20 contracts, t03/t14 aa-passkey)을 위협에 연결. 근거가 아직 없는 위협은 "—"로 보이게 해서 Phase 1에서 채울 목록이 됨.
- 스파이크에서 나온 새 위협 2건 추가:
  T21 번들러·페이마스터 검열/지연(D) → 다중 번들러, 자체 예치 폴백, EntryPoint 직접 handleOps 경로 유지.
  T22 클라우드 동기화 패스키 복제(BE/BS 플래그)(S) → 등록 시 플래그 기록, 기기 바운드 우선, 소유자 정책 옵션.
- T14에 "P-256 low-s 강제(프리컴파일은 high-s 거부 안 함)", T17에 "파일 연결/단일 인스턴스 인자는 경로로만 취급" 보강.

Phase 0 남은 것: Z-0.A.1(Windows 실기), Z-0.A.3(BSA 키 신청).

PIMLICO_API_KEY 등록 방법
1. https://dashboard.pimlico.io 가입(GitHub/이메일) → 왼쪽 메뉴 API Keys → Create API Key → 이름 아무거나 → 생성된 키(pim_…) 복사. 무료 티어로 충분하고 Base Sepolia 가스 스폰서(페이마스터)도 테스트넷은 무료입니다.
2. 프로젝트 등록: spikes/aa-passkey/.env.example을 .env로 복사해 값만 채우면 됩니다(.env는 gitignore 대상, 절대 커밋되지 않음).
   cp spikes/aa-passkey/.env.example spikes/aa-passkey/.env  →  PIMLICO_API_KEY=pim_… 입력
   실행: cd spikes/aa-passkey && node --env-file=.env scripts/kernel-account.mjs --send
   (또는 셸에서 export PIMLICO_API_KEY=pim_… 후 --send)
3. 주의: 현재 --send는 계정 잔고로 가스를 내는 경로만 있어 실제 체인에서는 잔고 0으로 실패합니다. 키를 채워 놓으셨다고 알려주시면 Pimlico 페이마스터(스폰서) 경로를 붙여 1건 제출하고 결과를 기록하겠습니다. 키 값 자체는 저에게 보내지 마세요 — .env에만 두면 됩니다.
```

### #31 [U] 2026-09-19
```
cp spikes/aa-passkey/.env.example spikes/aa-passkey/.env
sam@maindev:~/workspace/security/BSA_remote_file_auth_system/Z-BACS$ nano .env
sam@maindev:~/workspace/security/BSA_remote_file_auth_system/Z-BACS$ cd spikes/aa-passkey && node --env-file=.env scripts/kernel-account.mjs --send
passkey credential: J-fTVJ695SulhZx1JGc6uB38Xy8KYNp3qk7oZGZ0FcM
public key x=0x51f279fdc7069acf49d57e2ce753b4b3267e9cfdc3128282d031e58dce34dd4f
           y=0xf20a0a346b5c52fe4272cd20b0717990297dc246deae8fc16af9cd13980edf9d
Kernel v3.1 account (counterfactual): 0xc5EeD39265fcf6447d778B902830EbEaB3878001 deployed=false
factory: 0xd703aaE79538628d27099B8c4f621bE4CCd142d5 (516 bytes init data)
userOpHash: 0x3bf3d9c478c68f32a19813b28d1ecdb162c8a979934b34510390f0f998f0c741
signature: 480 bytes (WebAuthn assertion, usePrecompiled=false)
wrote vectors/userop.json
--send needs PIMLICO_API_KEY
```

### #31 [C] 2026-09-19
```
키가 잘못된 파일에 들어갔습니다. nano .env를 리포 루트(Z-BACS/)에서 열었는데, 스크립트는 spikes/aa-passkey/.env를 읽습니다. 확인 결과 spikes/aa-passkey/.env는 .env.example과 바이트 단위로 동일(키 비어 있음)하고, 루트에는 .env 파일이 아예 없습니다(저장이 안 됐거나 다른 곳에 저장됨). 키 값 자체는 확인하지 않았습니다.

고치는 방법:
  nano spikes/aa-passkey/.env      ← PIMLICO_API_KEY=pim_… 한 줄만 채우고 저장
  cd spikes/aa-passkey && node --env-file=.env scripts/kernel-account.mjs --send

그 사이 --send 경로를 실제로 동작하게 바꿔 커밋했습니다:
- Pimlico 번들러 + 테스트넷 페이마스터(가스 스폰서) 연결 → 계정 잔고 0이어도 제출 가능.
- --precompile 플래그: usePrecompiled=true로 서명·스텁 서명을 재인코딩해 번들러가 0x…0100 호출을 허용하는지(T21/ERC-7562) 측정.
- 출력: userOpHash, 포함된 tx·블록, success, 실제 가스, Basescan 링크.

키를 채우고 알려주시면 제가 두 번(기본 → --precompile) 제출하고 결과를 docs/research/aa_passkey_spike.md에 기록하겠습니다. 직접 돌려보셔도 됩니다.
```

### #32 [U] 2026-09-19
```
여기 메세지가 copy 하기 위한 블록이 잡히지 않아
```

### #32 [C] 2026-09-19
```
코드 블록 없이 한 줄씩 적겠습니다. 각 줄을 드래그해서 복사하면 됩니다.

1단계 — 키 넣기 (파일 편집기로 열어서 수정)
파일 경로: spikes/aa-passkey/.env
그 안의 PIMLICO_API_KEY= 줄 뒤에 키를 붙여 저장하면 됩니다. 터미널이면 아래 명령 한 줄(pim_여기에키 부분만 바꾸세요):
sed -i 's/^PIMLICO_API_KEY=.*/PIMLICO_API_KEY=pim_여기에키/' spikes/aa-passkey/.env

2단계 — 제출 실행
cd spikes/aa-passkey
node --env-file=.env scripts/kernel-account.mjs --send
프리컴파일 변형까지 보려면:
node --env-file=.env scripts/kernel-account.mjs --send --precompile

키를 넣으신 뒤 "넣었어"라고만 알려주시면 제가 두 번 실행하고 결과를 기록하겠습니다.
```

### #33 [U] 2026-09-19
```
sed -i 's/^PIMLICO_API_KEY=.*/PIMLICO_API_KEY=[REDACTED — 키 값은 기록에서 제외]/' spikes/aa-passkey/.env
sed: can't read spikes/aa-passkey/.env: No such file or directory
```

### #33 [C] 2026-09-19
```
실제 번들러 제출 2건 모두 성공했습니다. (sed 실패 원인: 이미 spikes/aa-passkey 안에 있어서 상대 경로가 어긋난 것. 제가 절대 경로로 .env에 키를 넣고 실행했습니다.)

| 변형 | 결과 | actualGasUsed | tx |
| permissionless 기본(usePrecompiled=false) | success, Kernel 배포+실행 | 757,792 | 0x2bf5…05f7 (블록 47,013,308) |
| --precompile(usePrecompiled=true) | success | 418,432 (−45%) | 0x8e64…340c (블록 47,013,314) |

- 가스는 전부 Pimlico 테스트넷 페이마스터가 스폰서(계정 잔고 0).
- 번들러가 검증 단계의 0x…0100 프리컴파일 호출을 허용 → T21/ERC-7562 리스크 해소.
- 첫 실행의 "deployed: false"는 공개 RPC latest 지연(실제로는 61B 프록시 배포됨) → 포함 블록 기준 조회로 수정.
- --send는 이제 vectors/live-userop*.json에 쓰고 포크 픽스처(userop.json)는 건드리지 않음. 포크 테스트 10개 재확인.

보안: 키 값이 채팅에 붙여넣기로 노출됐습니다. history.md에는 [REDACTED]로 기록했고 .env는 gitignore라 커밋되지 않지만, Pimlico 대시보드에서 키를 폐기(Revoke)하고 새로 발급해 .env만 바꿔 두시길 권합니다. 무료 티어라 피해는 없어도 습관으로.

문서: docs/research/aa_passkey_spike.md §2b(실제 제출 기록), dev_plan Z-0.H.2·T21 근거, CLAUDE.md, 스파이크 README 갱신. Z-0.H.2는 번들러까지 완결.
```

### #34 [U] 2026-09-19
```
가스는 전부 Pimlico 테스트넷 페이마스터가 스폰서(계정 잔고 0)  -> 이런 것이 왜 필요해 ? 가스 ??
```

### #34 [C] 2026-09-19
```
짧게 설명하면:

가스 = 체인에 뭔가를 쓸 때 내는 수수료입니다. Z-BACS에서 소유자가 "이 파일, 이 사람, 읽기만, 24시간" 승인을 하면 그 승인 티켓·회수·감사 기록이 Base 체인에 기록됩니다(승인 프로토콜 spec의 온체인 앵커). 체인에 쓰는 모든 트랜잭션은 ETH로 수수료를 내야 하고, 그 수수료가 가스입니다. 금액은 작지만(테스트 결과 418k gas ≈ Base 메인넷 기준 몇 원 수준) 0은 아닙니다.

문제: 우리 최상위 원칙은 "사용자는 아무것도 몰라도 된다"입니다. 그런데 가스를 사용자가 내려면 — 1. 지갑을 만들고 2. 거래소에서 ETH를 사서 3. 그 지갑에 넣어 두고 4. 잔고가 떨어지면 다시 채워야 합니다. 온보딩에서 이걸 요구하는 순간 원칙이 깨집니다.

해법이 페이마스터: ERC-4337에서 "이 사용자의 수수료는 내가 대신 낸다"고 서명해 주는 계약입니다. 사용자의 스마트계정 잔고가 0이어도 트랜잭션이 통과합니다. 그래서 실험에서 계정에 ETH를 한 푼도 안 넣고도 배포·승인 실행이 됐습니다. 실제 돈은 서비스 운영자(우리)가 페이마스터에 미리 예치해 두고, 사용자는 가스라는 개념 자체를 모릅니다. 테스트넷에서는 Pimlico가 무료로 해 줬고, 운영에서는 우리가 예치하거나 Pimlico 같은 사업자에게 카드 결제로 충전합니다.

한 줄로: 가스는 체인 수수료이고, 페이마스터는 그 수수료를 사용자 대신 서비스가 내게 해서 "지갑·코인 없이 쓰는" 원칙을 지키는 장치입니다. dev_plan에서는 Z-1.H.9(페이마스터 설정), 위협모델 T21(페이마스터가 막히면 자체 예치로 폴백)이 이 부분입니다.
```

### #35 [U] 2026-09-19
```
이것이 우리 프로젝트에 꼭 필요해 ? 우리가 직접 블록체인 을 생성하고 관리하고 운영하면 안되나 ?
```

### #35 [C] 2026-09-19
```
좋은 질문이고, 실제로 ADR-0005에서 한 번 검토했던 갈림길입니다.

먼저: 체인이 우리 프로젝트에서 하는 일
승인 프로토콜에서 체인에 올라가는 건 세 가지뿐 — 정책 해시 앵커(T02), 승인/회수 nonce(T03), 감사 로그(T07). 파일도 키도 안 올라갑니다. 필요한 성질은 "양쪽 당사자도, 우리도 나중에 못 고치는 기록"이지 블록체인이라는 기술 자체가 아닙니다.

세 가지 선택지
A. 공개 L2(Base) + 페이마스터(현재): 사용자 가스 0, 우리가 운영할 것 없음(페이마스터 예치만), 수천 노드 검증으로 "우리도 못 고침", 프라이버시는 해시만 올려도 관찰 가능(T13), 번들러·페이마스터·L2 외부 의존(T21), 실제 제출 2건으로 검증됨.
B. 자체 체인 운영: 가스 0 설정 가능, 검증 노드 24/7·업그레이드·모니터링·키 관리 필요, 우리만 검증하면 DB와 같음(컨소시엄 노드 있어야 의미), 완전 비공개, 외부 의존 없음, Besu에 P256 프리컴파일·4337 번들러 붙이는 것부터 재확인 필요.
C. 체인 없이 투명성 로그: 가스 없음, 로그 서버 1대, 머클 루트 외부 공개(또는 하루 1번 공개 체인 앵커)로 사후 변조 탐지, 완전 비공개, 외부 의존 없음, 구현 단순.

제 판단
B(자체 체인)는 가장 안 좋은 조합. 체인 운영 부담은 다 지면서 검증자가 우리뿐이면 "변조 불가"라는 유일한 장점이 사라짐 — 서명된 DB에 블록체인 인프라를 얹은 셈. ADR-0005가 "운영 부담 과다"로 기각한 이유. 고객사 컨소시엄이 전제되면 달라지지만 그건 Phase 3.
진짜 갈림길은 A vs C. A 유지: 이미 동작 확인, 제3자 검증 가능, "블록체인 기반" 정체성 유지, 대신 페이마스터 운영비(소액)·외부 의존. C: 가스·페이마스터·번들러 전부 사라지고 단순해짐, 대신 "우리를 믿어야" 하는 부분이 생기고 하루 1회 앵커링으로 보완.
규칙 6(벤더는 트레이트 뒤에) 덕분에 지금 결정 안 해도 됨 — zbacs-chain 인터페이스 뒤에 A든 C든 꽂을 수 있음. 다만 MVP에서 뭘 먼저 구현할지는 정해야 함.

결정을 위해 하나만: 이 프로젝트에서 "블록체인 기반"이 제품의 핵심 가치(BSA 연계·마케팅·차별점)인가, 아니면 "변조 못 하는 기록"을 얻기 위한 수단이었나?
- 전자면 → A 유지, 페이마스터는 운영비로 흡수(Z-1.H.9).
- 후자면 → C를 MVP로, A는 앵커링 용도로 축소. ADR-0006 작성하고 dev_plan H 트랙 축소.
답 주시면 그에 맞춰 ADR을 작성하겠습니다.
```

### #36 [U] 2026-09-19
```
전자 후자야 모두 사용해야 하는것 아닌가? 블록체인 기반에 변조 못하는 기록을 얻어서 그것을 가지 우리 프로젝트 목표를 달성 하기 위해 사용 해야하는 것 이 맞는거 같아
```

### #36 [C] 2026-09-19
```
맞습니다 — 그게 A입니다. "블록체인 기반"이 정체성이고, 그 위에서 얻는 변조 불가 기록이 수단인 구조. 결정을 ADR-0005에 재확인으로 기록했습니다(자체 체인·투명성 로그 대안 기각 사유, 가스는 사용자에게 비노출·페이마스터는 운영비 흡수(Z-1.H.9)·장애 시 자체 예치 폴백(T21) 포함). 커밋·푸시 완료. 설계 변경 없음 — 현재 dev_plan 그대로 진행합니다.
```

### #37 [U] 2026-09-19
```
우리가 운영할 블록체인은 어떤 것이며 어떤 원리로 작동하는지 그리고 그것을 실제로 테스트 하고 이용하는 방법을 설명하고 테스트 가능하도록 해줘
```

### #37 [C] 2026-09-19
```
문서와 실행 가능한 데모를 만들었습니다. 커밋·푸시 완료.

1. docs/chain_guide.md (블록체인 가이드) — 요지:
- 우리는 체인을 만들거나 운영하지 않는다. 공개 L2 Base 위에 컨트랙트 3개(FileRegistry, AccessPolicy, AuditLog)를 올려 "누가 어떤 파일을 누구에게 어떤 권한으로 승인·회수했는지"를 아무도 못 고치는 장부에 기록한다.
- 환경 3개, 코드 동일: Anvil(내 PC 시뮬레이터, 개발·데모) / Base Sepolia(테스트넷, 무료) / Base 메인넷(운영).
- 원리: 계정=개인키, 트랜잭션=서명된 함수 호출, 블록=2초마다 묶음(이전 해시 포함 → 과거 변경 불가), 컨트랙트=배포 후 우리도 우회 못 하는 규칙, 이벤트=감사 로그, 읽기 무료/쓰기 가스. L2 롤업: 시퀀서 블록 → 이더리움 L1에 데이터 기록 → 누구나 재실행 검증 → 시퀀서도 우리도 못 고침. 가스·페이마스터: 승인 1건 418k gas ≈ 수 센트, 우리가 대납(Z-1.H.9), 장애 시 자체 예치 폴백(T21).
- 패스키→체인 흐름: Windows Hello → EIP-712 서명 → Kernel 스마트계정 UserOp → 번들러 → EntryPoint(P-256 프리컴파일 검증) → AccessPolicy.grant → Granted 이벤트 → Bob은 isValid 읽기만(무료).
- 올라가는 것(솔트 해시·권한·만료·nonce·revoke) / 절대 안 올라가는 것(파일·이름·DEK·개인정보·기기키 원문).
- 테스트 4단계: (1) forge test 18개 (2) tools/chain-demo.sh 로컬 시나리오 (3) Base Sepolia 포크 테스트 + 실제 제출(basescan 링크·읽는 법) (4) Phase 1 E2E. cast 치트시트, 운영에서 관리하는 것/안 하는 것, FAQ.

2. tools/chain-demo.sh + contracts/script/Demo.s.sol — 실행 결과:
Anvil 자동 시작 → 배포 2건 → Alice 파일 등록 → Alice EIP-712 서명 "읽기전용·1시간·2회" → grant (isValid true) → Bob consumeOpen (opens 1) → 같은 서명 재제출 거부(T03) → Alice revoke (isValid false). 블록 6개(트랜잭션당 1개), 이벤트 Granted/Opened/Revoked를 ABI로 디코딩해 표시, 마지막 트랜잭션 영수증(status true, gasUsed 32,888). --keep이면 Anvil을 켜 두고 cast로 직접 조회 가능.

3. 문서 인덱스(docs/README.md), tools/README.md, CLAUDE.md 참조 목록에 추가. forge fmt·forge test 18개 통과 확인.
```

### #38 [U] 2026-09-19
```
windows hello 는 뭐야
```

### #38 [C] 2026-09-19
```
Windows Hello는 Windows 10/11에 내장된 로그인 방식 — 비밀번호 대신 얼굴·지문·PIN으로 PC를 잠금 해제하는 기능.

속에서 벌어지는 일
- 처음 설정할 때 PC의 보안 칩(TPM)이 안에서 개인키를 만듦. 이 키는 칩 밖으로 절대 나오지 않음(디스크·메모리·MS 서버 어디에도 없음).
- 얼굴/지문/PIN은 "칩에게 서명을 허락하는 열쇠"일 뿐. 생체 정보도 PC 밖으로 안 나감.
- 앱이 서명을 요청하면 Windows가 생체 인증 창을 띄우고, 통과하면 TPM이 P-256 서명을 돌려줌.
- 이 표준이 WebAuthn/FIDO2, 그렇게 만든 키가 패스키(passkey). 브라우저 비밀번호 없는 로그인과 같은 것.

우리 프로젝트에서의 역할
- 소유자가 "허용" → Windows Hello 창 → TPM이 승인 내용(EIP-712 AccessGrant)에 서명 → 그 서명이 곧 스마트계정 소유권 증명 → 체인 기록. 사용자에게는 "얼굴 한 번"이 전부. 지갑·시드·비밀번호가 없어도 되는 이유.
- Z-0.H.2의 virtual-authenticator.mjs가 흉내 낸 것이 정확히 이 부분. 실제 Agent에서는 getFn 한 함수만 진짜 Windows Hello 호출로 교체.
- 그 진짜 호출이 Z-0.A.1: webauthn.dll을 Rust에서 불러 생체 창을 띄우고 서명을 받는 스파이크. Windows에만 있는 DLL이라 Linux에서는 불가, Windows 실기 필요. Phase 0의 유일한 남은 게이트.

Windows 실기 조건: Windows 10 1903+ 또는 11, TPM 2.0, 지문 리더/IR 카메라(없으면 PIN도 동작). 준비되면 Z-0.A.1 진행.
```

### #39 [U] 2026-09-19
```
굿이 그렇게 하지말고 소유자가 허용 을 누르면 소유자가 허용한 H/W PC,Mobile,tablet 에서만 인증키를 생성해서 키로 나가거나 윈도우 hello 를 이용해서 생성하는 방법을 선택할수 있도록 두가지 다 가능하도록 넣어줘
```

### #39 [C] 2026-09-19
```
설계에 반영했습니다(ADR-0006, Spec-first). 커밋·푸시 완료.

결정: 소유자 스마트계정에 두 종류 서명자를 등록할 수 있고, 소유자가 기기마다 선택한다.
- A. 플랫폼 패스키 — Windows Hello / Touch ID / Android 생체. 승인마다 얼굴·지문·PIN 창. 온체인 검증은 기존 Kernel WebAuthn 검증기.
- B. 기기 바운드 키(DeviceKey) — Agent가 그 기기의 하드웨어 저장소(Windows TPM, Android Keystore, iOS Secure Enclave)에 내보내기 불가 P-256 키를 생성. 등록된 기기에서 "허용" 탭만으로 승인, 기기별로 OS 확인을 켤 수 있음. 온체인 검증은 새 P256Validator(계정당 키 집합, 프리컴파일 + 폴백, low-s 강제).
- 사용자에게 보이는 선택지는 "얼굴/지문으로 확인하고 승인" / "이 기기에서 바로 승인" 두 개뿐(온보딩 1화면, 이후 "내 기기"에서 변경). 기술 용어·입력 필드 없음. 기본값: OS 인증기 있으면 A, 없으면 B.
- 기기 등록 = 이미 등록된 기기가 새 기기를 허용(첫 기기는 온보딩 자동). 해지 = 다른 등록 기기에서 탭 한 번. 둘 다 체인 기록(T12/T22).
- 두 경로 모두 같은 EIP-712 AccessGrant를 만들고 Bob 쪽 검증(ERC-1271)은 변화 없음.

안전장치(새 위협 T23 — 무프롬프트 기기 키를 소유자 PC의 악성코드가 자동 승인에 악용): 키 사용은 Agent UI의 명시적 탭에만 연결, Edit 권한 승인·10분 내 5건 초과는 서명자 종류와 무관하게 OS 확인 강제(기본 정책), 다른 기기에서 즉시 해지.

문서 변경: ADR-0006 신규, approval_protocol §1.5(OwnerSig 두 형식, DeviceEnroll/DeviceRevoke), architecture §5 키 계층·§6, threat_model v1.2(T23), dev_plan(Z-1.A.7 DeviceKeyProvider, Z-1.H.10 P256Validator+기기 등록/해지, Z-1.U.7 선택 UI — Figma 먼저, Z-1.G.2 온보딩 갱신, 부록 A T12/T22/T23), ADR-0003 참조, CLAUDE.md.

부수 효과: Windows Hello 스파이크(Z-0.A.1)가 더 이상 Phase 0 게이트가 아님 — 경로 B의 P-256 서명은 Z-0.H.2에서 이미 체인까지 검증됨. Phase 0 종료. Z-0.A.1은 Windows 실기 확보 시 Phase 1 Z-1.A.2 선행으로 진행.

다음 제안: Phase 1 시작 — Z-1.A.1 AuthProvider 트레이트(+DeviceKeyProvider 인터페이스)와 Z-1.C.1 core 정식화. 지정해 주시면 시작합니다.
```

### #40 [U] 2026-09-19
```
다음 진행
```

### #40 [C] 2026-09-19
```
Phase 1 첫 태스크 Z-1.A.1 완료 — crates/zbacs-auth 신규. 커밋·푸시 완료.

내용
- AuthProvider 트레이트: kind / key_id(keccak256(x‖y)) / public_key / supports_os_confirmation / sign(challenge, confirmation). 구현체 자리: PasskeyProvider(Z-1.A.2), DeviceKeyProvider(Z-1.A.7), BsaProvider, OtakProvider.
- 타입(spec §1.5 그대로): ApprovalChallenge{digest, context{permission, file_id}}, ApprovalAssertion = WebAuthn | P256Raw | Bsa | Otak, Confirmation = NotRequired | OsUserVerification, DeviceEnroll/DeviceRevoke + 도메인 분리 keccak 다이제스트.
- ConfirmationPolicy(T23): Edit 승인 또는 10분 내 5건 이상이면 기기 설정과 무관하게 OS 확인 요구. 기기 설정보다 약해지지 않음.
- verify_assertion: P-256 검증(RustCrypto p256), low-s 강제(HighS), WebAuthn UP/UV 플래그, clientData challenge 일치, BE/BS(동기화 패스키) 플래그 파싱(T22).
- 소프트웨어 서명기(feature software-signer, 테스트·데모 전용): SoftwareDeviceKey, SoftwarePasskey — Windows Hello/TPM 자리에 끼우는 대역.
- 테스트 12개: 두 경로 왕복, t14 변조·타키·UV 제거·challenge 불일치 거부, t03/t14 high-s 거부, t22 동기화 플래그, t23 정책 2종, 등록/해지 다이제스트, JS 스파이크가 만든 WebAuthn assertion을 Rust가 검증하는 교차 구현 벡터.
- CI 게이트 통과: cargo fmt, clippy -D warnings, cargo test --workspace (auth 12 + core 9 + cli 1).

문서: architecture §3.2 트레이트 갱신, research.md(p256/sha3), dev_plan Z-1.A.1 ✅, CLAUDE.md.

다음: Z-1.C.1(core 정식화) 또는 Z-1.H.10(P256Validator 컨트랙트 — 경로 B를 체인에서 받는 부분). 지정 없으면 Z-1.C.1로 갑니다.
```

### #41 [U] 2026-09-19
```
다음 진행
```

### #41 [C] 2026-09-19
```
Z-1.C.1 완료 — zbacs-core 정식화. 커밋·푸시 완료.

내용
- 고정 길이 식별자 타입: FileId(32), HeaderHash(32), KeyId(16), Salt(16), NoncePrefix(16). CBOR 바이트열로 직렬화되므로 PoC 컨테이너와 와이어 호환, 길이 검사는 타입이 강제(런타임 검사 제거).
- Sealer / Opener 트레이트(객체 안전, &mut dyn Read/Write): OwnerKeys: Sealer, DeviceKeys: Opener(내장 봉투), GrantedDek: Opener(승인으로 받은 DEK — 수신자 경로). Agent가 Box<dyn Opener>로 런타임 선택.
- 에러 전 변이 문서화 + non_exhaustive, 키·평문 미포함 보장.
- 공개 API 전부 문서화(#![warn(missing_docs)]) + CI에 RUSTDOCFLAGS=-D warnings cargo doc 게이트.
- 커버리지 게이트: cargo llvm-cov -p zbacs-core -p zbacs-auth --fail-under-lines 90을 CI(ubuntu)에 추가. 현재 라인 96.3% (core container 97%, header 98%, keys 100%).
- 테스트 추가 11개(tests/api.rs) + 단위 5개: 트레이트 왕복, t04 승인 DEK 경로(수신자는 내장 봉투 없음 → NoEnvelope, 승인 DEK로 열림, 잘못된 DEK는 청크 누출 없이 NameAuth), 재봉인 체인(ver 2, prev = v1 해시, 새 np·salt), seal_to_path 원자성, 빈 파일, t18 청크 크기·헤더 길이 상한·미지원 cipher·chunk 0, t19 트레일러 뒤 잔여 바이트, read_header 위치, 에러 메시지.
- CI 게이트 전부 통과: fmt, clippy -D warnings, test --workspace(auth 13 + core 9+11+9 + cli 1), rustdoc, coverage.

문서: architecture §3.1(구현 반영), dev_plan Z-1.C.1 ✅, dev_guidelines(커버리지·문서 게이트), CLAUDE.md(빌드 명령 2줄 추가).

다음: Z-1.C.2 파서 견고화(악성 입력 20종·트레일러) → Z-1.C.3 cargo-fuzz, 또는 체인 쪽 Z-1.H.10 P256Validator. 지정 없으면 Z-1.C.2.
```

### #42 [U] 2026-09-19
```
다음 진행
```

### #42 [C] 2026-09-19
```
Z-1.C.2 완료 — 컨테이너 파서 견고화. 커밋·푸시 완료.

Spec-first: docs/specs/container_format.md v1.1 — §2.2에 필드 제한 표(fid/salt/np/prev/sigk/sig 고정 길이, ver ≥ 1이고 ver==1 ⇔ prev==null, own 1..64B, name ≤ 1040B, env 1..32개·enc/ct ≤ 1024B, 헤더 ≤ 1MiB, minor 상위 호환·major 불일치 거부), §4 개봉 절차 보강(서명 검증 후 필드 검사 → 키 사용, 파일명 복호화 실패 시 청크 전 중단, 트레일러 3항 + EOF, 오류 시 부분 출력 폐기).

코드: read_header에 validate_header(서명 검증 후·키 사용 전) 추가, reseal 버전 오버플로 checked_add, open_with_dek 문서에 부분 출력 폐기 규칙.

테스트 crates/zbacs-core/tests/malicious.rs 31종(요구 20종): 프레이밍 9(빈 입력, magic, major 3종, minor+1은 열림, 헤더 길이 0/상한/스트림 초과, CBOR 쓰레기·중간 절단), 서명 3(서명 바이트 3곳, 서명키 교체, 필드 수정 후 미서명), 필드 제한 7(fid 31B CBOR, cipher, chunk 0/16MiB+1, ver/prev 체인 3종, own, name, env 4종), 봉투 3(ct 변조·미지원 suite·타인 봉투만), plen 크게/작게, 청크 8(각 청크 인증, 복제, 마지막·첫 청크 삭제, 트레일러 6바이트 위치, 트레일러 누락/짧음, 뒤 잔여·컨테이너 2개 연결, 부분 출력 상한), 랜덤 변이 500회 + 전 길이 절단 sweep(무패닉·오답 평문 0).

게이트: clippy -D warnings, test --workspace(core 51 + auth 13 + cli 1), 커버리지 97.1%(container.rs 98.3%).

다음: Z-1.C.3 cargo-fuzz(헤더·청크 타깃) 또는 Z-1.H.10 P256Validator. 지정 없으면 Z-1.C.3.
```

### #43 [U] 2026-09-19
```
당음
```

### #44 [U] 2026-09-19 (작업 중 추가 메시지)
```
다음
```

### #43~#44 [C] 2026-09-19
```
Z-1.C.3 cargo-fuzz 진행 — 타깃·스크립트·CI 완료, 24h 실행만 남음(◐). 커밋·푸시 완료.

만든 것 (crates/zbacs-core/fuzz/, 루트 워크스페이스에서 제외)
- header: 원시 바이트 → magic/길이/CBOR/서명/제한 (프레이밍·디코딩 표면)
- header_signed: 퍼저가 HeaderBody를 구조적으로 생성 → 고정 키로 서명 → read_header + 임의 DEK로 open. 서명 이후 단계(validate_header, 청크 루프)까지 도달
- open_mutated: 유효 컨테이너 5종(0B~1000B, 청크 4~64)에 비트플립·바이트 치환·삽입·삭제·절단 최대 16회 → 열리면 평문이 원본과 같아야 함(속성 검사)
- envelope: HPKE enc/ct/aad/alg 임의값
- tools/fuzz.sh [24h|5m] [target]: nightly + cargo-fuzz, 4 workers, 크래시 아티팩트 있으면 실패
- .github/workflows/fuzz.yml: 매일 02:00 KST, 타깃당 20분, 크래시 입력 아티팩트 업로드
- nightly 툴체인 설치, dev_guidelines·tools/README 퍼징 절차

스모크 결과: 타깃당 150초, 총 약 300만 실행(header 1.55M @10k/s, header_signed 274k, open_mutated 659k, envelope 510k), 크래시 0, header 타깃 커버리지 966 edges.

DoD(24h 무크래시)는 제 세션에서 하루를 점유할 수 없어 사용자 머신 실행으로 남겼습니다: tools/fuzz.sh 24h (24코어면 4 workers×4 타깃 병렬 가능). 끝나면 결과 알려주시면 ✅로 바꾸겠습니다.

다음: Z-1.H.10 P256Validator(경로 B를 체인에서 받는 검증기 + 기기 등록/해지), 또는 Z-1.C.4 재봉인(버전 체인·원자적 교체). 지정 없으면 Z-1.H.10.
```

### #45 [U] 2026-09-19
```
PS C:\Users\이상진> tools/fuzz.sh 24h
tools/fuzz.sh : 'tools/fuzz.sh' 용어가 cmdlet, 함수, 스크립트 파일 또는 실행할 수 있는 프로그램 이름으로 인식되지 않습
니다. ...
 어디서 실행 해야해 ?
```

### #45 [C] 2026-09-19
```
이 스크립트는 Linux 개발 머신(maindev, 리포가 있는 곳)용 bash 스크립트라 Windows PowerShell에서는 안 됩니다(cargo-fuzz도 Windows에서는 불안정). 24시간짜리라 터미널을 닫아도 계속 돌도록 제가 maindev에서 백그라운드(nohup + setsid)로 띄웠습니다.

- 실행 위치: maindev:~/workspace/security/BSA_remote_file_auth_system/Z-BACS
- 명령: nohup setsid tools/fuzz.sh 24h > crates/zbacs-core/fuzz/logs/fuzz-24h.log &
- 순서: header → header_signed → open_mutated → envelope, 각 6시간(21,600초), 4 workers
- 확인: tail -f crates/zbacs-core/fuzz/logs/fuzz-24h.log / pgrep -af "fuzz run"
- 중단: pkill -f "fuzz.sh 24h"; pkill -f "fuzz run"
- 끝나면 로그 마지막에 "== no crashes" 또는 크래시 아티팩트 목록이 찍힙니다. 내일 이 시간 이후 알려주시면 결과를 확인하고 dev_plan을 ✅로 바꾸겠습니다.

직접 돌리고 싶을 때는 Windows에서 ssh sam@maindev 로 들어가 위 디렉터리에서 실행하면 됩니다.
```

### #46 [U] 2026-09-19
```
다 진행 해줘
```

### #46 [C] 2026-09-19 (1단계: Z-1.H.10)
```
Z-1.H.10 완료 — P256Validator(ADR-0006 경로 B를 체인에서 받는 ERC-7579 검증기). 커밋·푸시 완료.

컨트랙트 contracts/src/P256Validator.sol
- 계정별 기기 키 집합: enrollKey(x,y,requireOsConfirm) / revokeKey(keyId) — 호출자는 소유자 스마트계정 자신(즉 이미 등록된 기기가 서명한 UserOp). 첫 기기는 onInstall로 등록.
- keyId = keccak256(x‖y) — zbacs-auth와 동일. 서명 형식 keyId‖r‖s(96B) = spec §1.5 OwnerSig::P256Raw.
- 검증은 OZ P256.verify(RIP-7212 프리컴파일 + Solidity 폴백, s > n/2 거부) — 자체 구현 없음(규칙 2).
- validateUserOp는 view이고 _keys[sender][id]만 읽어 ERC-7562 번들러 스토리지 규칙 충족.
- 마지막 키는 해지 불가(계정 잠김 방지). requireOsConfirm은 온체인 기록(강제는 Agent의 ConfirmationPolicy, T23).
- ERC-1271 경로 + Agent용 dry-run isValidSignatureForAccount.

테스트
- 단위 16종(contracts/test/P256Validator.t.sol): 설치·등록·중복·잘못된 공개키, T12 두 번째 기기 등록/해지/마지막 키 보호/목록 일관성, T22 계정 격리, T14 변조·다이제스트 불일치·미등록 키, T03/T14 high-s 거부, 형식 오류, ERC-1271, 모듈 타입·언인스톨, 퍼즈(등록된 키만 통과).
- 포크 통합 4종(spikes/aa-passkey/test/DeviceKeyUserOp.t.sol, Base Sepolia): 실제 Kernel v3.1 팩토리로 계정 생성(우리 검증기를 root validator로) → 기기 키 UserOp 성공 216,221 gas → 노트북이 폰을 등록 → 폰으로 승인 → 폰이 분실된 노트북을 해지 → 해지된 노트북은 AA24, 재전송은 AA25.
- 가스 참고: 216k(기기 키, 계정 배포 후)와 418k(패스키, 계정 배포 포함)는 배포 포함 여부가 달라 직접 비교는 아닙니다. 다만 WebAuthn 래퍼(JSON·base64·이중 SHA-256)가 없어 검증 자체가 더 쌉니다.

문서: architecture §6에 P256Validator 행, dev_plan Z-1.H.10 ✅ + 부록 A(T12/T22/T23 근거), Deploy.s.sol에 배포 추가, CLAUDE.md.
```

### #46 [C] 2026-09-19 (2단계: Z-1.C.4)
```
Z-1.C.4 완료 — 재봉인. 커밋·푸시 완료.

Spec-first(container_format §5 확장): fid와 salt는 버전 간 불변임을 명문화했습니다. fid는 파일 정체성이자 온체인 FileRegistry의 키이고 bumpVersion(fileId, newHeaderHash)가 같은 fid 아래 최신 헤더를 갱신하므로, fid = SHA-256(plaintext_hash‖salt) 유도는 버전 1에만 적용됩니다(이후 내용 무결성은 header_hash + 트레일러). 이전 코드가 재봉인 때마다 fid를 새로 계산하던 것을 바로잡았습니다. 추가로 체인 규칙(ver+1, prev = 이전 헤더 해시, fid·salt 동일), 원자 교체(temp + rename), 새 DEK로 이전 승인 DEK 무효화(T20)를 스펙에 넣었습니다.

코드
- PrevVersion { header_hash, version, file_id, salt } + PrevVersion::of(&header, hash) — SealOptions.prev 타입 교체.
- reseal_to_path(plaintext, container, owner, policy): 기존 헤더에서 정체성·청크 크기·원본 파일명(소유자 봉투로 복호)을 승계해 ver+1로 원자 교체.
- verify_version_chain(&[(Header, HeaderHash)]): v1 시작, 연속 버전, prev 링크, fid·salt 불변, 헤더 해시 일치. 새 에러 Error::BrokenChain.
- decrypt_name 공개(Agent가 헤더만으로 파일명 복원).
- CLI: zbacs reseal --key --input --container [--perm --ttl --max-opens].

테스트 10종(tests/reseal.rs): v1→v2→v3 체인·정체성 불변·파일명 유지, T20 버전마다 새 DEK·np(이전 DEK로는 NameAuth), 재봉인 후 수신자 봉투 제거·정책 갱신, 원자성(temp 잔여 없음), 소유자 봉투 없으면 NoEnvelope이고 이전 버전 보존, T19 체인 검증 4종(시작·링크·버전 점프·다른 파일 접합·해시 불일치), 수동 PrevVersion 경로.

게이트: clippy -D warnings, rustdoc, test --workspace(core 61 + auth 13 + cli 1), 커버리지 97.3%.
```

### #46 [C] 2026-09-19 (3단계: Z-1.C.5)
```
Z-1.C.5 완료 — 파일명 암호화 강화, 정책 해시, 고정 테스트 벡터. 커밋·푸시 완료.

Spec v1.2
- 파일명 평문을 `u16 LE 길이 ‖ 이름 ‖ 0x00 패딩`으로 64바이트 배수까지 채운 뒤 암호화. 컨테이너를 가진 사람이 암호문 길이로 파일명 길이를 추측하던 누출을 막습니다(T13). 이름 ≤ 1024B, name 필드 ≤ 1104B.
- §2.2a 정책 해시: policy_hash = SHA-256("ZBACS-POL-v1" ‖ CBOR(pol)). 정책만 커버하므로 승인 UI 표시·버전 간 정책 비교용이고, 온체인 앵커는 계속 header_hash입니다.

코드: pad_name/unpad_name(패딩 바이트가 0이 아니면 거부 — 은닉 채널 차단), Policy::policy_hash / Header::policy_hash, PolicyHash 타입, 파서 길이 검사 갱신.

고정 벡터 crates/zbacs-core/tests/vectors/: v1.zbacs(ReadOnly) + v2.zbacs(재봉인, Edit) + owner.json(이 벡터 전용 폐기 키) + manifest.json(fid·salt·header_hash·policy_hash·plen·chunk·평문 SHA-256·prev). 회귀 테스트 2종이 매번 열어보고 매니페스트와 대조하므로 포맷이 바뀌면 바로 깨집니다. 파일명에 한글을 넣어 UTF-8·패딩도 함께 검증합니다. 재생성은 `cargo test -p zbacs-core --test vectors -- --ignored regenerate`.

게이트: clippy -D warnings, rustdoc, test --workspace 11 스위트 전부 ok, 커버리지 97.5%.
```

### #46 [C] 2026-09-19 (4단계: Z-1.C.6 — C 트랙 완료)
```
Z-1.C.6 완료 — 키 자료 위생 감사. 커밋·푸시 완료. 이로써 Core(C) 트랙은 C.3의 24시간 퍼징 실행만 남고 전부 완료입니다.

변경
- Dek을 secrecy::SecretBox<[u8;32]>로 전환 — drop 시 wipe, 접근은 expose_secret() 경유, Clone/Display 없음(규칙 3의 "SecretBox/secrecy" 명시를 코드로 반영).
- 모든 키 타입에 마스킹 Debug: Dek(REDACTED), DeviceKeys(kid=…, secret=REDACTED), SigningKeys(pub=…, secret=REDACTED), OwnerKeys. 파생 Debug는 금지.
- 평문 버퍼 wipe: seal의 스테이징 버퍼를 Zeroizing으로, open은 복호 청크를 기록 직후 zeroize, decrypt_name은 패딩 평문을 반환 전에 wipe.
- 회귀 방지: ZeroizeOnDrop 컴파일 타임 단언 + Debug 출력에 실제 비밀 16진수가 없는지 검사하는 테스트(t11_…).
- 감사 기록 docs/research/key_hygiene_audit.md: 비밀 자료 표(어디에 있고 어떻게 지워지는지), 코드 규칙 확인 결과, PR 체크리스트 5항목, 잔여 위험 4건(zeroize의 best-effort 한계·평문 파일·스왑/하이버네이션·코어 덤프)과 각각의 담당 태스크. dev_guidelines §2에 체크리스트 링크.

게이트: clippy -D warnings, rustdoc, test --workspace 전부 ok, 커버리지 97.6%, cargo audit 취약점 0(빌드 전용 매크로 크레이트 proc-macro-error2의 unmaintained 경고 1건만, 허용 범위).
```

### #46 [C] 2026-09-19 (5단계: Z-1.H.1 + Z-1.H.2)
```
Z-1.H.1, Z-1.H.2 완료 — 컨트랙트 정식화. 커밋·푸시 완료. 커버리지 라인·구문·브랜치·함수 전부 100%.

FileRegistry(H.1)
- retire(fileId): 소유자가 파일을 폐기하면 새 버전도, 새 승인도 불가(일방향). Retired 이벤트.
- currentVersion(fileId) -> (headerHash, version, retired) 뷰 추가.
- bumpVersion이 동일한 헤더 해시를 거부(SameHeaderHash) — 무의미한 버전 증가 방지.
- 테스트 8종, 브랜치 100%.

AccessPolicy(H.2)
- T19 버전 바인딩: grant()가 g.headerHash를 레지스트리의 현재 헤더 해시와 대조. 재봉인 후 옛 버전으로는 다시 승인할 수 없습니다(이게 없으면 회수 후에도 구버전 승인 티켓이 통과).
- 폐기된 파일은 새 승인 거부(FileRetired).
- consumeOpen(grantId, devicePubKeys): keccak256(devicePubKeys) == deviceKeyHash 요구 → 카운터를 승인된 기기의 공개키를 아는 호출자에게 바인딩. 체인에 Ed25519 프리컴파일이 없어 기기 자체의 서명 증명은 아니며 그 한계를 스펙·주석에 명시(원격 어테스테이션은 Z-3.H.3).
- grant 레코드에 deviceKeyHash·headerHash 저장(감사).
- 테스트 22종, 브랜치 100%. 기존 test_t15_already_expired_grant_rejected가 사실은 InvalidWindow를 검사하고 있어 이름을 바로잡고(empty window) 진짜 만료 경로 테스트를 추가했습니다.

스펙: approval_protocol v1.2 §3에 grant() 검증 순서(등록→폐기→버전 바인딩→권한→시간창→만료→nonce→서명), consumeOpen 서명과 한계, FileRegistry 함수 목록.
CI: contracts 잡에 forge coverage 요약 추가. tools/chain-demo.sh 재실행해 시나리오 정상 동작 확인.
```

### #46 [C] 2026-09-19 (6단계: Z-1.H.3)
```
Z-1.H.3 완료 — AuditLog. 커밋·푸시 완료.

컨트랙트: 이벤트 전용. Logged(fileId indexed, kind indexed, reporter indexed, actorCommit, detail), kind = Requested/Denied/Opened/Sealed/Failed. 스토리지·외부 호출 없음. actorCommit = keccak(deviceKid‖salt)로 기기 식별자를 가리고(T13), detail은 32바이트 자유 슬롯(Sealed의 새 헤더 해시, Denied의 사유 코드 등).

가스 DoD(≤30k/log): 처음엔 "등록된 파일만 기록" 검사를 넣었는데 레지스트리 조회의 콜드 접근(~4.7k) 때문에 실제 트랜잭션이 31,030 gas로 예산을 넘었습니다. 아키텍처 명세대로 이벤트 전용으로 되돌려 실측 25,515 gas로 통과. 대신 "누구나 아무 fileId로 기록할 수 있다"는 성질이 생기므로, 읽는 쪽이 자기가 아는 fileId로만 구독하고 항목은 reporter의 주장으로 취급한다는 점을 컨트랙트 주석·아키텍처에 명시했습니다(기기 서명의 온체인 검증은 Ed25519 프리컴파일이 없어 불가 — Z-3.H.3).

측정 방법 관련: 이 Foundry 버전에서 테스트 프레임 안의 gasleft()/lastCallGas는 하네스 오버헤드가 섞여 실제 트랜잭션과 크게 다릅니다(무동작 외부 호출이 21k로 측정). 그래서 가스 예산 검사는 tools/chain-demo.sh가 실제 Anvil 트랜잭션 영수증으로 하고(초과 시 실패), 단위 테스트는 비용을 평평하게 유지하는 구조적 성질(스토리지 쓰기 0, 이벤트 정확히 1개, 토픽 4개)을 고정합니다.

데모: chain-demo에 [4b] 단계 추가 — Bob이 Opened를, Alice가 Sealed를 기록하고, 마지막에 AuditLog.log 실제 가스를 예산과 대조해 출력합니다.

컨트랙트 전체: 55 tests, 커버리지 라인·구문·브랜치·함수 100%.
```

### #46 [C] 2026-09-19 (7단계: Z-1.R.1)
```
Z-1.R.1 완료 — Relay 프로토콜 정의. 커밋·푸시 완료.

스펙 docs/specs/relay_protocol.md v1
- 전제: Relay는 무신뢰. 평문·DEK·개인키를 못 보고 검열·지연만 가능. 보안은 소유자 EIP-712 서명과 HPKE 봉투에서 나오고 Relay는 배달만 합니다.
- 엔드포인트 7개: /v1/devices, /v1/requests, /v1/grants, /v1/revocations, /v1/inbox(폴링 폴백), /v1/stream(WebSocket), /v1/health.
- 서명 봉투 Signed<T>: payload(CBOR) + kid + kind + ts + nonce + Ed25519 서명. 서명 대상에 **메시지 종류(kind)** 를 포함해 한 메시지의 서명을 다른 종류로 재사용할 수 없게 했습니다.
- 메시지 8종(DeviceAnnounce/AccessRequest/GrantMsg/Revoke/Subscribe/Ack/Envelope + Kind), 오류 9종과 HTTP 매핑, 수명·할당량(본문 64KiB, 큐 24h, nonce 5분, 기기당 30/분, WS ping 60s), 프라이버시(Relay가 보는 것/못 보는 것, hint는 Phase 2에서 암호화), 셀프호스팅.
- 배달 방식: Relay는 원본 서명 바이트를 그대로 전달하고 수신자가 스스로 검증합니다(Envelope.body). Relay 서명은 배달 증거일 뿐 권한 근거가 아닙니다.

crates/zbacs-proto 신설 — 스펙을 실행 가능한 스키마로:
- Signed::sign/verify(kind 바인딩, ts 스큐 ±120s, kid 대조, payload 디코딩), to_bytes/from_bytes(64KiB 상한).
- DeviceIdentity(X25519 + Ed25519), kid = SHA-256(ed25519_pub)[..16] — 봉투 kid(X25519 해시)와 구분됨을 테스트로 고정.
- 테스트 14종: CBOR 왕복, T05 타 기기 서명·전 필드 변조 거부, T03 kind 재사용 거부, 스큐 경계, 본문 상한, 쓰레기 입력 무패닉, T04 Relay가 불투명 바이트를 전달하고 수신자가 검증, Deny엔 봉투 없음, 전 메시지 종류 서명·검증, 오류→HTTP 매핑, 비밀키 복원.

게이트: clippy -D warnings, rustdoc, cargo test --workspace 전부 통과.
```

### #47 [U] 2026-09-19
```
(Z-1.A.2/A.7, G 트랙 대부분)과 외부 절차(Z-0.A.3 BSA 키) 진행 해줘 내가 윈도우에서 할 것이 있으면 알려줘
```

### #47 [C] 2026-09-19 (1단계: Windows 하드웨어 경로 + BSA)
```
Windows 의존 코드를 전부 작성하고, Linux에서 cargo check --target x86_64-pc-windows-gnu로 컴파일까지 검증했습니다. 실제 하드웨어 동작만 Windows에서 확인하면 됩니다.

구현
- Z-1.A.3 zbacs-auth::store: KeyStore 트레이트 + OsKeyStore(Windows Credential Manager/DPAPI, macOS Keychain, Linux Secret Service) + MemoryKeyStore(헤드리스·테스트) + get_or_create(첫 실행 생성, 이후 로드 — 사용자에게 키를 보이지 않는 근거).
- Z-1.A.7 zbacs-auth::windows::device_key: NCrypt로 Platform Crypto Provider(TPM)에 P-256 영속 키 생성. 내보내기 정책을 설정하지 않아 개인키가 프로세스 메모리에 존재하지 않음. require_os_confirm이면 CNG UI 정책으로 Windows가 매 사용 시 동의/PIN 창을 띄움(T23의 OS 절반). TPM이 없으면 소프트웨어 KSP 폴백을 명시적으로 표시. 서명은 low-s 정규화(온체인 P256Validator 규칙과 동일).
- Z-1.A.2 zbacs-auth::windows::passkey: webauthn.dll MakeCredential/GetAssertion. clientDataJSON 직접 구성, UV 필수, attestedCredentialData에서 COSE 공개키(-2/-3) 파싱, DER 서명 → low-s (r,s). 사용자 취소는 AuthError::Cancelled로 구분(오류 아님).
- Z-1.A.5 BsaProvider: BsaClient 트레이트 + MockBsaClient. 테스트 4종(토큰이 다이제스트·신원에 묶임, 거부는 Cancelled, P-256 검증기가 BSA assertion 판정을 거부).
- zbacs-wincheck: Windows에서 한 번에 전부 검사하는 자가진단 바이너리.

Z-0.A.3(BSA 키)는 조직 명의 외부 신청이라 제가 대행할 수 없습니다. docs/research/bsa_sdk_notes.md에 신청 시 적을 내용과 받아올 규격 4가지(Client Key 발급·보관, 인증 요청 API, 결과 검증 방식, SDK 배포 형태·라이선스)를 정리했습니다. 키 값 자체는 보내지 마시고 .env나 자격 증명 저장소에 두시면 됩니다.

윈도우에서 하실 일은 docs/windows_checklist.md에 정리했고 요약은 최종 응답에 적었습니다.
```

### #47 [C] 2026-09-19 (2단계: G 트랙 — 세션·작업공간)
```
Z-1.G.4 완료, Z-1.G.5/G.7/G.8 구현 — crates/zbacs-session 신설. 커밋·푸시 완료.

Z-1.G.4 세션 상태머신: State(Requested/Granted/Open/Resealing/Closed/Denied/Revoked/Failed) × Event → Effect 목록(평문 생성, 읽기전용 표시, 뷰어 실행/종료 요청, 재봉인, 변경 폐기, 작업공간 소거, 감사, 사용자 알림). "지금 평문이 존재해도 되는가"를 결정하는 모든 규칙을 한곳에 모아 파일시스템·뷰어·체인 없이 테스트합니다.
- T15: 승인 창 밖(아직 아님/이미 만료) 거부, 열린 중 만료면 뷰어 종료+소거.
- T20: 회수가 오면 즉시 종료하고 아직 봉인 안 된 변경은 버립니다(회수 후 새 버전 생성 금지).
- T03: 열람 횟수를 로컬에서 셉니다(온체인 카운터는 권고). 재시작 복구용 Session::resume이 소진된 예산으로 열려 하면 파일을 보여주지 않고 소거합니다.
- T07: ReadOnly에서 뷰어가 저장하면 DiscardChanges + "변경 내용이 저장되지 않았습니다" 알림, 버전 생성 없음.

Z-1.G.5/G.7/G.8 작업공간: 세션별 디렉터리(Unix 0700 검증, Windows는 NOT_CONTENT_INDEXED|TEMPORARY), 경로 탈출 거부, 읽기전용 표시/해제, wipe(모든 파일 0으로 덮어쓰고 디렉터리 삭제), secure_delete. 덮어쓰기가 실제로 일어나는지는 하드링크로 같은 inode를 관찰해 검증했습니다(삭제 후 남은 링크의 내용이 전부 0).

정직하게 남긴 한계: Windows 상속 ACL 제거는 설치 단계(Z-1.G.5 잔여), SSD·CoW 스냅샷에서 덮어쓰기는 best-effort(T09, 포렌식 검증은 Z-1.Q.2).

테스트 18종, clippy/rustdoc/전체 테스트 통과, Windows 타깃 크로스 체크도 통과.
```

### #48 [U] 2026-09-19
```
TU-T DFS(Digital Financial Services) 보안 랩 / X.1284 관련 창구 또는 BSA 제공사에 샌드박스 Client Key 이외에 다른 키를 발급 받아 사용하려면 어떻게 해야해 ?
```

### #48 [C] 2026-09-19
```
docs/credentials.md를 새로 만들어 이 프로젝트가 외부에서 받아야 하는 키 전부를 정리했습니다. 핵심은 "보안 핵심 키는 전부 우리가/기기가 만들고, 외부에서 받는 것은 서비스 접근 토큰과 신뢰 표식뿐"이라는 구분입니다.

BSA 샌드박스 다음 단계(운영 키): NDA → 기술 검토(우리는 이미 보여줄 PoC가 있음) → 라이선스 계약(과금 모델·SLA) → 운영 테넌트·키 발급 → 로테이션 정책. 제공사마다 다르므로 질문 목록을 그대로 쓰시도록 정리했고, 그중 가장 중요한 질문은 "시크릿을 데스크톱 앱에 두어야 하는가"입니다 — 클라이언트에 시크릿을 넣어야 하는 구조면 사실상 공개되는 것이라 Relay만 시크릿을 쥐는 구성이 가능한지에 따라 설계가 달라집니다(OR-9로 등록).

역할 구분도 명확히 했습니다: ITU-T DFS 보안 랩은 X.1284 같은 권고안과 보안 평가·클리닉을 하는 쪽이지 상용 제품 운영 키를 발급하는 곳이 일반적으로 아닙니다. 표준 적합성 평가는 DFS 랩, SDK 키는 제공사 — 별개 절차입니다.

우리가 직접 만드는 키(발급 신청 불필요): 패스키·TPM 기기 키(기기가 생성, 밖으로 안 나옴), 기기 X25519/Ed25519, 소유자 봉인·서명키, DEK, Tauri 업데이터 키.

외부에서 받아야 하는 것: Pimlico API 키(있음), RPC 전용 엔드포인트, Basescan 키, FCM 서비스 계정, **EV 코드 서명 인증서**(가장 비싸고 오래 걸림 — 2023년부터 개인키가 하드웨어 토큰/클라우드 HSM에 있어야 하고 사업자 서류 심사 1~3주, 연 40만~90만원대), Apple Developer($99/년).

지금 시작할 것 3가지로 정리했습니다: EV 코드서명 문의(리드타임 최장), BSA 질문 목록 전달, Pimlico 운영 플랜·스폰서 정책 확인.
```

### #49 [U] 2026-09-19
```
이 프로젝트는 내 개인 프로젝트이므로 외부 인증 같은것은 안받아도 됨 여기서 직접 키 생성하는것은 어때 ?
```

### #49 [C] 2026-09-19
```
그게 오히려 원래 설계와 맞습니다. 파일을 지키는 키는 처음부터 전부 기기 안에서 우리가 만들고 있었고, 외부에서 받는 것들은 편의 기능(가스 대납·푸시·설치 경고 제거)일 뿐이었습니다. BSA 자리를 채울 Z-1.A.6 OtakProvider를 방금 구현했습니다.

OtakProvider(X.1284 흐름, 발급기관 없음)
- 시드 32바이트를 우리가 생성해 OS 자격 증명 저장소에 보관.
- 승인 요청마다 그 요청의 다이제스트로 HMAC-SHA256 일회용 키를 파생하고 쓴 뒤 폐기. 다이제스트는 요청 nonce를 품고 있어 매번 다르므로 별도 카운터 동기화가 필요 없습니다.
- 재전송 방지(DoD): 서명자와 검증자가 각각 독립적으로 "이 다이제스트는 이미 썼다"를 기록합니다. 캡처한 assertion은 재사용 불가. MAC 비교는 상수시간, 시드는 Debug에서 마스킹.
- 한계를 코드와 문서에 명시했습니다: 대칭키 MAC이라 스마트컨트랙트가 검증할 수 없고, 시드를 가져선 안 되는 상대에게 보내면 안 됩니다. 온체인 계정에는 여전히 P-256 서명자(패스키/TPM)가 필요하고, OTAK는 내 기기들 사이(또는 셀프호스팅 Relay)의 인증용입니다 — 그게 X.1284의 원래 용도입니다.

docs/credentials.md §7에 "개인 프로젝트 모드: 외부 발급 0" 표를 추가했습니다. BSA→OtakProvider, EV 코드서명→자체 서명(내 PC에선 경고 사라짐, 남에게 배포할 때만 EV 필요) 또는 서명 생략, Pimlico→EntryPoint에 소액 직접 예치 또는 자체 번들러, 전용 RPC→공개 RPC, Basescan→검증 생략, FCM→셀프호스팅 ntfy, Apple→맥 미지원. 각 항목마다 "잃는 것"도 같이 적었습니다.

결론: 보안적으로 잃는 것은 없습니다. dev_plan Z-1.A.6 ✅, Z-0.A.3는 "외부 배포 시에만 다시 연다"로 보류 처리했습니다.
```

### #50 [U] 2026-09-20
```
다음 진행
```

### #50 [C] 2026-09-20 (Z-1.A.4)
```
Z-1.A.4 완료 — 소유자 키 암호화 백업·복원. A 트랙은 이제 Windows 실기 확인만 남았습니다. 커밋·푸시 완료.

설계에서 한 가지 판단: 암호를 묻지 않습니다. 최상위 원칙상 사용자가 무언가를 만들어 외우게 하면 안 되므로, Agent가 복구 코드를 생성해 한 번 보여주고(125비트, 5글자×5그룹, I/L/O/U 제외) 그것을 Argon2id(64MiB·3패스)로 늘려 XChaCha20-Poly1305 키로 씁니다. 사용자는 받아 적기만 하고, 약한 암호를 고를 수 없습니다. 코드 입력은 복구 흐름에서만 일어나며 온보딩·봉인·승인 흐름에는 여전히 입력 필드가 없습니다.

파일: magic + 인증된 헤더(Argon2 파라미터·salt·nonce) + AEAD 본문. 헤더를 AAD로 묶어 salt/nonce 변조도 잡힙니다. 악성 파일이 64GiB 같은 파라미터를 요구하면 KDF를 돌리기 전에 거부합니다(테스트가 5초 내 거부를 확인). 잘못된 코드와 손상 파일은 같은 오류로 처리 — 사용자에게 보여줄 메시지가 하나여야 하기 때문입니다. 백업 파일은 512바이트 미만이라 인쇄도 됩니다.

테스트 9종 + 실제 복구 리허설(CLI): keygen → seal → backup(코드 출력) → 키 파일 삭제 → restore → 예전에 봉인한 파일 열기 성공, 잘못된 코드는 거부.

게이트: clippy/rustdoc/전체 테스트 통과, 커버리지 95.2%(backup.rs 97.4%).

퍼징은 3번째 타깃 진행 중입니다(누적 2억 4천만 실행, 크래시 0). 오늘 21시경 끝납니다.
```

### #51 [U] 2026-09-20
```
짆ㅇ
```

### #51 [C] 2026-09-20 (Z-1.G.6)
```
"진행"으로 읽고 Z-1.G.6(열람 앱 실행·PID 추적·저장 감지)을 진행했습니다. 커밋·푸시 완료.

zbacs-session::viewer
- Viewer: 추적 실행(우리가 띄운 프로세스의 PID·생존 확인), 정상 종료 요청(Unix SIGTERM / Windows taskkill /F 없이 = WM_CLOSE로 편집기가 저장 여부를 물을 기회를 줌), 강제 종료, 드롭 시 자동 종료(세션이 끝났는데 편집기가 평문을 붙들고 있으면 안 되므로). OS 연결 프로그램으로 여는 경로는 PID를 알 수 없다는 점을 Launch::Delegated로 정직하게 표현하고 is_running()이 None을 돌려줍니다.
- SaveWatcher: 파일이 아니라 **디렉터리**를 감시합니다. Word 같은 편집기는 제자리에 쓰지 않고 잠금 파일(~$doc.docx)을 만든 뒤 임시 파일을 rename 하기 때문에, 파일만 보면 저장을 놓치고 심지어 파일이 사라진 것처럼 보입니다. 디바운스로 "사람의 저장 1회 = 이벤트 1개"로 묶고, 잠금·스왑 파일은 무시하며, 파일이 사라져 돌아오지 않으면 Vanished로 구분합니다.

작업 중 테스트가 우연히 통과하던 문제를 발견해 고쳤습니다: launch_with가 인자 뒤에 파일 경로를 자동으로 덧붙이는 바람에 테스트의 `sleep 30 <path>`가 인자 오류로 즉시 죽고 있었고, 그래서 "종료 요청이 통했다"는 테스트가 사실은 아무것도 검증하지 않고 있었습니다. 인자 목록을 호출자가 완전히 구성하도록 API를 바꾸고(뷰어마다 파일 위치가 다름), 편의용 launch_file을 따로 뒀습니다. 이제 SIGTERM 경로가 실제로 검증됩니다. 테스트도 Windows CI에서 돌도록 플랫폼별 프로세스로 바꿨습니다.

테스트 12종. DoD의 "Word/메모장/PDF 3종"은 Windows + Agent UI가 필요하므로 ◐로 두고 docs/windows_checklist.md §4에 절차를 적었습니다.

게이트: clippy/rustdoc/전체 테스트/Windows 크로스체크 전부 통과.
```

### #52 [U] 2026-09-20
```
다음
```

### #52 [C] 2026-09-20 (Z-1.R.2)
```
Z-1.R.2 완료 — axum Relay 서버(apps/relay). 커밋·푸시 완료.

서버: 스펙 §2의 엔드포인트 7개(/v1/devices, /requests, /grants, /revocations, /inbox, /stream WebSocket, /health). 상태는 전부 메모리 — Relay는 지켜야 할 비밀을 하나도 들고 있지 않으므로 큐를 잃으면 재전송 비용만 발생합니다.

설계에서 신경 쓴 두 가지:
- 인증 순서: 형식 → 크기 → **서명자 확인** → 할당량 → 재전송. 미등록 기기가 남의 할당량을 소모하지 못하고, 잘못된 서명이 nonce를 태우지 못합니다.
- 라우팅: 소유자는 답장을 누구에게 보낼지 말할 필요가 없습니다. Relay가 요청 nonce → 요청한 기기를 기억해 두고 GrantMsg를 되돌려 보냅니다. 파일이나 사람에 대해 더 알 필요가 없는 구조입니다.

거부 동작 테스트: 미등록 기기, 서명자≠요청 주체(T05), 본문 변조, 재전송(T03), 시계 어긋남, 본문 상한, 쓰레기 입력, 할당량 초과(T16, 한 기기의 폭주가 다른 기기를 굶기지 않음), 모르는 요청에 대한 grant, 자기 키가 아닌 announce. 총 16종.

DoD(100 req/s): 릴리스 실측 **12,816 req/s** — 128배. 디버그는 115/s인데 그건 ed25519-dalek이 최적화 없이 도는 탓이라 의미 있는 수치가 아니어서, 처리량 테스트를 perf 게이트(release 전용)로 옮겼습니다.

그 과정에서 CI 버그를 하나 발견해 고쳤습니다: `cargo test --release -- perf_`는 #[ignore] 테스트를 건너뛰므로 **Z-0.D.3 이후 성능 게이트가 0개 테스트를 돌리고 있었습니다**. `--include-ignored`를 붙여 이제 100MB 왕복과 Relay 처리량 둘 다 실제로 돕니다.

실제 바이너리도 확인했습니다: `cargo run -p zbacs-relay`로 띄워 health 200, 잘못된 질의 400.
```

### #53 [U] 2026-09-20
```
다음
```

### #53 [C] 2026-09-20 (Z-1.R.5)
```
Z-1.R.5 완료 — Relay 클라이언트(crates/zbacs-relay-client). 커밋·푸시 완료. 이걸로 R 트랙의 서버·클라이언트 양쪽이 붙었습니다.

DoD가 "재연결·재시도"라 거기에 집중했습니다:
- 엔드포인트 장애 조치: 여러 Relay를 순서대로 시도. 한 운영자가 소유자를 침묵시킬 수 없습니다(T21).
- 지수 백오프 + 지터: 장애 복구 후 모든 Agent가 동시에 몰리지 않도록.
- **같은 바이트로 재시도**: 응답을 못 받아 다시 보낼 때 새로 서명하면 큐에 중복이 쌓여 소유자가 한 파일에 대해 두 번 요청받는 것처럼 보입니다. 같은 봉투를 그대로 재전송하면 Relay의 nonce 기록이 "이미 받았다(replayed)"고 답하고, 클라이언트는 그것을 **성공(AlreadyDelivered)** 으로 읽습니다. 프로토콜의 재전송 방지가 멱등성으로 그대로 쓰이는 구조입니다.
- 영구 거부(미등록 기기·잘못된 서명·형식 오류)는 재시도하지 않고 즉시 반환, 일시 거부(429·500)만 재시도.
- poll_device_inbox는 Relay가 죽어 있는 동안 백오프하며 기다리고 포기하지 않습니다 — 소유자가 언제 답할지 모르니까요.

테스트 10종은 전부 실제 서버를 띄워 HTTP로 검증합니다: 요청→승인 왕복, 죽은 엔드포인트에서 살아있는 쪽으로 전환, 전부 죽었을 때 정직하게 Unreachable, Relay가 재시작하면 자동 복구, 중복 제출이 큐를 늘리지 않음, 영구 거부는 1회만 시도, 429는 풀릴 때까지 재시도, 이상한 응답을 믿지 않음, 장애 중 폴링 생존.

부수적으로 두 가지를 고쳤습니다:
1. 디바운스 테스트가 병렬 부하에서 간헐적으로 실패했습니다. 시간 가정을 테스트에 두는 게 잘못이라, 디바운스 로직을 Debounce 구조체로 분리해 명시적 시계로 결정적으로 검증하고, 통합 테스트는 "저장이 보고된다"는 참인 성질만 남겼습니다.
2. rustls 기본 백엔드(aws-lc-rs)는 Windows에서 cmake·NASM을 요구해 ring으로 바꿨습니다. 다만 ring도 크로스 컴파일엔 Windows용 C 툴체인이 필요해, Windows 크로스체크 범위에서 이 크레이트만 제외했습니다(Windows 전용 코드가 한 줄도 없고, 실제 Windows 빌드는 CI의 windows-latest가 확인합니다). 이유를 CLAUDE.md와 체크리스트에 적어 뒀습니다.
```

### #53 [C] 2026-09-20 (추가: Z-1.C.3 퍼징 24시간 완료)
```
어제 시작한 24시간 퍼징이 방금 끝났습니다. 로그 마지막 줄이 "== no crashes", 크래시 아티팩트 0개.

타깃별 실행 횟수: header 212,734,402 / header_signed 27,387,137 / open_mutated 114,162,463 / envelope 66,395,316 — 누적 420,679,318회.

open_mutated는 "변형된 컨테이너가 열리면 평문이 원본과 같아야 한다"는 속성까지 검사하므로, 무크래시뿐 아니라 잘못된 평문을 내놓은 경우도 0이라는 뜻입니다.

Z-1.C.3을 ✅로 바꿨습니다. 이로써 C 트랙(C.1~C.6) 전부 완료. 앞으로는 야간 CI(fuzz.yml)가 타깃당 20분씩 계속 돌립니다.
```

### #54 [U] 2026-09-21
```
다음
```

### #54 [C] 2026-09-21 (Z-1.H.7)
```
Z-1.H.7 완료 — zbacs-chain(alloy). 커밋·푸시 완료.

바인딩: Foundry 아티팩트에서 직접 생성합니다. 컨트랙트를 바꾸고 다시 빌드하면 Rust 쪽을 고칠 때까지 컴파일이 깨지므로 ABI가 조용히 어긋날 수 없습니다.

클라이언트: owner_of / current_version / is_grant_valid 읽기, register_file / bump_version / retire / revoke / audit 쓰기. 오류를 "체인이 거절했다(revert)"와 "체인에 닿지 못했다"로 구분합니다 — 캐시로 대신할 수 있는 건 후자뿐이기 때문입니다.

EventWatcher: 구독이 아니라 폴링입니다. 프록시 뒤에서는 WebSocket을 계속 열어두지 못하는 경우가 많고, 폴백은 언제나 동작하는 쪽이어야 합니다. 대가는 회수 감지가 몇 초 늦는 것인데 세션 TTL이 이미 그 범위를 제한합니다. 폴링에 실패하면 블록 범위를 전진시키지 않습니다 — 놓치면 안 되는 단 하나가 Revoked라서요.

Cache: 마지막 답을 나이와 함께 보관하고, 호출자가 정책에 따라 판단합니다. strict_onchain 파일은 stale 답으로 열리지 않고, 일반 파일은 최근 답으로 진행한 뒤 다시 확인합니다. 한 가지 규칙을 코드에 박았습니다 — **죽은 grant는 되살아나지 않습니다.** 회수/만료는 온체인에서 한 방향이므로, 나중에 "유효하다"는 답이 오면 혼란스럽거나 적대적인 노드이고, 그럴 땐 세션을 닫는 쪽이 안전합니다.

테스트: Anvil을 띄우고 실제 컨트랙트를 배포해 7종(등록→재봉인→폐기→폐기 후 거절, 감사 기록, 오프라인 캐시 사용과 strict 거부, 캐시 없는 오프라인은 추측하지 않고 오류, 회수 감시, 실패한 폴링이 범위를 건너뛰지 않음, 실제 EIP-712 승인 서명→Granted 이벤트→isValid→revoke→Revoked 전체 흐름) + 캐시 단위 3종. Foundry가 없으면 이유를 출력하고 건너뜁니다. tools/chain-it.sh와 CI에 연결했습니다.

작업 중 테스트 인프라 문제 하나: 같은 계정을 여러 컨트랙트 핸들로 다루면 alloy의 캐시된 nonce가 어긋나 "nonce too low"가 났습니다. 테스트 픽스처를 uncached nonce 관리로 바꿔 해결했습니다.
```

### #55 [U] 2026-09-21
```
다음 진행
```

### #55 [C] 2026-09-21 (Z-1.G.1)
```
Z-1.G.1 진행 — apps/agent Tauri Agent 골격. 커밋·푸시 완료.

만든 것
- 트레이 상주: 창을 닫아도 Agent는 계속 실행됩니다. 승인 요청이 왔을 때 거기 있어야 하는 프로그램이라, 창을 닫는 것과 끝내는 것을 분리했습니다("종료"는 트레이 메뉴에서만).
- 단일 인스턴스: 두 번째 더블클릭이 새 창을 띄우지 않고 실행 중인 Agent에 경로를 넘깁니다(같은 작업공간·세션 상태를 두 프로세스가 다투면 안 되므로).
- 파일 연결: .zbacs / application/x-zbacs. macOS의 RunEvent::Opened는 그 플랫폼에만 있는 variant라 cfg로 감쌌습니다.
- 키 없이 헤더만 읽어 상태 표시: 잠긴 파일인지, 몇 번째 버전인지, 주인이 기본으로 어디까지 허용했는지. 파일 이름은 암호화돼 있어 보여주지 않습니다.

Linux 실측: deb에 Exec %U·MIME 등록 확인, 헤드리스(xvfb+dbus) 실행에서 첫 인자 수신과 두 번째 인스턴스 전달을 **로그로** 확인했습니다("handed a file ... sealed=true version=1", "second instance handed over 2 arguments"). 처음엔 두 번째 프로세스가 종료됐다는 것만 보고 추정할 뻔해서, 전달 경로에 로그를 넣고 다시 돌렸습니다.

UI: 규칙 8대로 디자인 토큰 변수만 씁니다. 그런데 토큰에 **간격(spacing) 스케일이 아예 없어서** 임의값을 쓸 수밖에 없는 상태였습니다(Z-1.U.0의 미완 부분). olive 테마에만 있던 4px 기반 스케일을 공용으로 올려 tokens.json/tokens.css에 --zb-space-1..6을 추가하고, UI가 쓰는 모든 var()가 실제로 토큰에 존재하는지 스크립트로 확인했습니다(29개, 누락 0). tokens.css는 build.rs가 UI 디렉터리로 복사하므로 사본이 어긋날 수 없습니다.

아직 안 하는 것은 UI가 직접 말합니다: "열람 요청" 버튼은 비활성이고 "다음 단계에서 연결됩니다"라고 적혀 있습니다. 온보딩·봉인·요청은 G.2/G.3/G.9입니다.

DoD의 "설치 후 더블클릭"은 Windows 확인이 남아 ◐입니다 — 체크리스트 §3을 스파이크가 아니라 실제 Agent 기준으로 고쳤습니다(트레이 상주 확인 항목도 추가).
```

### #56 [U] 2026-09-21
```
진행
```

### #56 [C] 2026-09-21 (Z-1.G.2, Z-1.U.1, Z-1.U.2, Z-1.U.7)
```
Z-1.G.2 첫 실행 온보딩을 끝냈습니다. 커밋·푸시 완료.

**먼저, G.1에서 놓친 버그를 찾았습니다.** 웹뷰가 아예 시작하지 못하고 있었습니다. Tauri capabilities 파일이 없어 event.listen이 거부됐고, UI 시작 스크립트가 예외로 죽었습니다. 지난번 "UI가 파일을 보여준다"는 근거는 백엔드 로그였는데, 웹뷰는 그 이벤트를 받은 적이 없습니다. capabilities/default.json을 추가해 고쳤고(core:event:default 하나만 — 웹뷰는 파일·셸·네트워크를 못 씁니다), 같은 종류의 침묵을 다시 놓치지 않도록 화면 전환을 백엔드 로그에 남기게 했습니다. 이건 사용자 기기에서 첫 실행이 실패했을 때 우리가 물어볼 수 있는 유일한 단서이기도 합니다.

**탭 2번**: [시작하기] → [승인 방식]. 그 사이에 기기 X25519/Ed25519 키, 소유자 봉인·서명 키, 승인 서명기가 만들어지고 기기 프로필이 남습니다. 입력 칸 0개, 사용자가 볼 기술 용어 0개.

백엔드는 Agent가 아니라 zbacs-auth::setup에 뒀습니다. Agent 크레이트는 루트 워크스페이스 밖이라 거기 두면 CI에서 테스트가 한 번도 돌지 않습니다.

두 가지를 특히 신경 썼습니다.
- **두 번째 실행은 같은 신원을 이어받습니다.** 새 봉투 키를 만들면 어제 봉인한 파일이 오늘 안 열립니다. 테스트로 박아 뒀습니다.
- **못 끝낸 일을 숨기지 않습니다.** 계정을 체인에 만드는 일(H.8)과 기기 등록(H.10)은 아직이라 Pending으로 돌아옵니다. 다만 그중 **사용자에게 보여주는 건 둘뿐**입니다 — "전용 보안 칩이 없어요", "안전한 보관함이 없어서 다시 준비해야 해요". 나머지는 우리가 끝낼 일이지 사용자가 알 일이 아닙니다(ux_principles §2).

기기가 못 하는 방식은 버튼 자체가 비활성이고 이유가 적혀 있습니다. 백엔드도 그 방식을 거부합니다 — 화면과 백엔드가 따로 놀면 결국 누를 수 있는데 실패하는 버튼이 생깁니다.

**Z-1.U.2 용어 린트**도 같이 했습니다. U.7의 DoD가 "용어 린트 통과"인데 린트가 없으면 통과를 주장할 수 없습니다. docs/design/ui_strings.md가 원본이고 스크립트가 그 문서를 읽습니다(금지 용어 48개). 검사 4종: 금지 용어(U-5), 텍스트 입력 0개(U-6), 토큰만 사용(규칙 8), JS가 참조하는 id·data-role이 마크업에 실제로 있는지. **일부러 위반을 넣어 네 검사가 전부 실패하는 것을 확인했습니다** — 통과만 확인한 린트는 아무것도 보장하지 않습니다.

한글이 든 줄만 검사합니다. 규칙 7이 주석·식별자를 영어로 못박으므로 한글 = 사용자에게 보이는 문구입니다. 그래서 백엔드는 문장을 만들지 않고 "biometric", "volatile_key_store" 같은 기계값만 돌려줍니다.

CI에 두 잡을 추가했습니다. agent(ubuntu+windows — 지금까지 Agent는 CI에서 빌드조차 되지 않았습니다)와 ux. 덤으로 CI 버그 하나를 고쳤습니다: 체인 통합 테스트 단계가 존재하지 않는 step id를 보고 있어서 한 번도 실행된 적이 없었습니다.

전부 통과: 루트 워크스페이스 clippy 0, 테스트 전 스위트, 커버리지 92.6%(게이트 90), 문서 빌드, Windows 크로스컴파일, Agent 8종, 린트.

실제 Hello·TPM으로 2탭을 밟는 확인은 Windows에서만 됩니다. docs/windows_checklist.md §3.5에 절차를 적었습니다 — 핵심은 "탭 3번 안에 끝나고, 타이핑 0번이고, 두 번째 실행에서는 첫 실행 화면이 안 나온다"입니다.

다음은 Z-1.G.3 봉인 UI(+U.3)입니다.
```
