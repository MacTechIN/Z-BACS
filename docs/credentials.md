# 외부 키·자격 증명 발급 가이드

| 문서 버전 | 1.0 (2026-09-19) |
|---|---|
| 목적 | Z-BACS가 외부에서 **받아야** 하는 키와, 우리가 **직접 만드는** 키를 구분하고, 각각의 발급 절차·비용·보관 위치를 한곳에 정리 |
| 원칙 | 키 값은 저장소에 절대 커밋하지 않는다. `.env`(gitignore) 또는 OS 자격 증명 저장소, CI는 GitHub Actions Secrets. Claude에게 키 값을 보내지 않는다 — "받았다"는 사실과 규격만 공유한다. |

## 0. 한눈에

| 키 | 누가 발급 | 비용(대략) | 필요 시점 | 없으면 막히는 것 |
|---|---|---|---|---|
| **사용자 승인키**(패스키·TPM 기기 키) | **아무도 — 기기가 스스로 생성** | 0 | 이미 구현 | — |
| 컨테이너·기기·Relay 키 | **우리가 생성**(`zbacs-core`/`proto`) | 0 | 이미 구현 | — |
| Tauri 업데이터 서명 키 | **우리가 생성**(`tauri signer generate`) | 0 | Z-1.G.13 | 자동 업데이트 |
| BSA Client Key (샌드박스→운영) | BSA 제공사 | 계약 협의 | Z-1.A.5 연결 시 | BSA 연동 — **개인 프로젝트면 불필요**, `OtakProvider`로 대체(§7) |
| Pimlico API Key | Pimlico (가입) | 무료 티어→유료 | Z-1.H.9 | 가스 대납(페이마스터) |
| RPC 엔드포인트 키 | Alchemy/QuickNode 등 | 무료 티어→유료 | Z-1.H.7 운영 | 안정적 체인 조회 |
| Basescan API Key | Basescan (가입) | 무료 | Z-1.H.4 | 컨트랙트 소스 검증 |
| 컨트랙트 배포 키 | **우리가 생성**(하드웨어 지갑 권장) | 지갑 비용 | Z-1.H.4 | 메인넷 배포 |
| **EV 코드 서명 인증서** | 공인 CA(DigiCert/Sectigo 등) | **연 40만~90만원 + 토큰/HSM** | Z-1.S.2 | Windows SmartScreen 경고 제거 |
| Apple Developer ID | Apple | 연 $99 | Z-2.G.1 | macOS 배포·공증 |
| FCM 서비스 계정 | Google Firebase | 무료 | Z-1.R.3 | 모바일 승인 푸시 |
| Relay TLS 인증서 | Let's Encrypt | 무료·자동 | Z-1.R.4 | HTTPS |

**중요**: 이 시스템의 **보안 핵심 키는 전부 우리가/기기가 만든다.** 외부에서 받는 것은 대부분 *서비스 접근 토큰*(RPC·번들러·푸시)과 *신뢰 표식*(코드 서명 인증서)이다. 외부 키가 없어도 시스템은 동작하고, 없을 때 잃는 것만 위 표의 마지막 열에 적었다.

---

## 1. BSA: 샌드박스 이후 (운영 키)

샌드박스 Client Key는 "동작을 확인해 보라"는 임시 자격이다. 실제 제품에 넣으려면 보통 다음 단계를 거친다 — **이 절차는 제공사마다 다르므로 아래를 그대로 질문 목록으로 쓰면 된다.**

1. **NDA** — SDK 문서·프로토콜 상세를 받기 위해 대개 먼저 요구된다.
2. **기술 검토(PoC 결과 공유)** — 우리는 이미 보여줄 것이 있다: 패스키·TPM 경로가 동작하는 Agent, EIP-712 승인 티켓, 체인 기록. "BSA를 어디에 끼우려는지"를 그림으로 제시하면 검토가 빨라진다.
3. **라이선스 계약** — 과금 모델(월 정액 / 인증 건당 / 좌석당), 최소 계약 기간, SLA.
4. **운영 테넌트·키 발급** — 운영 Client Key/Secret, 테넌트 ID, 허용 도메인·앱 번들 ID 등록.
5. **키 로테이션·폐기 정책** — 유출 시 즉시 폐기 절차, 교체 주기, 키 두 개를 동시에 유효하게 두는 무중단 교체 지원 여부.

**제공사에 그대로 물어볼 것** (샌드박스 신청 때 함께 물어도 된다):

- 샌드박스 키와 운영 키는 **같은 API 규격**인가, 엔드포인트만 다른가?
- 운영 키 발급의 **선행 조건**은 무엇인가(계약, 보안 점검, 앱 등록)?
- 과금 단위와 **무료/평가 기간**은?
- 키 **로테이션**을 지원하는가(무중단 교체 가능 여부)?
- 키를 **클라이언트(데스크톱 앱)에 두어야 하는가**, 서버에만 두어도 되는가?
  → 이게 가장 중요하다. 데스크톱 앱에 시크릿을 넣으면 사실상 공개된 것과 같다. 서버(우리 Relay)만 시크릿을 쥐고 클라이언트는 토큰을 받는 구조가 가능한지 반드시 확인한다.
- 온프레미스/자체호스팅 옵션이 있는가(기업 고객이 요구할 수 있다)?

### ITU-T DFS 보안 랩의 역할

ITU-T DFS Security Lab은 X.1284 같은 권고안을 만들고 **보안 평가·클리닉**을 제공하는 쪽이지, 일반적으로 상용 제품의 운영 키를 발급하는 곳은 아니다. 따라서:

- **표준 적합성**을 주장하고 싶으면 → DFS 랩/관련 창구에 **적합성 평가·시험** 절차를 문의한다.
- **제품 SDK 키**가 필요하면 → 그 SDK를 만든 **제공사**와 계약한다.

둘은 별개 절차이고, 우리 문서·마케팅에서 "BSA 기반"은 ADR-0003의 정의(**X.1284 흐름 준수 + BSA SDK 연동 가능**)를 넘지 않는다.

---

## 2. 우리가 직접 만드는 키 (발급 신청 불필요)

| 키 | 만드는 법 | 어디에 보관 |
|---|---|---|
| 소유자 승인키 A(플랫폼 패스키) | Windows Hello가 TPM 안에서 생성 (`WindowsPasskey::create`) | TPM. 밖으로 나오지 않음 |
| 소유자 승인키 B(기기 키) | CNG가 TPM 안에서 생성 (`WindowsDeviceKey::open_or_create`) | TPM. 내보내기 불가 |
| 기기 키(X25519/Ed25519) | `DeviceIdentity::generate()` | OS 자격 증명 저장소(`zbacs-auth::store`) |
| 소유자 봉인키·헤더 서명키 | `OwnerKeys::generate()` | 같은 저장소 + 암호화 백업(Z-1.A.4) |
| DEK | 봉인할 때마다 난수 | 메모리에만, HPKE 봉투 안 |
| Tauri 업데이터 키 | `cargo tauri signer generate -w ~/.zbacs-updater.key` | 개인키는 CI Secret(`TAURI_SIGNING_PRIVATE_KEY`) + 암호, 공개키는 `tauri.conf.json` |

---

## 3. 서비스 접근 키 (가입하면 바로)

### 3.1 Pimlico (번들러·페이마스터, Z-1.H.9)
- dashboard.pimlico.io 가입 → API Keys → 생성. 테스트넷 무료.
- 운영: 스폰서 한도·허용 컨트랙트 화이트리스트를 설정한다. **페이마스터 정책을 열어두면 남이 우리 돈으로 가스를 쓴다** — `AccessPolicy`/`P256Validator` 호출만 스폰서하도록 제한한다.
- T21 대비: 번들러 엔드포인트를 **둘 이상** 설정하고, 실패 시 자체 예치 + EntryPoint 직접 호출로 폴백(Z-0.H.2에서 두 경로 모두 실측).

### 3.2 RPC (Z-1.H.7)
- 공개 RPC(`https://mainnet.base.org`)는 개발·폴백용. 운영은 Alchemy/QuickNode 등의 전용 엔드포인트(무료 티어로 시작 가능).
- 키는 **Agent에 넣지 않는다.** 클라이언트가 직접 쓰면 키가 배포되는 것과 같으므로, 조회는 Relay를 경유하거나 공개 RPC를 쓴다.

### 3.3 Basescan (Z-1.H.4)
- 무료 API 키. `forge verify-contract`에 사용. 없으면 소스 검증만 못 하고 배포 자체는 된다.

### 3.4 FCM (Z-1.R.3)
- Firebase 프로젝트 생성 → 서비스 계정 JSON 다운로드(HTTP v1 API 기준. 예전 "서버 키"는 폐기 방향).
- **서비스 계정 JSON은 Relay 서버에만** 둔다. 모바일 앱에는 `google-services.json`(공개 가능한 설정)만 들어간다.
- 폴백은 셀프호스팅 ntfy — 키 없이 동작한다.

---

## 4. 코드 서명 (가장 비싸고 오래 걸림 — 미리 시작할 것)

### 4.1 Windows EV 코드 서명 (Z-1.S.2, OR-4)
2023년 6월부터 **모든 OV/EV 코드 서명 개인키는 하드웨어(FIPS 140-2 Level 2 이상 토큰 또는 클라우드 HSM)에 있어야 한다.** 따라서 "인증서 파일"이 아니라 토큰이나 HSM 계정을 받는다.

- 발급기관: DigiCert, Sectigo, GlobalSign, SSL.com 등.
- 필요 서류: **사업자등록증**, 조직 실재 확인(공적 디렉터리·전화 인증), 신청자 신원 확인. 개인 사업자도 가능하나 심사가 더 길다.
- 소요: 보통 1~3주(서류 왕복 포함). **가장 먼저 시작해야 하는 항목.**
- 비용: EV 연 40만~90만원대 + 토큰/HSM 비용. OV는 더 싸지만 SmartScreen 평판을 처음부터 쌓아야 한다(EV는 즉시 평판 부여).
- CI 서명: 클라우드 HSM(예: DigiCert KeyLocker, Azure Trusted Signing)을 쓰면 GitHub Actions에서 서명할 수 있다. USB 토큰은 자동화가 어렵다 — **CI 서명을 원하면 발급 전에 클라우드 옵션인지 확인할 것.**

### 4.2 macOS (Z-2.G.1)
- Apple Developer Program 연 $99 → "Developer ID Application" 인증서 + `notarytool`용 앱 전용 암호 또는 App Store Connect API 키.

---

## 5. 보관과 CI

| 어디 | 무엇 |
|---|---|
| `.env` (gitignore) | 로컬 개발용 `PIMLICO_API_KEY`, `BASE_SEPOLIA_RPC_URL` 등 |
| OS 자격 증명 저장소 | 사용자 기기의 기기 키·봉인키 (`zbacs-auth::store`) |
| GitHub Actions Secrets | CI 서명 키, 배포 RPC·검증 키 |
| 하드웨어 지갑 / 멀티시그 | 컨트랙트 소유권. 배포 EOA와 **소유권을 분리**하고 소유권은 Timelock+Safe로 옮긴다(Z-1.H.4) |

배포 키 운영 원칙: 배포용 EOA는 가스만 들고 있는 일회성 계정으로 두고, 배포 직후 `FileRegistry`/`AccessPolicy`의 관리 권한을 **Timelock(+멀티시그)** 으로 이전한다. 개인키 하나가 유출돼도 컨트랙트를 바꿀 수 없어야 한다.

---

## 6. 지금 당장 할 것 / 나중에 할 것

> 아래는 **외부 배포를 하는 경우**의 순서다. 개인 프로젝트로 유지한다면 §7만 따르면 되고 아무것도 신청하지 않아도 된다.

**지금 (외부 배포 시)**
1. EV 코드 서명 발급 절차 **문의 시작** — 리드타임이 가장 길다.
2. BSA 제공사에 §1의 질문 목록 전달(샌드박스 신청과 함께).
3. Pimlico 운영 플랜·스폰서 정책 확인(이미 테스트 키 보유).

**나중 (필요해질 때)**
4. Basescan 키(메인넷 배포 직전), 전용 RPC(운영 트래픽 생길 때)
5. FCM(모바일 승인 앱 착수 시), Apple Developer(맥 지원 시)

---

## 7. 개인 프로젝트 모드: 외부 발급 0으로 돌리기

개인 프로젝트라 외부 인증·계약을 하지 않겠다면, **전부 자체 생성·자체 호스팅으로 대체할 수 있다.** 잃는 것은 "남이 보증해 주는 신뢰 표식"뿐이고 기능은 그대로다.

| 원래 외부에서 받던 것 | 자체 대체 | 잃는 것 |
|---|---|---|
| BSA Client Key | **`OtakProvider`**(Z-1.A.6, 구현 완료) — X.1284 흐름을 우리 키로 구현. 소유자 승인은 패스키/TPM 키(이미 자체 생성) | "BSA 제품 연동" 타이틀. 표준 흐름 준수는 유지 |
| EV 코드 서명 | 자체 서명 인증서(`New-SelfSignedCertificate` + `signtool`)로 서명하거나 서명 생략 | SmartScreen 경고("추가 정보 → 실행" 한 번 필요). 본인·지인 배포엔 충분 |
| Pimlico 페이마스터 | 계정에 소액 직접 예치(`EntryPoint.depositTo`) 또는 자체 번들러(alto/rundler) 실행. 테스트넷은 무료 키로 충분 | 가스 대납 UX. 본인 계정이면 예치가 더 단순 |
| 전용 RPC | 공개 RPC(`sepolia.base.org`, `mainnet.base.org`) | 레이트리밋·가용성 보장 |
| Basescan 키 | 검증 생략(배포는 됨) | 탐색기에서 소스 보기 |
| FCM | **셀프호스팅 ntfy** (Z-1.R.3 폴백이 원래 이것) | 모바일 기본 푸시 채널 |
| Apple Developer | macOS 미지원으로 두기 | 맥 배포 |
| Relay TLS | Let's Encrypt(무료·자동) 또는 자체 서명 + 앱에 인증서 핀 고정 | — |

### 자체 서명으로 Windows 바이너리에 서명하기 (참고)

```powershell
$c = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Z-BACS Dev" `
     -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(3)
# 내 PC에서 경고를 없애려면 신뢰된 루트에 등록(다른 PC에는 효과 없음)
Export-Certificate -Cert $c -FilePath zbacs-dev.cer
Import-Certificate -FilePath zbacs-dev.cer -CertStoreLocation Cert:\CurrentUser\Root
signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 zbacs-agent.exe
```

자체 서명은 **내 PC에서만** 경고가 사라진다. 남에게 배포할 때는 EV 인증서가 있어야 하고, 그때 §4.1로 돌아오면 된다.

### 결론

**보안적으로 잃는 것은 없다.** 파일을 지키는 키(패스키·TPM 기기 키·DEK·봉인키)는 처음부터 전부 기기 안에서 우리가 만들고, 어떤 발급기관도 관여하지 않는다. 외부 자격 증명은 편의(가스 대납·푸시·경고 없는 설치)일 뿐이다.
