# ADR-0006: 소유자 승인 서명 이중 경로 — 플랫폼 패스키(Windows Hello 등) 또는 등록 기기 바운드 키, 소유자가 선택

- 상태: Accepted (2026-09-19, 사용자 지시)

## 컨텍스트
ADR-0003은 소유자 승인 서명을 `PasskeyProvider`(Windows Hello 등 OS 인증기) 하나로 두었다. 이 경로는 (1) 승인마다 생체 창이 뜨고, (2) OS 인증기가 없는 기기(생체 없는 태블릿, FIDO 미설치 Linux)에서는 쓸 수 없으며, (3) Windows에 종속된 스파이크(Z-0.A.1)를 Phase 0 게이트로 만든다. 소유자는 자신이 허용한 하드웨어(PC·모바일·태블릿)에서만 승인이 나가길 원하고, 생체 확인 여부는 선택하고 싶어 한다.

## 결정
소유자 스마트계정(Kernel v3.1)에 **두 종류의 서명자**를 등록할 수 있고, 소유자가 기기마다 선택한다.

| 서명자 종류 | 키 위치 | 승인 시 사용자 경험 | 온체인 검증 |
|---|---|---|---|
| **PlatformPasskey** | OS 인증기(Windows Hello / Touch ID / Android 생체). TPM·Secure Enclave 보호 | 승인마다 얼굴·지문·PIN 창 | Kernel WebAuthn 검증기(기존) |
| **DeviceKey** | Agent가 기기 하드웨어 저장소에 생성한 **내보내기 불가 P-256 키**(Windows: TPM Platform Crypto Provider, Android: Keystore StrongBox, iOS: Secure Enclave) | 등록된 기기에서 "허용" 탭만으로 승인. 기기별 옵션으로 OS 확인(생체/PIN) 켤 수 있음 | 새 `P256Validator`(ERC-7579): 계정당 키 집합, P256VERIFY 프리컴파일 + Daimo 폴백, low-s 강제 |

- **선택 UI**(온보딩 1화면, 이후 "내 기기"에서 변경): "얼굴/지문으로 확인하고 승인" / "이 기기에서 바로 승인". 기술 용어·입력 필드 없음. 기본값: OS 인증기가 있으면 전자, 없으면 후자.
- **기기 등록** = 이미 등록된 서명자가 새 기기를 허용하는 UserOp(첫 기기는 온보딩에서 자동). **기기 해지** = 다른 등록 기기에서 한 번의 탭. 등록·해지는 모두 계정의 검증기 키 집합 변경이므로 체인에 기록된다(T12, T22).
- 두 경로 모두 동일한 EIP-712 `AccessGrant`를 만들고, Bob Agent의 검증은 ERC-1271 `isValidSignature` 하나로 동일하다(spec §2 규칙 4 불변).
- `zbacs-auth`에 `DeviceKeyProvider`를 추가한다. `PasskeyProvider`·`BsaProvider`·`OtakProvider`는 유지.

## 근거
- 소유자가 허용한 하드웨어에서만 승인이 나간다는 요구를 두 경로가 모두 만족한다(둘 다 키가 하드웨어를 떠나지 않음).
- DeviceKey는 플랫폼 독립적이라 Phase 0 게이트를 Windows 실기에서 분리하고, 모바일·태블릿 승인 앱(Z-1.P)과 같은 구조를 쓴다.
- 생체 확인은 "존재 증명"이 필요한 고가치 승인에 여전히 유용하므로 버리지 않는다.

## 대안
- Windows Hello만 — Windows 종속, 승인 피로, 사용자 요구와 불일치. 기각.
- DeviceKey만 — 생체 존재 증명을 잃음. 기각.
- 두 키를 한 검증기(WebAuthn)로 — DeviceKey를 WebAuthn 포맷으로 감싸면 가능하나 불필요한 복잡성. `P256Validator`가 더 단순하고 가스가 적다.

## 결과
- 새 위협 **T23**: 무프롬프트 DeviceKey를 소유자 기기의 악성코드가 자동 승인에 악용. 완화: 키 사용은 Agent UI의 명시적 탭에만 연결, Edit 권한·다량 승인은 OS 확인 강제(기본 정책), 승인 속도 제한, Phase 3 VBS 격리. `threat_model.md` v1.2.
- 태스크: Z-1.A.7 `DeviceKeyProvider`, Z-1.H.10 `P256Validator` + 기기 등록/해지, Z-1.U.7 선택 UI(Figma 먼저), Z-1.G.2 온보딩에 선택 포함. Z-0.A.1(Windows Hello)은 유지하되 Phase 0 게이트에서 제외 — DeviceKey 경로는 Z-0.H.2에서 이미 체인까지 검증됨(P-256 서명 = 같은 프리미티브).
- 스펙 `approval_protocol.md` §1.5 소유자 서명 방식, `architecture.md` §5 키 계층 갱신.
