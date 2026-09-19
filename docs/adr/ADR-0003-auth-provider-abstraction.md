# ADR-0003: AuthProvider 추상화 — 패스키 우선, BSA는 어댑터

- 상태: Accepted (2026-09-18). 2026-09-19 ADR-0006으로 `DeviceKeyProvider`(등록 기기 바운드 키) 추가.

## 컨텍스트
프로젝트 명세는 BSA(Blockchain Secure Authentication) 기반이다. 그러나 BSA SDK는 상용·비공개이며 ITU DFS 샌드박스 Client Key 신청이 필요하고 공개 저장소가 없다. 개발 초기부터 BSA에 종속되면 진행이 막힌다.

## 결정
- `zbacs-auth`에 `AuthProvider` 트레이트를 두고 세 구현을 제공한다.
  1. `PasskeyProvider` — WebAuthn/FIDO2 (Windows Hello via webauthn.dll, macOS Secure Enclave, Linux libfido2). MVP 기본.
  2. `BsaProvider` — BSA Web/Mobile SDK 래핑. SDK 확보 즉시 연결.
  3. `OtakProvider` — ITU-T X.1284 흐름을 참조한 자체 일회용 인증키 구현(폴백·데모).
- 승인 서명은 EIP-712 `AccessGrant`로 통일하여 어떤 Provider든 동일 티켓을 생성한다.
- 문서·마케팅에서 "BSA 기반"은 "X.1284 표준 흐름 준수 + BSA SDK 연동 가능"으로 정의한다.

## 근거
- 패스키는 즉시 구현 가능하고 하드웨어 보호 서명을 제공하며, BSA의 핵심 가치(패스워드리스, 기기 생체)와 일치한다.
- 어댑터 패턴으로 벤더 종속과 라이선스 리스크를 격리한다.

## 결과
- Z-0.A.3에서 BSA 샌드박스 신청을 병행한다.
- `ApprovalAssertion` 형식은 Provider별 검증 경로(체인 P-256 / Relay 검증 / BSA 콜백)를 포함해야 한다.
