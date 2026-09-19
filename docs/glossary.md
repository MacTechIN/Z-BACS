# 용어집 (Glossary)

| 용어 | 정의 |
|---|---|
| **Z-BACS** | Zero-Knowledge & Blockchain-based Access Control System. 본 프로젝트 |
| **BSA** | Blockchain Secure Authentication. SIG ONE/FNSV의 블록체인 기반 패스워드리스 인증(ITU-T X.1284/X.1286) |
| **OTAK** | One-Time Authentication Key. 요청마다 생성·폐기되는 일회용 인증키 |
| **MIRC / MDV** | BSA의 다중요소 무작위 조합 / 다중노드 분산 검증 계층 |
| **Seal / Open / Reseal** | 봉인(암호화) / 개봉(승인 후 복호화) / 재봉인(저장 후 재암호화) |
| **DEK** | Data Encryption Key. 파일 본문을 암호화하는 대칭키 |
| **Envelope(봉투)** | DEK를 특정 공개키로 HPKE 암호화한 것 |
| **HPKE** | Hybrid Public Key Encryption, RFC 9180 |
| **AccessRequest / AccessGrant / GrantMsg** | 접근 요청 / EIP-712 승인 티켓 / 티켓+봉투 전달 메시지 |
| **Permission** | Deny / ReadOnly / Edit |
| **Relay** | 요청·승인을 중계하는 무신뢰 서버 |
| **Protected Workspace** | 수신자 기기에서 평문이 잠시 머무는 ACL 보호 디렉터리 |
| **Guardian Node** | Phase 3 프록시 재암호화 노드 |
| **PRE / TPRE** | (Threshold) Proxy Re-Encryption |
| **ERC-4337 / 7579** | 계정 추상화 / 모듈러 스마트계정 표준 |
| **RIP-7212** | secp256r1(P-256) 서명 검증 프리컴파일 |
| **EIP-712** | 구조화 데이터 서명 표준 |
| **Passkey / WebAuthn** | FIDO2 기반 패스워드리스 자격증명 |
| **Stub** | 컨테이너에 붙는 최소 실행 파일(자체실행 래퍼) |
| **Minifilter** | Windows 파일시스템 필터 드라이버 |
