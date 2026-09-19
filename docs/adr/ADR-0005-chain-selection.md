# ADR-0005: EVM L2(Base) + 로컬 Anvil, 소유자 = 패스키 스마트계정

- 상태: Accepted (2026-09-18)

## 결정
- 개발: Foundry Anvil. 테스트넷: Base Sepolia. 운영: Base(또는 RIP-7212 지원 OP Stack 체인). 프라이빗 배포 옵션: Hyperledger Besu.
- 소유자 계정: ERC-7579 Kernel + 패스키(WebAuthn) 검증 모듈, 페이마스터 가스 대납(Pimlico).
- 컨트랙트: OpenZeppelin v5, UUPS + Timelock.

## 근거
- L2는 승인 왕복 지연을 초 단위로 유지한다(보고서 §6.2).
- RIP-7212 P-256 프리컴파일로 패스키 서명 온체인 검증 가스가 낮다.
- 감사 로그·회수·정책 앵커는 EVM 이벤트로 충분하다.

## 대안
- 자체 하이브리드 DLT(BSA 방식) — 운영 부담 과다.
- Solana/Sui — 패스키 지원은 있으나 생태계·AA 도구 성숙도에서 EVM 우위.

## 결과
- `strict_onchain` 정책이 아닌 경우 개봉은 체인 확정을 기다리지 않는다(UX 우선).
