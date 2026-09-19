# ADR-0002: 파일 암호화 = XChaCha20-Poly1305 청크 스트림, 키 봉투 = HPKE(X25519)

- 상태: Accepted (2026-09-18)

## 결정
- 본문: XChaCha20-Poly1305, 64KiB 청크, 청크 인덱스·`is_last`를 AAD로 포함.
- DEK 봉투: HPKE Base mode (DHKEM-X25519, HKDF-SHA256, ChaCha20-Poly1305) — `hpke-rs` + RustCrypto 백엔드.
- 헤더 서명: Ed25519. 해시: SHA-256(파일 커밋), BLAKE3(무결성).
- 모든 키 자료는 `zeroize`/`secrecy`로 관리.

## 근거
- XChaCha20의 192비트 nonce는 파일별 랜덤 prefix + 카운터 조합에 안전 여유가 크다.
- AES-GCM은 하드웨어 가속 시 빠르지만 nonce 오용 위험이 크고, 대상 기기가 다양하다.
- HPKE는 RFC 9180 표준으로 상호운용성과 감사 용이성이 높다. 이후 하이브리드 PQC KEM(X-Wing)으로 교체 가능.
- age 포맷을 그대로 쓰지 않는 이유: 정책·버전 체인·온체인 커밋을 헤더에 넣어야 하고, 다중 봉투를 승인 시점에 외부(GrantMsg)로 전달해야 하기 때문.

## 대안
- age 포맷 직접 사용 (플러그인으로 확장) — 검토했으나 헤더 확장성 부족.
- libsodium secretstream — 유사하나 Rust 순수 구현 선호.

## 결과
- 테스트 벡터를 `zbacs-core/tests/vectors`에 고정하고 변경 시 메이저 버전 상승.
