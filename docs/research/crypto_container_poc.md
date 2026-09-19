# 컨테이너 PoC 기록 (Z-0.C.1 / Z-0.C.2)

- 일자: 2026-09-19
- 코드: `crates/zbacs-core` (라이브러리), `crates/zbacs-cli` (PoC CLI `zbacs`)
- 환경: Ubuntu 22.04, Rust 1.98.1, 24코어 (AMD64), 릴리스 프로파일 `lto=thin`

## 사용 크레이트 (출처·라이선스)
| 크레이트 | 버전 | 라이선스 | 용도 |
|---|---|---|---|
| chacha20poly1305 (RustCrypto) | 0.10 | MIT/Apache-2.0 | XChaCha20-Poly1305 청크 AEAD |
| hpke-rs + hpke-rs-rust-crypto (cryspen) | 0.2.0 | MPL-2.0 | RFC 9180 HPKE Base, DHKEM-X25519/HKDF-SHA256/ChaCha20-Poly1305 |
| x25519-dalek | 2 (`static_secrets`) | BSD-3 | X25519 키 생성·공개키 파생 (hpke-rs는 `hazmat` 없이는 비밀키 바이트를 노출하지 않음) |
| ed25519-dalek | 2 | BSD-3 | 헤더 서명 |
| sha2, blake3 | 0.10 / 1 | MIT/Apache | fid 커밋, 트레일러 무결성 |
| ciborium + serde_bytes + serde_repr | 0.2 / 0.11 / 0.1 | Apache-2.0 / MIT | CBOR 헤더 |
| zeroize | 1 | MIT/Apache | 키 자료 제로화 |
| clap, serde_json, hex, anyhow | 4 / 1 / 0.4 / 1 | MIT/Apache | CLI |

## 측정
| 항목 | 결과 |
|---|---|
| 100 MB seal (release) | 204 ms |
| 100 MB open (release) | 145 ms |
| 합계 | 0.35 s (DoD ≤ 2 s 충족) |
| 디버그 빌드 동일 테스트 | ~43 s → 디버그에서는 `#[ignore]`, CI는 `cargo test --release -- perf_` |

## 스펙 대비 구현 메모
- 헤더 앞에 `u32 LE` 길이 필드를 두어 스트리밍 파서가 헤더 경계를 알 수 있게 했다 (스펙 §2 레이아웃 반영).
- 청크 nonce prefix(16B)는 헤더 `np` 필드에 저장.
- 파일명은 DEK로 암호화하며 nonce index `u64::MAX` 예약.
- 봉투 AAD = `fid` (컨테이너 내장 봉투). 승인 시 외부 전달 봉투는 grant 해시를 AAD로 쓸 예정(Z-1.H.2).
- seal은 2패스(1: SHA-256 → fid, 2: 암호화)라 입력이 `Read + Seek`이어야 한다. 파이프 입력이 필요하면 임시 파일 경유.
- 헤더 서명 검증은 `body`를 다시 CBOR 직렬화해 수행. 필드 순서가 곧 정규화 규칙이므로 `HeaderBody` 필드 순서 변경 = 포맷 버전 상승.

## 테스트 매핑 (docs/threat_model.md)
| 테스트 | 위협 |
|---|---|
| `t02_header_tamper_policy_is_detected` | T02 정책 변조 |
| `t04_wrong_key_cannot_open` | T04 키 없는 개봉 |
| `t18_chunk_tamper_is_detected`, `t18_chunk_reorder_is_detected` | T18 파서/청크 |
| `t19_truncation_is_detected` | T19 절단·다운그레이드 |
| `bad_magic_and_version` | T19 |
| `envelope::tests::roundtrip_and_aad_binding` | T04/T05 봉투 바인딩 |

## 남은 일
- Z-1.C.2 견고화(길이 상한 세분화, 헤더 크기 DoS), Z-1.C.3 `cargo-fuzz` 타깃, Z-1.C.4 Reseal API(현재 `SealOptions.prev`로 버전 체인 필드만 지원).
- CLI 키 파일은 평문 JSON(PoC 전용). Agent는 OS 키체인(Z-1.A.3).
