# docs/research/ — 수집 코드·스니펫·벤더링 기록

`research.md`의 카테고리별로 실제 수집한 코드 조각, API 응답 예시, 벤치마크 결과를 보관한다.

| 파일 | 내용 |
|---|---|
| `auth_passkey_windows.md` | webauthn.dll 호출 예제, webauthn-rs 검증 흐름 (수집 예정) |
| `crypto_container_poc.md` | 청크 AEAD + HPKE 봉투 PoC 기록 (Z-0.C.1/C.2 완료) |
| `tauri_file_association.md` | → `spikes/tauri-assoc/README.md` 참조 (Z-0.G.1 완료) |
| `contracts_eip712_grant.md` | AccessGrant 타입 해시, 검증 설계, 교차 구현 벡터 (Z-0.H.1 완료) |
| `aa_passkey_spike.md` | RIP-7212 실측(OR-2), Kernel v3.1 + WebAuthn 패스키 UserOp 포크 실행, 가스 (Z-0.H.2 완료) |
| `pre_umbral_notes.md` | umbral-pre API, kfrag/cfrag 흐름 (Phase 3) |
| `hf_audit_pipeline.md` | HF 모델 로컬 추론 스크립트, Slither 연동 (권장) |

규칙:
1. 외부 코드를 붙여 넣을 때는 **출처 URL, 커밋 해시, 라이선스**를 첫 줄에 기록한다.
2. GPL 코드는 이 폴더에만 두고 `zbacs-*` 패키지에 복사하지 않는다.
3. 벤치마크는 환경(OS, CPU, 버전)을 함께 기록한다.
