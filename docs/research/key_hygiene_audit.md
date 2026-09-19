# 키 자료 위생 감사 (Z-1.C.6, T11)

| 일자 | 2026-09-19 |
|---|---|
| 범위 | `crates/zbacs-core`, `crates/zbacs-auth` (Phase 1 시점) |
| 방법 | 소스 전수 검토 + 컴파일 타임 단언(`ZeroizeOnDrop` 구현 여부) + `Debug` 출력 테스트 |
| 결과 | 통과. 잔여 위험 4건은 아래 §4에 명시 |

## 1. 비밀 자료 목록과 처리

| 자료 | 타입 | 메모리 보호 | 로그 노출 |
|---|---|---|---|
| DEK (32B) | `zbacs_core::Dek` | `secrecy::SecretBox<[u8;32]>` — drop 시 0으로 덮음, 접근은 `expose_secret()` 경유 | `Debug` = `Dek(REDACTED)`. `Clone`/`Display` 없음 |
| 기기·소유자 X25519 비밀키 | `DeviceKeys` | `#[derive(Zeroize, ZeroizeOnDrop)]` | `Debug` = `DeviceKeys(kid=…, secret=REDACTED)` |
| 헤더 서명 Ed25519 비밀키 | `SigningKeys` | `#[derive(ZeroizeOnDrop)]` (dalek `SigningKey`가 자체 zeroize) | `Debug` = `SigningKeys(pub=…, secret=REDACTED)` |
| 소유자 승인키 (패스키/기기 키) | 하드웨어 (TPM/Secure Enclave/Keystore) | 프로세스 메모리에 **존재하지 않음** — OS가 서명만 수행 | 공개키·keyId만 다룸 |
| 소프트웨어 서명기(테스트용) | `zbacs_auth::software::*` | `p256::ecdsa::SigningKey`가 drop 시 스칼라 zeroize | feature `software-signer` 전용, 릴리스 빌드 제외 |
| 평문 청크 버퍼 | `Zeroizing<Vec<u8>>` (seal), 복호 결과 `Vec` (open) | seal: 스코프 종료 시 wipe. open: 기록 직후 `zeroize()` | — |
| 파일명 평문(패딩 포함) | 지역 `Vec` | `decrypt_name`이 반환 직전 wipe | 파일명은 UI에 표시되는 값 |

## 2. 코드 규칙 확인

- **에러에 비밀 없음**: `zbacs_core::Error`, `zbacs_auth::AuthError`의 모든 변이를 검토. 길이·인덱스·이유 문자열만 포함하며 키·평문·서명 원문을 담지 않는다. 테스트 `error_display_never_contains_key_material`.
- **`Debug` 자동 파생 금지**: 비밀을 가진 타입에 `#[derive(Debug)]`를 쓰지 않고 수동 구현으로 마스킹. 테스트 `t11_key_types_zeroize_on_drop_and_redact_in_logs`가 실제 비밀 16진수가 출력에 없음을 확인.
- **`ZeroizeOnDrop` 회귀 방지**: 컴파일 타임 단언(`fn assert_zeroize_on_drop<T: ZeroizeOnDrop>()`)으로 derive 제거를 CI에서 잡는다.
- **비밀 복사 최소화**: HPKE open이 돌려준 평문 DEK는 `Dek`로 감싼 뒤 중간 `Vec`을 즉시 wipe(`envelope.rs`).

## 3. PR 체크리스트 (dev_guidelines에 반영)

- [ ] 새 타입이 비밀을 담는가? → `SecretBox`/`Zeroize(OnDrop)` + 수동 `Debug`.
- [ ] 비밀이 `String`/`format!`/`log`/에러 메시지로 흘러가지 않는가?
- [ ] 평문 버퍼를 `Vec`으로 만들었다면 스코프 종료 전에 wipe 하는가?
- [ ] 비밀을 `Clone` 해야 한다면 사본의 수명과 wipe 지점을 주석으로 남겼는가?
- [ ] 테스트·예제에 실제 키를 커밋하지 않는가? (`tests/vectors/owner.json`은 이 벡터 전용 폐기 키이며 그 사실을 파일에 적어 둔다)

## 4. 잔여 위험 (수용, 상위 태스크로 이관)

1. **메모리 zeroize는 best-effort** — 컴파일러 최적화는 `zeroize`가 막지만, 앨로케이터가 재할당 전 복사하거나 OS가 페이지를 스왑하면 흔적이 남을 수 있다. 완화: 짧은 수명, Phase 3 TEE/VBS(`Z-3.G.2`).
2. **평문 파일 자체** — 열람 앱이 디스크에 쓰는 평문은 이 크레이트 밖의 문제다. `Z-1.G.8`(안전 삭제)·`Z-1.Q.2`(포렌식 검사)·`Z-2.G.3`(가상 드라이브)이 담당(T09/T10).
3. **스왑·하이버네이션** — OS 설정 영역. 설치 시 안내(`Z-1.D.1`), 기업 배포는 정책으로 비활성 권고.
4. **코어 덤프** — 크래시 시 프로세스 메모리가 파일로 남을 수 있다. Agent 패키징 단계(`Z-1.G.13`)에서 코어 덤프 비활성화를 설정한다.
