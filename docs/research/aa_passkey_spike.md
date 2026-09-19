# 패스키 스마트계정 스파이크 기록 (Z-0.H.2, OR-2)

| 일자 | 2026-09-19 |
|---|---|
| 코드 | `spikes/aa-passkey/` (독립 Node + Foundry) |
| 환경 | Ubuntu (Linux 6.8), Node 22.23.1, Foundry 1.8.3, viem 2.56.8, permissionless 0.4.1, Base Sepolia 포크 블록 47,012,597 |
| 결과 | **성공** — 포크 + **실제 Base Sepolia 번들러 제출 2건**(Pimlico, 페이마스터 스폰서) 모두 통과 |

## 1. OR-2: P256VERIFY 프리컴파일 실측

`scripts/probe-rip7212.mjs` — 새로 생성한 유효 P-256 벡터와 변조 벡터를 `0x0000…0100`에 `eth_call`.

| 체인 | chainId | 유효 서명 | 변조 서명 | 프리컴파일 | Daimo p256-verifier(`0xc2b7…4De4`) |
|---|---|---|---|---|---|
| Base Sepolia | 84532 | `0x…01` | `0x` | **활성** | 배포됨 (3,537 B) |
| Base 메인넷 | 8453 | `0x…01` | `0x` | **활성** | 배포됨 |
| OP Sepolia | 11155420 | `0x…01` | `0x` | **활성** | 배포됨 |
| Ethereum Sepolia | 11155111 | `0x…01` | `0x` | **활성** | 배포됨 |

포크 테스트(`test/Rip7212.t.sol`, `gasleft()` 측정, STATICCALL 오버헤드 포함):

| 검증기 | 가스 |
|---|---|
| P256VERIFY 프리컴파일 | **3,885** |
| Daimo p256-verifier (Solidity 폴백) | 334,897 |
| WebAuthn assertion 전체(sha256×2 + 프리컴파일) | 3,885 (+해시) |

주의: 프리컴파일은 **high-s 서명을 거부하지 않는다**. 서명 가변성(T03 재전송의 변형)은 온체인 검증기/클라이언트가 low-s 정규화로 막아야 한다. ox(viem)는 `normalizeS()`를 적용한다.

`eth_estimateGas`로는 프리컴파일 비용을 읽을 수 없다(EIP-7623 calldata 하한 가격에 묻힘). 정확한 값은 포크 테스트로만 얻는다.

## 2. 패스키 → Kernel v3.1 → UserOp

흐름(승인 앱이 그대로 쓸 경로):
1. `virtual-authenticator.mjs`: node:crypto P-256 키로 `navigator.credentials.get()`을 흉내 낸 `getFn` → viem `toWebAuthnAccount`. 실제 Agent에서는 이 `getFn`만 OS WebAuthn 호출(Z-0.A.1)로 바뀐다.
2. `toKernelSmartAccount({owners:[webauthn], entryPoint 0.7, version '0.3.1'})` — 검증기 `0x7ab1…9e69`(WebAuthn), 메타팩토리 `0xd703…42d5`. 카운터팩추얼 주소 계산에 번들러 불필요.
3. UserOp 구성 → `account.signUserOperation` → `vectors/userop.json`(PackedUserOperation 필드 + `usePrecompiled=true` 재인코딩 서명).
4. `test/PasskeyUserOp.t.sol`: Base Sepolia 포크에서 계정에 예치 후 `handleOps`.

| 테스트 | 결과 | 가스 |
|---|---|---|
| `test_userOpHash_matches_viem` | viem `getUserOperationHash` == `EntryPoint.getUserOpHash` | — |
| `test_passkey_userop_deploys_kernel_and_executes` (permissionless 기본, Solidity P-256) | 배포·실행·nonce 소모·예치 차감 확인 | **789,620** |
| `test_passkey_userop_with_rip7212_precompile` (`usePrecompiled=true`) | 동일 | **450,310** (−43%) |
| `test_t14_tampered_signature_rejected` | `AA24 signature error` | — |
| `test_t03_replay_rejected` | `AA25 invalid account nonce` | — |

## 2b. 실제 번들러 제출 (Base Sepolia, Pimlico 번들러 + 테스트넷 페이마스터)

`node --env-file=.env scripts/kernel-account.mjs --send [--precompile]` — 새 소프트웨어 패스키마다 새 Kernel 계정, 잔고 0, 가스는 페이마스터 스폰서.

| 변형 | 계정 | UserOp / tx | 블록 | 결과 | actualGasUsed |
|---|---|---|---|---|---|
| permissionless 기본 (`usePrecompiled=false`) | `0x03be3B8374695217C4C61d826BBD8C58c70C12b6` | [`0x2bf5…05f7`](https://sepolia.basescan.org/tx/0x2bf572108c88a1d176bfa4a44e05247fd06c352db67c1e4229e19bd718db05f7) | 47,013,308 | success | **757,792** |
| `--precompile` (`usePrecompiled=true`) | `0x073D161866B8334a27B97b96F2579fA3AE0140bc` | [`0x8e64…340c`](https://sepolia.basescan.org/tx/0x8e64a7f1652167388e8b5da52422596086a29a043aaef9aca4a1e313f4ca340c) | 47,013,314 | success | **418,432** (−45%) |

- 번들러(Pimlico alto)는 검증 단계의 `0x…0100` 프리컴파일 호출을 **허용**했다 → T21/ERC-7562 리스크 해소(Base Sepolia, 2026-09-19 기준). 
- 두 계정 모두 ERC-1967 프록시(61 B)로 배포됨. 첫 실행의 "deployed: false" 출력은 공개 RPC `latest` 지연이었고, 스크립트는 포함 블록 기준 조회로 수정.
- 포크 측정(789,620 / 450,310)과 실제 값(757,792 / 418,432)의 차이는 번들러 가스 추정·preVerificationGas 차이. 절감률은 동일(≈ −45%).

## 3. 발견·결정 사항
- **permissionless.js 0.4.1은 `usePrecompiled=false`를 하드코딩**(소스에 TODO). Base에서는 339k 가스를 낭비한다. Phase 1(`Z-1.H.8`)에서 Kernel WebAuthn 서명 인코딩을 직접 수행하거나 permissionless에 패치를 올린다.
- Kernel v3 nonce는 192비트 key에 검증기 모드/타입/주소를 담는다 — `getNonce(sender, 0)`가 아니라 `op.nonce >> 64` key로 조회해야 한다.
- 미배포 Kernel 계정의 `encodeCalls`는 마이그레이션 헬퍼 fallback 설치/해제 호출을 배치 앞뒤에 끼워 넣는다(permissionless 동작). 실행 가스에 포함됨.
- node:crypto `sign(null, data, ecKey)`는 data를 SHA-256 한 뒤 서명한다(프리해시 아님). 온체인 검증기(Daimo, 프리컴파일 둘 다 거부)로 잡아냈다.
- 번들러 제출(`--send`)은 §2b에서 완료. 포크와 실제 경로의 차이(ERC-7562 mempool 규칙)는 프리컴파일 변형까지 실측으로 해소.

## 4. Phase 1로 넘기는 것
- `Z-1.H.8`: `usePrecompiled=true`를 기본으로 하는 서명 인코딩(permissionless 패치 또는 자체 인코더), 페이마스터 정책(운영은 스폰서 한도·검증 필요).
- `Z-1.A.2`: `getFn`을 Windows Hello(Z-0.A.1)로 교체. rpId/origin은 Agent가 고정값(`zbacs.local`)으로 처리 — 사용자 입력 없음.
- ADR-0005 근거 항목에 실측치 반영(완료).
