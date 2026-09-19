# Z-0.H.2 — 패스키 스마트계정 스파이크 (RIP-7212 실측 + Kernel v3.1 WebAuthn UserOp)

독립 Node + Foundry 프로젝트. 루트 Cargo 워크스페이스·CI에 포함되지 않는다.
결과 요약은 `docs/research/aa_passkey_spike.md`.

## 무엇을 검증하나
1. **OR-2** — Base Sepolia / Base 메인넷에서 P256VERIFY 프리컴파일(`0x…0100`, RIP-7212/EIP-7951)이 실제로 동작하는가, 가스는 얼마인가.
2. **패스키 → 스마트계정 → UserOp** — permissionless.js `toKernelSmartAccount`(Kernel v3.1 + WebAuthn 검증기)로 만든 계정이 소프트웨어 패스키 서명 1건으로 실제 EntryPoint v0.7 `handleOps`를 통과하는가. 번들러 API 키 없이 Base Sepolia **포크**에서 실행한다.

## 실행
```bash
npm install
npm run probe                                   # OR-2: 4개 체인 eth_call 실측
node scripts/p256-vector.mjs --out vectors/p256.json
node scripts/kernel-account.mjs                 # 패스키 생성 → Kernel 계정 주소 → 서명된 UserOp → vectors/userop.json
forge test --fork-url https://sepolia.base.org -vv   # 포크에서 EntryPoint.handleOps 실행 + 가스 측정
```
`PIMLICO_API_KEY`가 있으면 `node scripts/kernel-account.mjs --send`로 같은 UserOp를 실제 번들러에 제출한다(스파이크에서는 미실행).

## 구성
| 경로 | 역할 |
|---|---|
| `scripts/probe-rip7212.mjs` | 체인별 P256VERIFY 활성 여부·Daimo p256-verifier 폴백 배포 여부 실측 (의존성 없음) |
| `scripts/p256-vector.mjs` | P-256 서명 벡터 + WebAuthn 형태 assertion 벡터 생성 |
| `scripts/virtual-authenticator.mjs` | node:crypto P-256 키로 플랫폼 인증기(Windows Hello) 흉내 → viem `WebAuthnAccount` |
| `scripts/kernel-account.mjs` | permissionless.js Kernel v3.1 계정 생성, UserOp 구성·서명, `usePrecompiled=true` 변형 재인코딩 |
| `src/IEntryPoint.sol` | EntryPoint v0.7 최소 인터페이스(자체 선언, GPL 레퍼런스 미벤더링) |
| `src/Recorder.sol` | UserOp 호출 대상(포크에서 `0x…BEEF`에 etch) |
| `test/Rip7212.t.sol` | 프리컴파일 정확한 가스(`gasleft()`), 변조·high-s 거부 여부, WebAuthn digest 검증 |
| `test/PasskeyUserOp.t.sol` | `handleOps` 실행: Kernel 배포 + WebAuthn 검증 + 호출, T14 변조 거부(AA24), T03 재전송 거부(AA25) |
| `vectors/*.json` | 재현용 픽스처(공개키·서명만, 개인키 없음) |

## 주요 발견
- P256VERIFY는 Base Sepolia·Base 메인넷·OP Sepolia·Ethereum Sepolia 모두 **활성**. 유효 서명 검증 가스 **3,885**(STATICCALL 오버헤드 포함) vs Daimo Solidity 폴백 **334,897**.
- 프리컴파일은 high-s 서명을 **거부하지 않는다** → 온체인 검증기가 스스로 low-s를 강제해야 한다(Kernel WebAuthn 검증기는 클라이언트 ox가 normalizeS 처리).
- permissionless.js 0.4.1은 Kernel WebAuthn 서명에 `usePrecompiled=false`를 하드코딩(TODO 주석). 같은 UserOp를 `true`로 재인코딩하면 배포+검증+실행 가스가 **789,620 → 450,310**(−43%). Phase 1에서 서명 인코딩을 직접 제어해야 한다.
- node:crypto `sign(null, digest, ecKey)`는 digest를 다시 SHA-256 한다 — 프리해시 서명이 아니다. 온체인 검증기 교차검증으로 발견; 벡터 생성기는 프리이미지를 넘겨 한 번만 해시한다.
