# 컨트랙트 EIP-712 승인 티켓 PoC 기록 (Z-0.H.1)

- 일자: 2026-09-19
- 코드: `contracts/` (Foundry). `src/AccessGrantLib.sol`, `src/FileRegistry.sol`, `src/AccessPolicy.sol`, `test/*.t.sol`, `script/Deploy.s.sol`
- 환경: forge 1.8.3, solc 0.8.28 (cancun), OpenZeppelin v5.7.0, forge-std v1.16.2
- 스펙: `docs/specs/approval_protocol.md` §1.2, §3

## 의존성 (출처·라이선스)
| 패키지 | 버전 | 라이선스 | 용도 |
|---|---|---|---|
| OpenZeppelin/openzeppelin-contracts | v5.7.0 (git submodule `contracts/lib/`) | MIT | `EIP712`, `SignatureChecker`(ECDSA + ERC-1271), `ECDSA`. v5.7에는 `P256.sol`, `WebAuthn.sol`도 포함 → Z-0.H.2 패스키 검증기 후보 |
| foundry-rs/forge-std | v1.16.2 | MIT/Apache | 테스트 |

## 설계 요점
- `grantId = EIP-712 structHash(AccessGrant)` — 주소·체인 독립. 서명 검증은 `_hashTypedDataV4`로 도메인(name "Z-BACS", version "1", chainId, verifyingContract)에 바인딩.
- 재전송 방지 2중: 소유자 순차 `grantNonce` + 1회용 `requestNonce`(T03).
- 서명자 = `FileRegistry.ownerOf(fileId)`. EOA면 ECDSA, 스마트계정이면 ERC-1271(`SignatureChecker.isValidSignatureNow`). 제출자는 누구나(릴레이어·페이마스터).
- 시간 검사는 온체인 시간(T15). `isValid`는 `notBefore ≤ now < expiry && !revoked && opens < maxOpens`.
- `revoke`는 소유자 계정만(T20). ERC-1271 계정의 경우 EOA가 아니라 계정 컨트랙트가 호출해야 함(테스트로 확인).

## 테스트 (18개, 퍼즈 512회)
| 테스트 | 위협 |
|---|---|
| `test_t03_replay_same_grant_rejected`, `test_t03_request_nonce_cannot_be_reused_with_new_grant_nonce`, `test_t03_signature_bound_to_chain_and_contract` | T03 재전송·크로스체인·크로스컨트랙트 |
| `test_t14_wrong_signer_rejected`, `test_t14_tampered_field_rejected`, `test_t14_erc1271_smart_account_owner` | T14 서명 우회, T02/T06 권한 상향 변조 |
| `test_t15_expiry_and_notBefore`, `test_t15_already_expired_grant_rejected` | T15 시간 |
| `test_t20_revoke_only_owner` | T20 회수 |
| `test_t02_only_owner_bumps` (FileRegistry) | T02 |

## 교차 구현 테스트 벡터 (zbacs-chain / alloy에서 동일 값 재현해야 함)
```
TYPEHASH = keccak256("AccessGrant(bytes32 fileId,bytes32 headerHash,bytes32 deviceKeyHash,uint8 permission,uint64 notBefore,uint64 expiry,uint16 maxOpens,bytes16 requestNonce,uint256 grantNonce)")
         = 0xb18a4d7501b33e154c64c24685dc7ca4ac200e967e8b2b5bd7574b90c518a00e
vector-1: fileId=0x..01 headerHash=0x..02 deviceKeyHash=0x..03 permission=1 notBefore=1700000000 expiry=1700003600 maxOpens=1 requestNonce=0x00000000000000000000000000000004 grantNonce=0
STRUCT_HASH(vector-1) = 0xd57d596bf1b00f8b8cc22ada6875352e42b07bf7bc0d02db0c208083732b78fa
domain: name="Z-BACS" version="1"
```

## forge lint 상태
- `block-timestamp` 경고 3건은 의도된 사용(T15). 만료·시작 시각은 초 단위 정밀도가 필요 없고 L2 시퀀서 편차(수 초)는 `docs/specs/approval_protocol.md` §2의 허용 오차 안에 있다. 경고는 유지하고 여기서 문서화한다.
- `reentrancy-events` 1건은 ERC-1271 staticcall 뒤의 emit이라 억제 주석 처리.

## Anvil 배포 확인 (2026-09-19)
`anvil` + `forge script script/Deploy.s.sol --broadcast` → FileRegistry `0x5FbD…0aa3`, AccessPolicy `0xe7f1…0512` (기본 계정 nonce 0/1). `cast send register(...)` 후 `ownerOf` 조회로 소유자 확인.

## 배운 것
- Foundry `vm.expectRevert`는 **바로 다음 외부 호출**에 걸린다. 서명 헬퍼가 `policy.digestOf()` view를 호출하면 그 호출이 대상이 되어 테스트가 잘못 실패한다 → 서명을 먼저 만들고 expectRevert.
- `forge install`은 `foundry.toml`이 없으면 git 루트를 프로젝트 루트로 보고 `<git root>/lib`에 설치한다. `contracts/foundry.toml`을 먼저 만들 것.

## 남은 일 (Z-1.H.1/H.2)
- UUPS 프록시 + Timelock, `retire()`, `consumeOpen`에 기기 어테스테이션 바인딩.
- Z-0.H.2: Kernel(ERC-7579) + 패스키 검증기(또는 OZ `WebAuthn.sol`/`P256.sol`)로 ERC-1271 경로 실제 검증, Base Sepolia RIP-7212 확인.
- Slither/Echidna CI(Z-1.H.5), HF 감사(Z-1.H.6).
