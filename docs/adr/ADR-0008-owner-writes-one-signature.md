# ADR-0008: 체인 쓰기 경로 — 소유자 계정이 직접 제출, 한 번의 탭 = 한 번의 서명

- 상태: Accepted (2026-09-28, Z-1.H.8 b단계)
- 관련: [ADR-0005](ADR-0005-chain-selection.md)(Base L2 + 페이마스터), [ADR-0006](ADR-0006-owner-signer-dual-path.md)(승인 서명기 이중 경로), [approval_protocol.md](../specs/approval_protocol.md) §1.3·§2·§3, `contracts/src/AccessPolicy.sol`, `crates/zbacs-chain/src/writer.rs`

## 문제
Z-1.H.8 a단계까지 체인 쓰기(`register`·`grant`·`bumpVersion`·`revoke`)의 **바이트**는 준비됐지만, Agent에 배선하려니 두 가지가 남았다.

1. **`grant`의 이중 서명.** 스펙 §3은 소유자 스마트계정이 UserOp로 `grant(g, ownerSig)`를 제출한다고 했다. 그런데 UserOp는 그 자체의 서명(userOpHash)이 필요하고, `ownerSig`는 EIP-712 digest에 대한 별도 서명이다 — 승인 한 번에 기기 서명기를 **두 번** 부른다. `DeviceKey` 서명기는 두 번째를 조용히 할 수 있지만 플랫폼 패스키(Windows Hello)는 항상 프롬프트를 띄우므로 **한 번 허락에 Hello가 두 번** 뜬다. ux_principles의 "한 번의 탭" 과 T23(명시적 탭에만 키 사용)에 모두 어긋난다.
2. **Anvil에서는 스마트계정이 없다.** Kernel 팩토리·EntryPoint·번들러는 Base(Sepolia)에 있고 로컬 Anvil에는 없다. 그런데 E2E는 로컬에서 돌아야 한다(Q.1 하네스, CI).

## 결정
1. **`AccessPolicy.grant`는 호출자가 소유자 계정 자신이면 `ownerSig`를 요구하지 않는다.**
   `if (msg.sender != owner && !SignatureChecker.isValidSignatureNow(owner, digest, ownerSig)) revert InvalidSignature();`
   소유자 계정이 이 호출을 했다는 것은 이미 그 계정의 검증기가 (UserOp 서명으로) 승인했다는 뜻이다 — `revoke`·`bumpVersion`의 `onlyOwner`와 같은 근거다. 제3자(Relay·수신자)가 대신 제출하는 경로는 그대로 서명을 요구한다(ECDSA 또는 ERC-1271).
   → 승인 한 번 = 기기 서명 한 번(UserOp 해시). `Write::Grant{permission}`을 서명기에 알려 T23 확인 정책(Edit·연속 승인은 OS 확인)을 그 한 번의 서명에 적용한다.
2. **쓰기는 `ChainWriter` 트레이트 뒤에 둔다(`zbacs-chain::writer`).**
   - `SmartAccountWriter`: 프로덕션. Kernel v3.1 계정(루트 검증기 = 기기 승인 키, `aa.rs`) → 쓰기 1건 = UserOp 1건(미배포면 initCode 동반) → 번들러 + 페이마스터(`bundler.rs`). 소유자 = 계정 주소.
   - `DirectWriter`: Anvil·셀프호스팅·테스트. 자금이 있는 키가 일반 트랜잭션으로 보낸다. 소유자 = 그 키의 주소.
   Agent는 둘을 구분하지 않는다. 설정이 없으면 쓰기 없이 동작하고 `chain_*` pending으로 정직하게 표시한다(지금까지와 같다).
3. **수신자(Bob)의 소유자 서명 검증(스펙 §2 규칙 4)은 체인 기록으로 한다.** `GrantMsg.tx_hash`(허락 트랜잭션)가 오면 `AccessPolicy.isValid(grantId)`/`Granted` 이벤트가 소유자의 승인 증거이고, 체인 확정 전에는 봉투 바인딩(DEK 봉투의 AAD = grantId — 소유자만 만들 수 있다)이 열기의 근거다. `GrantMsg.owner_sig`(EIP-712 digest에 대한 기기 서명)는 `DirectWriter` 경로에서만 채워진다(개발용, 기존 T23 테스트 유지). 스마트계정 경로에서는 `owner_sig = None`, `tx_hash = Some`.
4. **소유자 주소는 첫 실행에 정해진다.** 스마트계정 경로에서는 기기 승인 키로 계산한 카운터팩추얼 주소(배포는 첫 쓰기가 한다), 직접 경로에서는 키의 주소. `DeviceProfile.account`에 기록되고 이후 모든 컨테이너의 `owner`·Relay 라우팅 키가 된다. 프로필이 이미 다른 값을 갖고 있으면 바꾸지 않는다(바꾸면 그 전에 잠근 파일의 요청이 이 기기에 도달하지 않는다).
5. **백그라운드 쓰기(`bumpVersion`)의 프롬프트.** 버전 통지 수락은 사람의 탭이 아니다. `Write::BumpVersion`에는 `Confirmation::NotRequired`를 적용하고, 그래도 프롬프트를 띄우는 서명기(플랫폼 패스키)에서는 **미룬다** — 다음 명시적 탭(허락·회수·잠그기)의 UserOp에 배치로 묶는 것이 다음 단계(Z-2.H.x, ERC-7579 batch 실행). 그때까지 패스키 기기의 `bumpVersion`은 큐에 남고 개발 패널에 `chain_version` pending으로 보인다.

## 결과
- 컨트랙트 변경 1줄 + 테스트 3종(`test_owner_account_submits_its_own_grant_without_a_signature`, `test_t14_the_owner_shortcut_is_not_open_to_others`, `test_smart_account_owner_calling_itself_needs_no_signature`). 배포된 컨트랙트가 없으므로 마이그레이션 없음. ABI는 변하지 않아 `zbacs-chain/abi` 사본은 바이트코드만 갱신.
- 스펙 §3 검증 순서의 마지막 항목이 "서명(호출자가 소유자면 생략)"으로 바뀐다. §1.3 `GrantMsg.tx_hash`의 의미가 정해진다.
- Anvil E2E(Agent 두 대 + Relay + Anvil)가 `DirectWriter`로 돈다 — 잠그기→`register`, 허락→`grant`(+`tx_hash`), 저장→`bumpVersion`, 회수→`revoke`, 그리고 G.12 기록에 체인 이벤트(`Source::Chain`)가 합쳐진다.
- 위협: 소유자 계정을 사칭하려면 계정의 검증기(기기 키)를 통과해야 하므로 T02/T14 경계는 그대로다. 제3자 제출 경로의 서명 검사는 유지되어 Relay가 허락을 위조할 수 없다(T06).

## 대안
- **Relay가 `grant(g, ownerSig)`를 대신 제출** — 서명 한 번으로 되지만 Relay에 가스 키가 필요하고, Relay 불통이 체인 기록 불통이 된다(T21). 소유자 계정 제출이 페이마스터 대납(ADR-0005)과 자연스럽게 맞는다. 제3자 제출 경로는 컨트랙트에 남겨 두어 나중에 폴백으로 쓸 수 있다.
- **Kernel ERC-1271로 검증되는 서명 하나만 쓰고 UserOp는 다른 키가 서명** — Kernel은 계정 검증기의 서명을 요구하므로 결국 같은 키를 두 번 부른다.
- **Anvil에 Kernel 전체를 배포** — 네트워크에서 바이트코드를 끌어와야 하고(포크), CI를 외부 RPC에 묶는다. `DirectWriter`가 같은 calldata를 보내므로 컨트랙트 쪽 검증은 동일하게 된다.
