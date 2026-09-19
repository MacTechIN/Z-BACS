# Z-BACS 기술 검토 및 리소스 카탈로그 (Technical Research)

| 항목 | 내용 |
|---|---|
| 문서 버전 | 1.0 (2026-09-18) |
| 목적 | 구현에 필요한 기술·오픈소스·모델·표준을 수집·평가하고, 라이브러리화 대상을 기록한다 |
| 수집 채널 | GitHub, Hugging Face, npm/crates.io/PyPI, ITU/표준 문서, 벤더 개발자 포털 |
| 관련 문서 | [project_definition.md](project_definition.md), [architecture.md](architecture.md), [dev_plan.md](dev_plan.md) |

> **운영 규칙**: 새 리소스를 발견하면 반드시 이 문서의 해당 카테고리 표에 추가하고, 도입 결정은 `docs/adr/`에 ADR로 남긴다. 실제 코드 스니펫·벤더링 대상은 `docs/research/` 아래 카테고리별 파일에 보관한다.

---

## 0. 리서치 요약 (2026-09 기준 핵심 사실)

| # | 사실 | 설계 영향 |
|---|---|---|
| R1 | **NuCypher 조직은 비활성** 상태. `pyUmbral`, `taco-web`, `nucypher` 노드 런타임은 유지보수 중단. TACo는 2026 하반기 WEDF(World Ethical Data Forum)가 포크·재출범 예정 | TACo 네트워크 의존 금지. Umbral **알고리즘**은 `umbral-pre`(Rust) 라이브러리로 자체 노드에서 사용 가능 → Phase 3 옵션 |
| R2 | **Lit Protocol v8 SDK + Naga 메인넷** 운영 중. 유료($LITKEY)이며 PKP 발급·요청마다 과금 | 탈중앙 키 관리가 필요한 3단계에서 유력. MVP는 벤더 종속 없이 설계 |
| R3 | **BSA(Blockchain Secure Authentication)**: ITU DFS Security Lab 샌드박스를 통해 Android/iOS/Web SDK 제공. Client Key 신청(MS Forms) 필요, 공개 GitHub 없음. 국내 SIG ONE(씨아이지원)이 X.1284/X.1286 표준 주도 | BSA는 **어댑터**로 통합. SDK 확보 전에는 패스키(WebAuthn) 어댑터로 동일 인터페이스 구현 |
| R4 | **ITU-T X.1284 (2025-04)**: OTAK(일회용 인증키) 기반 인증 프레임워크 AFOTAK. 하이브리드 체인, 요청마다 OTAK 생성·폐기 | 자체 OTAK 어댑터 구현 시 이 표준을 참조 규격으로 삼는다 |
| R5 | **Tauri 2**: Windows/macOS/Linux 파일 연결(file association) 공식 지원, `RunEvent::Opened` 로 열린 파일 경로 수신 | 데스크톱 Agent 프레임워크로 채택 |
| R6 | **Windows Hello를 브라우저 없이** 사용: `webauthn.dll`(Win10+) 네이티브 API, `windows-rs` 바인딩, `webauthn-rs`(SUSE 보안감사 통과) 서버측 검증 | 데스크톱 Agent가 직접 패스키 서명 가능 |
| R7 | **ERC-4337/7579 + 패스키**: Pimlico `permissionless.js`(viem 기반), Kernel/Safe/Nexus 계정, RIP-7212 P-256 프리컴파일(Base/OP Stack Pectra 이후) | 소유자 온체인 계정 = 패스키 서명 스마트 계정. Base(L2) 우선 |
| R8 | **HPKE(RFC 9180)**: `hpke-rs`(cryspen) + RustCrypto 백엔드, X25519 + AES-GCM/ChaCha20 | DEK 봉투 암호화 표준 프리미티브 |
| R9 | **age/rage**: 검증된 파일 암호화 포맷·Rust 라이브러리, 플러그인 구조 | 컨테이너 포맷 설계 참조. 직접 채택보다는 스트림 암호화 설계 차용 |
| R10 | **Windows 미니필터 투명 암호화**: EaseFilter SDK(상용, GitHub 예제 공개), Fasoo OpenOS-DRM(오픈 프로젝트) | 3단계 "저장 시 강제 재암호화"의 커널 레벨 옵션 |
| R11 | **HF 스마트컨트랙트 감사 리소스**: `qtum/Qwen3-Coder-30B-A3B-Audit`, `AbijithwearsHUGGIES/codebert-smart-contract-vuln`, `mwritescode/slither-audited-smart-contracts`, `darkknight25/Smart_Contract_Vulnerability_Dataset` 등 | CI에 정적 분석(Slither) + LLM 감사 단계 구성 |

---

## 1. 인증 (Authentication) — 패스워드리스 승인

### 1.1 BSA (Blockchain Secure Authentication)

| 항목 | 내용 |
|---|---|
| 제공처 | SIG ONE(국내, 표준 주도) / FNSV·FNS(M) (ITU DFS 샌드박스 제공) |
| 표준 | ITU-T X.1284, X.1286, TTAK.KO-12.0411, CC EAL2 |
| SDK | Android Native, iOS, Web. 샌드박스 Authenticator 앱(APK/App Store) |
| 획득 절차 | ITU DFS 랩 페이지에서 Client Key 신청 → SDK 가이드·FCM 설정 가이드 수령 |
| 흐름 | 온보딩 → 기기 등록 → 인증 요청(푸시) → 생체 인증 → 결과 콜백 |
| 링크 | https://www.itu.int/en/ITU-T/dfs/seclab/sar/Pages/bsa.aspx , https://www.sigone.net/ |
| 라이선스 | 상용/비공개. 계약 필요 |
| 평가 | ★★★★☆ 표준 부합·마케팅 가치 높음 / 공개 저장소 없음, 벤더 종속 |
| 적용 | `AuthProvider` 트레이트의 `BsaProvider` 구현. Web SDK → Tauri WebView 또는 모바일 승인 앱에 통합 |

### 1.2 WebAuthn / 패스키 (BSA 대체·병행 어댑터)

| 프로젝트 | 언어 | 역할 | 라이선스 | 링크 |
|---|---|---|---|---|
| kanidm/webauthn-rs | Rust | RP(서버) 측 등록/인증 검증. SUSE 보안감사 통과 | MPL-2.0 | https://github.com/kanidm/webauthn-rs |
| 1Password/passkey-rs | Rust | WebAuthn L3 + CTAP2 클라이언트 프레임워크 | MIT/Apache | https://github.com/1Password/passkey-rs |
| keyroost-winwebauthn | Rust | Windows `webauthn.dll` 래퍼 (Windows Hello 직접 호출) | 확인 필요 | https://docs.rs/keyroost-winwebauthn |
| windows-rs `WebAuthNAuthenticatorMakeCredential` | Rust | 공식 Win32 바인딩 | MIT | https://microsoft.github.io/windows-docs-rs/ |
| MichaelGrafnetter/webauthn-interop | .NET | 데스크톱 앱에서 webauthn.dll 사용 레퍼런스 | MIT | https://github.com/MichaelGrafnetter/webauthn-interop |
| MasterKale/SimpleWebAuthn | TS | 브라우저/Node RP. ML-DSA(PQC) 패스키 지원 | MIT | https://github.com/MasterKale/SimpleWebAuthn |
| yackermann/awesome-webauthn | - | 큐레이션 목록 | - | https://github.com/yackermann/awesome-webauthn |

- **Windows Hello 제약**: `webauthn.dll`은 외부 키 관리(키 내보내기)를 지원하지 않음 → 패스키는 **승인 서명 전용**, 파일 키(DEK) 봉인은 별도 키(§2)로 분리한다.
- **macOS**: `LocalAuthentication` + Secure Enclave(`SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`). **Linux**: FIDO2 보안키(libfido2) 또는 TPM2.

### 1.3 자체 OTAK 어댑터 (X.1284 참조 구현)
- BSA SDK가 없는 환경에서 "매 요청 일회용 키 + 분산 검증 + 원장 기록" 흐름을 재현하는 경량 구현.
- 참고: ITU-T X.1284 본문 https://www.itu.int/rec/T-REC-X.1284/en
- 구성: 기기 등록 크리덴셜(랜덤화) → 요청별 OTAK 파생(HKDF) → Relay + 체인 이벤트로 검증 → 즉시 폐기.

---

## 2. 암호화 프리미티브 및 파일 컨테이너

| 프로젝트 | 언어 | 역할 | 라이선스 | 링크 |
|---|---|---|---|---|
| RustCrypto (aes-gcm, chacha20poly1305, hkdf, sha2, x25519-dalek, ed25519-dalek) | Rust | AEAD, KDF, 서명 | MIT/Apache | https://github.com/RustCrypto |
| cryspen/hpke-rs (+ hpke-rs-rust-crypto) **≥ 0.6** (0.5 이하 RUSTSEC-2026-0069~0072) | Rust | RFC 9180 HPKE 봉투 암호화(DEK → 수신자 공개키) | MPL-2.0 | https://github.com/cryspen/hpke-rs |
| str4d/rage (`age` crate) | Rust | 스트림 암호화·수신자 플러그인 포맷 참조 | MIT/Apache | https://github.com/str4d/rage |
| libsodium / sodiumoxide | C/Rust | sealed box, secretstream 대안 | ISC | https://github.com/jedisct1/libsodium |
| zeroize, secrecy | Rust | 메모리 내 키 자료 제로화 | MIT/Apache | https://github.com/RustCrypto/utils |
| keyring (3.x) | Rust | OS 자격 증명 저장소(Windows Credential Manager/DPAPI, macOS Keychain, Secret Service) — `zbacs-auth::store` (Z-1.A.3) | MIT/Apache | https://github.com/open-source-cooperative/keyring-rs |
| microsoft/windows-rs (`windows` 0.58) | Rust | webauthn.dll·CNG(NCrypt) FFI — Windows Hello·TPM 기기 키 (Z-1.A.2/A.7) | MIT/Apache | https://github.com/microsoft/windows-rs |
| RustCrypto p256 (ecdsa), sha3 (Keccak-256) | Rust | 소유자 승인 서명 P-256 검증·low-s 정규화, keyId 해시 (`zbacs-auth`, Z-1.A.1) | MIT/Apache | https://github.com/RustCrypto/elliptic-curves, https://github.com/RustCrypto/hashes |
| hide-protocol/hide | Rust | X25519+ML-KEM-768 하이브리드 PQC 파일 암호화 실험(미감사) | 확인 필요 | https://github.com/hide-protocol/hide |

**설계 결정(초안, ADR-0002 참조)**
- 파일 본문: XChaCha20-Poly1305 청크 스트림(64KiB 청크, 청크 인덱스 AAD) — 대용량·부분 복호화 대응.
- DEK 봉투: HPKE Base mode, X25519 + ChaCha20-Poly1305. 소유자 봉투 + 수신자 봉투(승인 시 추가).
- 컨테이너: 매직 `ZBACS`, 버전, CBOR 헤더(정책·소유자 계정·파일 커밋·버전 체인), 서명(Ed25519), 본문 청크.

---

## 3. 데스크톱 Agent 및 자체 실행

| 프로젝트 | 역할 | 라이선스 | 링크 | 비고 |
|---|---|---|---|---|
| tauri-apps/tauri (v2) | Rust 코어 + WebView UI, 파일 연결, 트레이, 자동 업데이트 | MIT/Apache | https://v2.tauri.app/ | `bundle.fileAssociations` 로 `.zbacs` 연결, `RunEvent::Opened` |
| tauri-plugin-single-instance, -updater, -notification, -autostart | Tauri 플러그인 | MIT/Apache | https://github.com/tauri-apps/plugins-workspace | |
| NSIS (Tauri 번들러) | Windows 설치기, 파일 연결 레지스트리 | zlib | https://nsis.sourceforge.io/ | |
| notify (crate) | 파일 변경 감시(저장 이벤트) | CC0/Artistic | https://github.com/notify-rs/notify | |
| sysinfo (crate) | 열람 앱 프로세스 종료 감지 | MIT | https://github.com/GuillaumeGomez/sysinfo | |
| WinFsp / Dokan / cryptfs 계열 | 사용자 모드 가상 드라이브(평문을 디스크에 쓰지 않는 옵션) | GPLv3+예외 / MIT | https://github.com/winfsp/winfsp , https://github.com/dokan-dev/dokany | 2단계 옵션 |
| EaseFilterSDK/mini-filter-driver-framework, Auto-File-Encrypt-with-DRM | 커널 미니필터 투명 암호화 (상용 SDK, 예제 공개) | 상용 | https://github.com/EaseFilterSDK | 3단계 |
| Fasoo-OpenProject/OpenOS-DRM | 국내 DRM 벤더 오픈 프로젝트 | 확인 필요 | https://github.com/Fasoo-OpenProject/OpenOS-DRM | 벤치마크 |
| Windows DPAPI / `windows-rs` Credential Manager | 기기 키 보호 | MIT | | 로컬 키 저장 |
| keyring (crate) | 크로스플랫폼 OS 키체인 | MIT/Apache | https://github.com/hwchen/keyring-rs | |

**자체 실행 래퍼(Windows) 전략**
- 방식 A(권장): `.zbacs` + 설치된 Agent(파일 연결). 최초 1회 설치 필요.
- 방식 B: `zbacs-stub.exe`(수백 KB, 코드 서명) 뒤에 컨테이너를 덧붙인 단일 `.exe`. 실행 시 Agent 설치 여부 확인 → 없으면 다운로드·설치 안내 → 컨테이너를 Agent로 전달. AV/SmartScreen 오탐 대응으로 **EV 코드 서명** 필수.
- 방식 C(3단계): 미니필터 드라이버로 확장자 무관 투명 암호화.

---

## 4. 블록체인 / 계정 추상화 / 서명

| 프로젝트 | 역할 | 라이선스 | 링크 |
|---|---|---|---|
| foundry-rs/foundry | Solidity 빌드·테스트·퍼징·Anvil 로컬체인 | MIT/Apache | https://github.com/foundry-rs/foundry |
| OpenZeppelin/openzeppelin-contracts (v5) | AccessControl, EIP712, ECDSA, UUPS 프록시, TimelockController | MIT | https://github.com/OpenZeppelin/openzeppelin-contracts |
| eth-infinitism/account-abstraction | ERC-4337 EntryPoint 레퍼런스 | GPL-3.0 | https://github.com/eth-infinitism/account-abstraction |
| pimlicolabs/permissionless.js | 번들러/페이마스터/스마트계정 TS 클라이언트(viem). 0.4.1 `toKernelSmartAccount` WebAuthn 소유자 지원 확인, 단 `usePrecompiled=false` 하드코딩 | MIT | https://github.com/pimlicolabs/permissionless.js |
| zerodevapp/kernel | ERC-7579 모듈러 계정(가장 많이 배포). v3.1 + WebAuthn 검증기 `0x7ab1…9e69` Base Sepolia 배포 확인, 스파이크 통과 | MIT | https://github.com/zerodevapp/kernel |
| rhinestonewtf/core-modules (Passkeys Validator) | 패스키(WebAuthn) 검증 모듈 | MIT/GPL 확인 | https://github.com/rhinestonewtf/core-modules |
| exactly/webauthn-owner-plugin | ERC-6900 secp256r1 서명 검증 플러그인 | 확인 필요 | https://github.com/exactly/webauthn-owner-plugin |
| daimo-eth/p256-verifier, FreshCryptoLib | Solidity P-256 검증기(RIP-7212 미지원 체인 폴백) | MIT | https://github.com/daimo-eth/p256-verifier |
| wevm/viem, ox | TS EVM 클라이언트, EIP-712, WebAuthn 유틸 | MIT | https://github.com/wevm/viem |
| alloy-rs/alloy | Rust EVM 클라이언트(Agent가 체인 조회·서명) | MIT/Apache | https://github.com/alloy-rs/alloy |
| Base / Optimism / Arbitrum | L2 배포 대상. P256VERIFY(`0x…0100`) Base Sepolia·메인넷·OP Sepolia 활성 실측(2026-09-19, OR-2) | - | https://docs.base.org |
| Hyperledger Besu / Anvil | 프라이빗·로컬 체인 옵션 | Apache-2.0 | https://github.com/hyperledger/besu |

**컨트랙트 설계 초안** (specs/approval_protocol.md 참조)
- `FileRegistry`: fileId(커밋 해시) → owner account, 최신 버전 해시, 상태.
- `AccessPolicy`: 승인 티켓 검증(EIP-712 `AccessGrant`), nonce, 만료, 회수.
- `AuditLog`: 이벤트 전용(Requested / Granted / Denied / Opened / Sealed / Revoked). 개인정보 없음.

---

## 5. 프록시 재암호화 / 임계값 접근 제어 (Phase 3)

| 프로젝트 | 상태(2026-09) | 역할 | 라이선스 | 링크 |
|---|---|---|---|---|
| nucypher/rust-umbral (`umbral-pre`) | 조직 비활성, 코드 사용 가능. Python/WASM 바인딩 | Umbral TPRE 알고리즘 라이브러리 | GPL-3.0 (확인 필요) | https://github.com/nucypher/rust-umbral |
| nucypher/pyUmbral | 아카이브성. 참조 구현 | 학습·테스트 벡터 | GPL-3.0 | https://github.com/nucypher/pyUmbral |
| nucypher/taco-web | 유지보수 중단, WEDF 재출범 대기 | TACo 클라이언트 | GPL-3.0 | https://github.com/nucypher/taco-web |
| LIT-Protocol/js-sdk (v8, Naga) | 활성, 유료 | 분산 키(PKP), Lit Actions, ACC 기반 복호화 | MIT | https://github.com/LIT-Protocol/js-sdk |
| miker83z/umbral-rs | 개인 프로젝트 | 대안 Rust 구현 | 확인 필요 | https://github.com/miker83z/umbral-rs |
| sourcenetwork/orbis-go | 활성 여부 확인 | 분산 비밀 관리 엔진 | Apache-2.0 | https://github.com/sourcenetwork/orbis-go |
| taoxinyi/Proxy-Re-encryption-Demo | 교육용 | PRE 개념 데모 | 확인 필요 | https://github.com/taoxinyi/Proxy-Re-encryption-Demo |

**결정 방향(ADR-0004)**: MVP는 소유자 온라인 승인이 전제이므로 PRE 불필요. Phase 3 "소유자 오프라인 정책 위임"에 한해 (a) 자체 Guardian 노드 + `umbral-pre`, (b) Lit v8 중 택일. GPL 라이선스 영향 검토 필수.

---

## 6. 영지식 증명 / 프라이버시 (Phase 3)

| 프로젝트 | 역할 | 라이선스 | 링크 |
|---|---|---|---|
| iden3/circom + snarkjs | 회로 설계, Groth16/PLONK 증명 | GPL-3.0 | https://github.com/iden3/circom |
| semaphore-protocol/semaphore | 익명 그룹 멤버십 증명(요청자가 "허가 그룹 구성원"임을 증명) | MIT | https://github.com/semaphore-protocol/semaphore |
| noir-lang/noir | Rust 스타일 ZK DSL, Aztec | MIT/Apache | https://github.com/noir-lang/noir |
| privacy-scaling-explorations/zk-kit | ZK 유틸리티 | MIT | https://github.com/privacy-scaling-explorations/zk-kit |
| SanjayUG/ZKPass-Passwordless-Authentication-with-Zero-Knowledge-Proofs | 패스워드리스 ZK 인증 참조 | 확인 필요 | https://github.com/SanjayUG/ZKPass-Passwordless-Authentication-with-Zero-Knowledge-Proofs |
| iden3 (Polygon ID) | 검증 가능 자격증명 | AGPL/MIT 혼합 | https://github.com/iden3 |

**적용 후보**: (1) 온체인 감사 로그에 요청자 신원 대신 Semaphore 그룹 증명 기록, (2) 파일 커밋 = `H(fileHash || salt)` 로 파일 지문 은닉, (3) 소유자 계정 ↔ 실제 신원 분리.

---

## 7. 메시징 / 릴레이 / 전송

| 프로젝트 | 역할 | 라이선스 | 링크 |
|---|---|---|---|
| Firebase Cloud Messaging / APNs | 승인 푸시 (BSA SDK도 FCM 사용) | 상용 무료 | |
| ntfy.sh (binwiederhier/ntfy) | 셀프호스팅 푸시 대안 | Apache-2.0/GPL | https://github.com/binwiederhier/ntfy |
| NATS / nats-server | Relay 메시지 버스 | Apache-2.0 | https://github.com/nats-io/nats-server |
| axum + tokio | Relay 서버(Rust) | MIT | https://github.com/tokio-rs/axum |
| libp2p / rust-libp2p | P2P 직접 전송(2단계) | MIT | https://github.com/libp2p/rust-libp2p |
| webrtc-rs | 브라우저·데스크톱 P2P 터널 | MIT/Apache | https://github.com/webrtc-rs/webrtc |
| IPFS (kubo), web3.storage | 암호화 파일 분산 저장(선택) | MIT/Apache | https://github.com/ipfs/kubo |
| lenny-mo/IPFSdatasharing | IPFS + 접근제어 참조 | 확인 필요 | https://github.com/lenny-mo/IPFSdatasharing |

---

## 8. AI 기반 스마트 컨트랙트 감사 (Hugging Face)

| 리소스 | 유형 | 용도 | 링크 |
|---|---|---|---|
| qtum/Qwen3-Coder-30B-A3B-Audit | MoE 코드 LLM(감사 파인튜닝) | PR 단위 취약점 리포트 생성 | https://huggingface.co/qtum/Qwen3-Coder-30B-A3B-Audit |
| AbijithwearsHUGGIES/codebert-smart-contract-vuln | CodeBERT 분류기(재진입/오버플로/타임스탬프/delegatecall) | 경량 게이트 | https://huggingface.co/AbijithwearsHUGGIES/codebert-smart-contract-vuln |
| xj210/solidity_vulnerability_audit_dataset | 9만+ 취약/패치 쌍 | 파인튜닝·레퍼런스 | https://huggingface.co/datasets/xj210/solidity_vulnerability_audit_dataset |
| samscrack/solidity-audit-cot | CoT 프롬프트 데이터 | 감사 프롬프트 설계 | https://huggingface.co/datasets/samscrack/solidity-audit-cot |
| mwritescode/slither-audited-smart-contracts | Slither 라벨 데이터 | 정적 분석 기준선 | https://huggingface.co/datasets/mwritescode/slither-audited-smart-contracts |
| darkknight25/Smart_Contract_Vulnerability_Dataset | 15개 카테고리 2,000건 | 회귀 테스트 | https://huggingface.co/datasets/darkknight25/Smart_Contract_Vulnerability_Dataset |
| crytic/slither, crytic/echidna, a16z/halmos | 정적 분석 / 퍼저 / 심볼릭 | CI 필수 게이트 | https://github.com/crytic/slither |

**CI 파이프라인 초안**: `forge test` → `slither` → `echidna`(핵심 불변식) → HF 모델 감사 리포트(자동 코멘트) → 인간 리뷰. AI 결과는 **게이트가 아닌 리뷰 보조**로 취급(오탐 관리).

---

## 9. 대안 및 경쟁 솔루션 벤치마크

| 솔루션 | 방식 | Z-BACS 대비 |
|---|---|---|
| Fasoo Enterprise DRM, MarkAny | 커널 드라이버 + 중앙 정책 서버 | 기업 내부 특화, 조직 간 전달·개인 사용 불가, 비밀번호/AD 의존 |
| Microsoft Purview Information Protection (AIP) | Office 통합 RMS | MS 생태계 종속, 실시간 소유자 승인 없음 |
| age / 7-Zip AES | 정적 암호화 | 키 전달 문제, 회수·감사 불가 |
| Google Drive 권한 | 클라우드 중앙 통제 | 파일이 클라우드에 상주, 로컬 파일 아님 |
| Lit Protocol 기반 dApp | 탈중앙 ACC | 온체인 조건 기반, "소유자 실시간 승인" UX 없음 |

---

## 10. 라이선스 리스크 표

| 구성요소 | 라이선스 | 리스크 | 대응 |
|---|---|---|---|
| umbral-pre / pyUmbral / taco-web | GPL-3.0 | 배포 바이너리 전염 | 별도 프로세스(Guardian 노드)로 격리, 또는 Lit 선택 |
| circom | GPL-3.0 | 회로 컴파일러만 GPL, 산출물 무관 | 빌드 도구로만 사용 |
| WinFsp | GPLv3 + FLOSS 예외 | 상용 배포 시 상용 라이선스 필요 | Dokan(MIT) 우선 검토 |
| eth-infinitism/account-abstraction | GPL-3.0 | 온체인 배포된 EntryPoint 사용은 무관 | 코드 포함 금지, 주소 참조만 |
| EaseFilter SDK | 상용 | 비용 | 3단계에서 검토 |
| BSA SDK | 상용 계약 | 벤더 종속 | 어댑터 패턴으로 격리 |

---

## 11. 라이브러리화 대상 (Z-BACS 자체 패키지)

| 패키지 | 언어 | 내용 |
|---|---|---|
| `zbacs-core` | Rust | 컨테이너 포맷, 청크 AEAD, HPKE 봉투, 정책 구조체, 서명 |
| `zbacs-auth` | Rust | `AuthProvider` 트레이트 + `PasskeyProvider`(Win/mac/Linux) + `BsaProvider` + `OtakProvider` |
| `zbacs-chain` | Rust(alloy) / TS(viem) | 컨트랙트 ABI 바인딩, EIP-712 타입, 이벤트 구독 |
| `zbacs-agent` | Rust + Tauri 2 | 데스크톱 Agent, 세션 관리, 보호 작업공간, 재봉인 |
| `zbacs-relay` | Rust(axum) | 무신뢰 릴레이, 푸시 연동 |
| `zbacs-contracts` | Solidity(Foundry) | FileRegistry / AccessPolicy / AuditLog |
| `zbacs-approve` | TS(React Native 또는 Tauri mobile) | 소유자 승인 앱 |
| `zbacs-stub` | Rust(no_std 지향) | Windows 자체실행 래퍼 |
| `zbacs-guardian` | Rust | Phase 3 PRE 노드 |

각 패키지의 상세 인터페이스는 [architecture.md](architecture.md) 참조.

---

## 12. 후속 조사 항목 (Open Research)

| ID | 항목 | 담당 단계 |
|---|---|---|
| OR-1 ◐ | BSA 샌드박스 Client Key 신청 및 Web SDK 실제 API 확인 — 절차·받아올 규격 정리 완료, **사용자 신청 대기**([research/bsa_sdk_notes.md](research/bsa_sdk_notes.md)) | Phase 0 |
| OR-2 ✅ | Base 메인넷/세폴리아 RIP-7212 프리컴파일 활성 여부 실측 — 2026-09-19 활성 확인, 3,885 gas. [research/aa_passkey_spike.md](research/aa_passkey_spike.md) | Phase 0 |
| OR-3 | `keyroost-winwebauthn` vs `windows-rs` 직접 호출 안정성 비교 | Phase 0 |
| OR-4 | Windows SmartScreen/Defender 오탐 최소화를 위한 EV 코드서명 비용·절차 | Phase 1 |
| OR-5 | umbral-pre GPL 격리 아키텍처 vs Lit v8 비용 비교 | Phase 3 |
| OR-6 | WEDF TACo 재출범 일정 추적 | Phase 3 |
| OR-7 | Semaphore v4 온체인 검증 가스 비용(Base) | Phase 3 |
| OR-8 | Dokan vs WinFsp 가상 드라이브로 평문 디스크 기록 제거 가능성 | Phase 2 |

---

## 참고 링크 (원문 보고서 인용 포함)
- SIG ONE: https://www.sigone.net/en
- ITU-T X.1284: https://www.itu.int/rec/T-REC-X.1284/en
- BSA 개발자 리소스(ITU DFS Lab): https://www.itu.int/en/ITU-T/dfs/seclab/sar/Pages/bsa.aspx
- Lit v8 릴리스: https://spark.litprotocol.com/new-release-naga-dev-and-sdk-v8/
- TACo 문서: https://docs.taco.build/
- Tauri 2 설정: https://v2.tauri.app/reference/config/
- Pimlico 계정 비교: https://docs.pimlico.io/guides/how-to/accounts/comparison
- EIP-712: https://eips.ethereum.org/EIPS/eip-712
- Windows Hello in webauthn-rs: https://fy.blackhats.net.au/blog/2020-08-24-windows-hello-in-webauthn-rs/
- EaseFilter 투명 암호화: https://www.easefilter.com/kb/transparent-file-encryption-filter-driver-sdk.htm
