# 배포 주소

`script/Deploy.s.sol`이 `<chainId>.json`을 여기에 쓴다(Z-1.H.4). Agent는 이 파일을 읽는다 — `zbacs_chain::Deployment::from_file`.

- 실제 네트워크(Base Sepolia 84532, Base 8453)의 파일은 **커밋한다.** 다른 사람이 같은 배포를 찾아야 한다.
- 로컬 체인(31337)의 파일은 anvil을 껐다 켤 때마다 바뀌므로 `.gitignore` 대상이다.

파일에는 프록시 주소와 구현 주소가 모두 들어 있다. **말을 걸어야 하는 쪽은 프록시**다(`registry`, `policy`). 구현(`registryImplementation`, `policyImplementation`)은 블록 탐색기에서 소스를 확인할 때 쓴다.
