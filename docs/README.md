# Z-BACS 문서 인덱스

> 개발 시 **항상** 이 인덱스를 시작점으로 참조한다. (루트 `CLAUDE.md` 참조)

| 문서 | 내용 | 갱신 시점 |
|---|---|---|
| [ux_principles.md](ux_principles.md) | **최상위 개발 원칙**: 아무것도 몰라도 쓸 수 있는 UX, 설계 규칙, UX DoD | 원칙 변경 시 |
| [project_definition.md](project_definition.md) | 프로젝트 정의서: 목표, 시나리오, FR/NFR, 신뢰 모델, MVP DoD | 범위 변경 시 |
| [research.md](research.md) | 기술 검토·리소스 카탈로그 (GitHub / Hugging Face / 표준 / 벤더) | 리소스 발견 시 |
| [research/](research/) | 수집 코드·스니펫·벤치마크 | 수시 |
| [dev_plan.md](dev_plan.md) | 개발 계획서: Phase 0~3 마이크로 태스크, 위협 매핑, 마일스톤 | 스프린트마다 |
| [architecture.md](architecture.md) | 시스템 아키텍처, 패키지 구조, 키 계층, 스택 | 설계 변경 시 |
| [threat_model.md](threat_model.md) | 자산·공격자·위협 T01~T20·완화·잔여 위험 | 기능 추가 시 |
| [specs/container_format.md](specs/container_format.md) | `.zbacs` 컨테이너 포맷 v1 | 포맷 변경 시 |
| [specs/approval_protocol.md](specs/approval_protocol.md) | AccessRequest / AccessGrant(EIP-712) / GrantMsg / Revoke | 프로토콜 변경 시 |
| [specs/permission_model.md](specs/permission_model.md) | Deny / ReadOnly / Edit 및 조건 | 권한 추가 시 |
| [reference/figma.md](reference/figma.md) | Figma 디자인 가이드 링크·파일 키·사용 규칙 (UI의 단일 원본) | 파일 변경 시 |
| [adr/](adr/README.md) | 아키텍처 결정 기록 | 결정 시 |
| [dev_guidelines.md](dev_guidelines.md) | 보안 코딩·스타일·테스트·릴리스 규칙 | 필요 시 |
| [glossary.md](glossary.md) | 용어집 | 필요 시 |
| [../블록체인 패스워드리스 파일 인증 분석.md](../블록체인%20패스워드리스%20파일%20인증%20분석.md) | 원본 타당성 분석 보고서 | 읽기 전용 |

## 읽는 순서 (신규 참여자)
1. ux_principles → 2. project_definition → 3. architecture → 3. threat_model → 4. specs/* → 5. dev_plan → 6. research → 7. adr
