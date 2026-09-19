# Figma 디자인 가이드 참조

| 항목 | 값 |
|---|---|
| 디자인 가이드 파일 URL | (Figma URL 미제공. 현재 원본은 파일 스냅샷: `docs/design/dgo-vault/`, `docs/design/foundations-olive/`) |
| 파일 키 | (URL의 `/design/<fileKey>/` 부분) |
| 주요 페이지 | 토큰(색·타이포·간격) / 컴포넌트 / Agent 화면 / 승인 앱 화면 / 설치·스텁 화면 |
| 토큰 생성 위치 | `apps/agent/src/design/tokens.ts`, `apps/approve/src/design/tokens.ts` |
| Code Connect | `figma.config.json` (예정) |

## 현재 상태 (2026-09-19)
- Figma 링크 대신 디자인 파일(PNG/PDF)을 받아 `docs/design/`에 보관하고, `packages/design-tokens/`로 토큰화했다. 골격 가이드: [../design/ui_guideline.md](../design/ui_guideline.md).
- Figma URL이 제공되면 이 파일에 기록하고 `get_variable_defs`로 근사값(`approx.`)을 교체한다.

## 사용 규칙
1. UI 작업 시작 시 이 파일의 URL로 `get_metadata` → 대상 프레임 → `get_design_context`.
2. 변수 변경은 Figma에서 먼저, 코드 토큰은 재생성.
3. 스크린샷 비교(`get_screenshot`)를 PR에 첨부.
