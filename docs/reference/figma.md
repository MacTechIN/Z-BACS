# Figma 디자인 가이드 참조

| 항목 | 값 |
|---|---|
| 디자인 가이드 파일 URL | (사용자 제공 예정) |
| 파일 키 | (URL의 `/design/<fileKey>/` 부분) |
| 주요 페이지 | 토큰(색·타이포·간격) / 컴포넌트 / Agent 화면 / 승인 앱 화면 / 설치·스텁 화면 |
| 토큰 생성 위치 | `apps/agent/src/design/tokens.ts`, `apps/approve/src/design/tokens.ts` |
| Code Connect | `figma.config.json` (예정) |

## 사용 규칙
1. UI 작업 시작 시 이 파일의 URL로 `get_metadata` → 대상 프레임 → `get_design_context`.
2. 변수 변경은 Figma에서 먼저, 코드 토큰은 재생성.
3. 스크린샷 비교(`get_screenshot`)를 PR에 첨부.
