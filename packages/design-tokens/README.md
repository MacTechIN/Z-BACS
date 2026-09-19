# @zbacs/design-tokens

UI의 단일 원본은 `docs/design/`의 디자인 소스이며, 이 패키지는 그 값을 코드로 옮긴 것이다. 값을 바꾸려면 디자인 소스(Figma/디자인 파일)를 먼저 바꾸고 `tokens.json` → `tokens.css`를 갱신한다.

| 파일 | 내용 |
|---|---|
| `tokens.json` | W3C Design Tokens 형식. 테마 `vault`(기본, D-GO Vault UI 키트), `olive`(대체, Foundations A안) |
| `tokens.css` | CSS 커스텀 프로퍼티. `:root`(vault light), 다크 모드, `[data-theme="olive"]` |

사용: Tauri/React 앱에서 `import "@zbacs/design-tokens/tokens.css"` 후 `var(--zb-primary)` 등으로 참조. 색·간격·폰트를 컴포넌트 안에 하드코딩하지 않는다.

`approx.` 표시가 있는 값은 이미지에서 눈으로 읽은 근사치다. Figma 원본이 연결되면 `get_variable_defs`로 정확한 값을 받아 교체한다 (Z-1.U.0).
