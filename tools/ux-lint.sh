#!/usr/bin/env bash
# Z-1.U.2 — the UX rules that can be checked mechanically.
#
#   1. U-5  no forbidden vocabulary in anything the person reads
#   2. U-6  no text input in the onboarding / sealing / approval / opening flows
#   3. rule 8  the UI uses design tokens, not colours and sizes of its own
#
# What counts as "anything the person reads": a line containing Hangul. Project rule 7 puts
# every comment and identifier in English, so Hangul in a UI source file is a sentence for a
# person. That is what makes a one-file grep honest here instead of a guess.
#
# The word list lives in docs/design/ui_strings.md, so the terminology and its enforcement
# cannot drift apart.
set -euo pipefail

cd "$(dirname "$0")/.."

DICT="docs/design/ui_strings.md"
TOKENS="packages/design-tokens/tokens.css"
fail=0

note() { printf '  %s\n' "$*"; }
bad() {
  printf 'FAIL %s\n' "$*"
  fail=1
}

# Files the person's words can live in. `git ls-files` keeps generated copies (ui/tokens.css)
# out of it, since those are gitignored.
mapfile -t UI_FILES < <(git ls-files 'apps/*/ui/*.html' 'apps/*/ui/*.js' 'apps/*/src-tauri/src/*.rs')
mapfile -t CSS_FILES < <(git ls-files 'apps/*/ui/*.css')

if [ ${#UI_FILES[@]} -eq 0 ]; then
  echo "no UI files yet — nothing to check"
  exit 0
fi

# ---------------------------------------------------------------- 1. vocabulary (U-5)

mapfile -t BANNED < <(
  awk '/ux-lint:banned:start/{on=1;next} /ux-lint:banned:end/{on=0} on' "$DICT" |
    sed -e 's/^```.*$//' -e 's/#.*$//' -e 's/[[:space:]]*$//' | grep -v '^$'
)
if [ ${#BANNED[@]} -eq 0 ]; then
  bad "$DICT has no banned-term block"
fi

echo "checking ${#UI_FILES[@]} UI file(s) against ${#BANNED[@]} forbidden term(s)"
for term in "${BANNED[@]}"; do
  # Only lines that contain Hangul, i.e. lines addressed to a person.
  hits=$(grep -nP '[\x{AC00}-\x{D7A3}\x{3131}-\x{318E}]' "${UI_FILES[@]}" 2>/dev/null |
    grep -iF -- "$term" || true)
  if [ -n "$hits" ]; then
    bad "forbidden term in a user-visible string: $term"
    printf '%s\n' "$hits" | sed 's/^/       /'
  fi
done

# ---------------------------------------------------------------- 2. no text input (U-6)

inputs=$(grep -HnE '<input|<textarea|contenteditable|prompt\(' "${UI_FILES[@]}" || true)
if [ -n "$inputs" ]; then
  bad "the flows must have no text input (U-6)"
  printf '%s\n' "$inputs" | sed 's/^/       /'
fi

# ---------------------------------------------------------------- 3. design tokens (rule 8)

if [ ${#CSS_FILES[@]} -gt 0 ]; then
  defined=$(grep -oE -- '--zb-[a-z0-9-]+[[:space:]]*:' "$TOKENS" | sed 's/[[:space:]]*:$//' | sort -u)
  used=$(grep -ohE -- 'var\(--zb-[a-z0-9-]+' "${CSS_FILES[@]}" | sed 's/^var(//' | sort -u)
  missing=$(comm -23 <(printf '%s\n' "$used") <(printf '%s\n' "$defined"))
  if [ -n "$missing" ]; then
    bad "the UI uses tokens that $TOKENS does not define"
    printf '%s\n' "$missing" | sed 's/^/       /'
  else
    note "$(printf '%s\n' "$used" | grep -c .) token(s) used, all defined"
  fi

  # A literal colour or size in the UI is a value that never came from the design source.
  literals=$(grep -HnE '#[0-9a-fA-F]{3,8}\b|[^-a-z(][0-9]+px' "${CSS_FILES[@]}" |
    grep -vE '^\s*[^:]*:\s*/\*' || true)
  if [ -n "$literals" ]; then
    bad "literal colours or sizes in the UI (CLAUDE.md rule 8) — put them in tokens.json"
    printf '%s\n' "$literals" | sed 's/^/       /'
  fi
fi

# ---------------------------------------------------------------- 4. the UI matches its markup

# A renamed id does not break the build, it blanks a screen in silence. Cheap to check, and the
# failure it prevents is one nobody notices until a person is looking at an empty window.
for js in $(git ls-files 'apps/*/ui/app.js'); do
  html="$(dirname "$js")/index.html"
  [ -f "$html" ] || continue
  have_ids=$(grep -oE 'id="[^"]+"' "$html" | sed -e 's/^id="//' -e 's/"$//' | sort -u)
  have_roles=$(grep -oE 'data-role="[^"]+"' "$html" | sed -e 's/^data-role="//' -e 's/"$//' | sort -u)

  want_ids=$(grep -oE 'getElementById\("[^"]+"' "$js" | sed -e 's/^.*("//' -e 's/"$//')
  # the one templated case: `screen-${name}` for every name in SCREENS
  for name in $(sed -n 's/^const SCREENS = \[\(.*\)\];$/\1/p' "$js" | tr -d '" ' | tr ',' ' '); do
    want_ids="$want_ids screen-$name"
  done
  want_roles=$(grep -oE 'data-role="[^"]+"' "$js" | sed -e 's/^data-role="//' -e 's/"$//')

  for id in $(printf '%s\n' $want_ids | sort -u); do
    printf '%s\n' "$have_ids" | grep -qxF -- "$id" ||
      bad "$js asks for #$id, which $html does not have"
  done
  for role in $(printf '%s\n' $want_roles | sort -u); do
    printf '%s\n' "$have_roles" | grep -qxF -- "$role" ||
      bad "$js asks for [data-role=$role], which $html does not have"
  done
done

# ---------------------------------------------------------------- 5. every error has a sentence (Z-1.U.4)

# The catalogue in the dictionary (§7) is the list of machine values the backend may return.
# Each must have a sentence in app.js, and app.js must not invent values the catalogue does
# not know. The backend side of the same triangle is apps/agent/src-tauri/tests/errors.rs.
catalogue=$(awk '/ux-lint:errors:start/{on=1;next} /ux-lint:errors:end/{on=0} on' "$DICT" |
  grep -oE '^\| `[a-z_]+`' | sed -e 's/^| `//' -e 's/`$//' | sort -u)
if [ -z "$catalogue" ]; then
  bad "$DICT has no error catalogue block (§7)"
fi
for js in $(git ls-files 'apps/*/ui/app.js'); do
  keys=$(awk '/^const [A-Z_]*_PROBLEMS = \{/{on=1;next} on && /^\};/{on=0} on' "$js" |
    grep -oE '^[[:space:]]+[a-z_]+:' | tr -d ' :' | sort -u)
  for id in $catalogue; do
    printf '%s\n' "$keys" | grep -qxF -- "$id" || bad "$js has no sentence for the catalogued error '$id'"
  done
  for id in $keys; do
    printf '%s\n' "$catalogue" | grep -qxF -- "$id" || bad "$js invents an error '$id' that $DICT §7 does not list"
  done
  note "$(printf '%s\n' "$catalogue" | grep -c .) catalogued error(s), all with a sentence"
done

# ---------------------------------------------------------------- result

if [ "$fail" -eq 0 ]; then
  echo "ux-lint: ok"
else
  echo "ux-lint: failed — see docs/design/ui_strings.md"
fi
exit "$fail"
