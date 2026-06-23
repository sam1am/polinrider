#!/usr/bin/env bash
# Safely remove PolinRider VS Code / fake-font repo injection (git rm only — never executes payloads).
set -euo pipefail
ROOT="${1:-.}"
cd "$ROOT"
[ -d .git ] || { echo "Not a git repo: $ROOT" >&2; exit 1; }

echo "PolinRider repo cleanup in $(pwd) (git rm only; no node/VS Code execution)"

# Build-config files commonly targeted by the EtherHiding config-injection vector
# (payload appended after the legit code, plus an injected `createRequire` preamble
# so `require` exists in ESM context). Keep in sync with check-polinrider-*.sh BUILD_CFG_GLOB.
BUILD_CFGS='tailwind.config.js tailwind.config.cjs tailwind.config.mjs tailwind.config.ts
vite.config.js vite.config.cjs vite.config.mjs vite.config.ts
postcss.config.js postcss.config.cjs postcss.config.mjs
next.config.js next.config.cjs next.config.mjs next.config.ts
nuxt.config.js nuxt.config.ts svelte.config.js astro.config.mjs
webpack.config.js webpack.config.cjs rollup.config.js rollup.config.mjs'

# Payload signatures (both known variants). A file matching ANY of these in a
# build-config context has appended malware; we strip it in place (never execute).
SIG_RE="rmcej%otb%|Cot%3t=shtP|global\\['!'\\]='8-1638-2'|_\\\$_1e42|MDy"

# strip_config_payload <file>: remove the injected createRequire preamble and the
# trailing obfuscated payload, preserving the original legitimate config. The payload
# always starts by assigning to a JS global (global['…']=…) appended after the real
# code — so we truncate from the first such assignment to EOF. A .polinrider-bak copy
# is left next to the file for review.
strip_config_payload() {
  local f="$1"
  cp "$f" "$f.polinrider-bak"
  perl -0777 -i -pe '
    # 1. Cut the appended payload: from the first global[..]= assignment to EOF.
    s/\s*\bglobal\s*\[\s*.[^]]*.\s*\]\s*=.*\z//s;
    # 2. Remove the injected ESM->CJS shim the payload relies on.
    s/^[ \t]*import[ \t]*\{[ \t]*createRequire[ \t]*\}[ \t]*from[ \t]*["\x27]module["\x27];?[ \t]*\r?\n//m;
    s/^[ \t]*const[ \t]+require[ \t]*=[ \t]*createRequire\([ \t]*import\.meta\.url[ \t]*\);?[ \t]*\r?\n//m;
    # 3. Tidy: trim leading blank lines, collapse blank runs, single trailing newline.
    s/\A(?:[ \t]*\r?\n)+//;
    s/(\r?\n){3,}/\n\n/g;
    s/\s*\z/\n/;
  ' "$f"
}

removed=0
if [ -d .vscode ]; then
  git rm -r .vscode
  removed=1
  echo "  removed .vscode/"
fi
if [ -d public/fonts ]; then
  git rm -r public/fonts
  removed=1
  echo "  removed public/fonts/"
fi
if [ -f .gitignore ]; then
  before=$(wc -l < .gitignore | tr -d ' ')
  grep -v -E '^(temp_auto_push\.bat|temp_interactive_push\.bat|\.gitignore)$' .gitignore > .gitignore.tmp || true
  mv .gitignore.tmp .gitignore
  after=$(wc -l < .gitignore | tr -d ' ')
  if [ "$before" != "$after" ]; then
    git add .gitignore
    removed=1
    echo "  cleaned .gitignore (PolinRider propagation artifacts)"
  fi
fi

# Config-injection vector: strip appended payload from build-config files in place.
# BUILD_CFGS is whitespace-separated; rely on word-splitting (filenames have no spaces).
for cfg in $BUILD_CFGS; do
  [ -f "$cfg" ] || continue
  if grep -qE "$SIG_RE" "$cfg" 2>/dev/null; then
    strip_config_payload "$cfg"
    if grep -qE "$SIG_RE" "$cfg" 2>/dev/null; then
      echo "  WARNING: payload signature still present in $cfg after strip — inspect $cfg.polinrider-bak manually" >&2
    else
      git add "$cfg"
      removed=1
      # The .polinrider-bak still contains the LIVE payload — make sure it can never
      # be accidentally committed (e.g. by a later `git add -A`).
      if ! grep -qxF '*.polinrider-bak' .gitignore 2>/dev/null; then
        printf '*.polinrider-bak\n' >> .gitignore
        git add .gitignore
      fi
      echo "  cleaned $cfg (stripped appended payload + createRequire shim; backup at $cfg.polinrider-bak)"
    fi
  fi
done

if [ "$removed" -eq 0 ]; then
  echo "Nothing to remove (no .vscode/, public/fonts/, gitignore, or config-payload artifacts found)."
  exit 0
fi
echo "Staged. Review with: git status && git diff --cached"
echo "Commit when ready. Do NOT open this repo in VS Code until merged."
