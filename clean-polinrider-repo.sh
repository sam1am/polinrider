#!/usr/bin/env bash
# Safely remove PolinRider VS Code / fake-font repo injection (git rm only — never executes payloads).
set -euo pipefail
ROOT="${1:-.}"
cd "$ROOT"
[ -d .git ] || { echo "Not a git repo: $ROOT" >&2; exit 1; }

echo "PolinRider repo cleanup in $(pwd) (git rm only; no node/VS Code execution)"

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

if [ "$removed" -eq 0 ]; then
  echo "Nothing to remove (no .vscode/, public/fonts/, or gitignore artifacts found)."
  exit 0
fi
echo "Staged. Review with: git status && git diff --cached"
echo "Commit when ready. Do NOT open this repo in VS Code until merged."
