#!/usr/bin/env bash
# PolinRider / Beavertail / TasksJacker comprehensive scanner — Linux
# IOCs from https://github.com/OpenSourceMalware/PolinRider
#
# Usage:
#   bash check-polinrider-linux.sh                          # quick (default paths)
#   bash check-polinrider-linux.sh --repos ~/code           # also scan repos under a path
#   sudo bash check-polinrider-linux.sh --full              # adds journalctl + system-wide checks
#
# Exits 0 if clean, non-zero with hit count.

set -u
RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; DIM=$'\033[2m'; BLU=$'\033[34m'; RST=$'\033[0m'
hits=0; warns=0
section() { printf "\n${BLU}═══ %s ═══${RST}\n" "$1"; }
sub()     { printf "\n${DIM}── %s ──${RST}\n" "$1"; }
hit()     { printf "  ${RED}⚠ HIT:${RST} %s\n" "$1"; hits=$((hits+1)); }
warn()    { printf "  ${YEL}? REVIEW:${RST} %s\n" "$1"; warns=$((warns+1)); }
ok()      { printf "  ${GRN}✓${RST} %s\n" "$1"; }
note()    { printf "  ${DIM}·${RST} %s\n" "$1"; }

REPO_ROOTS=("$HOME/code" "$HOME/src" "$HOME/projects" "$HOME/dev" "$HOME/git" "$HOME/repos" "$HOME/Documents/GitHub")
FULL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --repos) shift; REPO_ROOTS=("$1"); shift ;;
    --full)  FULL=1; shift ;;
    *) shift ;;
  esac
done

# ═════════════════════ IOC CONSTANTS ═════════════════════
V1_MARKER='rmcej%otb%'
V1_GLOBAL="global\\['!'\\]='8-1638-2'"
V2_MARKER='Cot%3t=shtP'
TRON_ADDRS='TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP|TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG'
BSC_TX='0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e|0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3'
C2_IP='166\.88\.54\.158'
C2_VERCEL='260120\.vercel\.app|default-configuration\.vercel\.app|vscode-settings-bootstrap\.vercel\.app|vscode-settings-config\.vercel\.app|vscode-bootstrapper\.vercel\.app|vscode-load-config\.vercel\.app'
C2_RPC='api\.trongrid\.io|api\.telegram\.org|bsc-dataseed\.binance\.org|bsc-rpc\.publicnode\.com'
PROPAGATION='temp_auto_push\.bat|temp_interactive_push\.bat'
EVIL_NPM='tailwindcss-style-animate'
EVIL_UUIDS='e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9'
NPM_DIR_RE='[a-zA-Z0-9._-]+\$[a-zA-Z0-9._-]+_[0-9]{6}_[0-9]{6}'
EXFIL_ZIP_RE='\$[a-zA-Z0-9._-]+_[0-9]{6}_[0-9]{6}(_2)?#[a-f0-9]{6,}\.zip$'

section "PART A — REPO PAYLOAD SCAN"

sub "A1. JS payload signatures in tracked source files"
found=0
for root in "${REPO_ROOTS[@]}"; do
  [ -d "$root" ] || continue
  while IFS= read -r f; do hit "$f"; found=1
  done < <(find "$root" -maxdepth 8 -type f \
    \( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" -o -name "*.ts" -o -name "*.tsx" -o -name "*.jsx" -o -name "*.vue" -o -name "*.svelte" \) \
    -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/venv/*" -not -path "*/.venv/*" \
    -not -path "*/dist/*" -not -path "*/build/*" -not -path "*/.next/*" -not -path "*/.nuxt/*" \
    2>/dev/null | xargs grep -lE "$V1_MARKER|$V2_MARKER|$V1_GLOBAL" 2>/dev/null | head -50)
done
[ "$found" = 0 ] && ok "no payload signatures"

sub "A2. Fake font/asset payloads (wrong magic + signature)"
found=0
for root in "${REPO_ROOTS[@]}"; do
  [ -d "$root" ] || continue
  while IFS= read -r f; do
    magic=$(head -c 4 "$f" 2>/dev/null | xxd -p)
    case "$f" in
      *.woff2) want='774f4632' ;;
      *.woff)  want='774f4646' ;;
      *.ttf)   want='00010000|74727565|4f54544f' ;;
      *) want='' ;;
    esac
    [ -z "$want" ] && continue
    if ! echo "$magic" | grep -qE "^($want)$"; then
      if grep -qE "$V1_MARKER|$V2_MARKER|$V1_GLOBAL|require|process\.|child_process" "$f" 2>/dev/null; then
        hit "$f (magic=$magic, looks like JS not font)"; found=1
      fi
    fi
  done < <(find "$root" -maxdepth 8 -type f \( -name "*.woff2" -o -name "*.woff" -o -name "*.ttf" \) \
           -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/venv/*" 2>/dev/null)
done
[ "$found" = 0 ] && ok "no fake font files"

sub "A3. Malicious .vscode/tasks.json with auto-execute (TasksJacker)"
found=0
for root in "${REPO_ROOTS[@]}"; do
  [ -d "$root" ] || continue
  while IFS= read -r f; do
    if grep -qE "runOn[\"' ]*:[\"' ]*folderOpen" "$f" 2>/dev/null; then
      if grep -qE "node[[:space:]]+.*\.(woff|ttf|eot)|curl[^|]*\| *(bash|sh|zsh)|wget[^|]*\| *(bash|sh|zsh)|$C2_VERCEL|$C2_RPC|$EVIL_UUIDS" "$f" 2>/dev/null; then
        hit "$f"; found=1
      else
        warn "$f has runOn:folderOpen — manual review"
      fi
    fi
  done < <(find "$root" -maxdepth 8 -path "*/.vscode/tasks.json" -not -path "*/node_modules/*" 2>/dev/null)
done
[ "$found" = 0 ] && [ "$warns" = 0 ] && ok "no folderOpen auto-tasks"

sub "A4. .vscode/settings.json with task.allowAutomaticTasks:true"
found=0
for root in "${REPO_ROOTS[@]}"; do
  [ -d "$root" ] || continue
  while IFS= read -r f; do
    grep -qE '"task\.allowAutomaticTasks"[[:space:]]*:[[:space:]]*true' "$f" 2>/dev/null && \
      { warn "$f sets allowAutomaticTasks:true"; found=1; }
  done < <(find "$root" -maxdepth 8 -path "*/.vscode/settings.json" -not -path "*/node_modules/*" 2>/dev/null)
done
[ "$found" = 0 ] && ok "no allowAutomaticTasks:true"

sub "A5. Propagation script names referenced"
found=0
for root in "${REPO_ROOTS[@]}"; do
  [ -d "$root" ] || continue
  while IFS= read -r f; do hit "$f"; found=1
  done < <(grep -rlI \
            --include=".gitignore" --include="*.md" --include="*.json" --include="*.yml" --include="*.yaml" \
            --include="*.sh" --include="*.bat" --include="*.cmd" --include="*.ps1" --include="*.txt" \
            --include="*.js" --include="*.mjs" --include="*.cjs" --include="*.ts" \
            --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=venv --exclude-dir=.next \
            --exclude-dir=dist --exclude-dir=build --exclude-dir=.nuxt \
            -E "$PROPAGATION" "$root" 2>/dev/null | head -50)
done
[ "$found" = 0 ] && ok "no propagation refs"

sub "A6. Malicious npm package '$EVIL_NPM' in package.json"
found=0
for root in "${REPO_ROOTS[@]}"; do
  [ -d "$root" ] || continue
  while IFS= read -r f; do hit "$f"; found=1
  done < <(find "$root" -maxdepth 6 -name package.json -not -path "*/node_modules/*" 2>/dev/null \
            | xargs grep -l "$EVIL_NPM" 2>/dev/null)
done
[ "$found" = 0 ] && ok "no malicious npm dep"

sub "A7. Weaponized take-home UUIDs"
found=0
for root in "${REPO_ROOTS[@]}"; do
  [ -d "$root" ] || continue
  while IFS= read -r f; do hit "$f"; found=1
  done < <(grep -rlE "$EVIL_UUIDS" --include="*.json" --exclude-dir=node_modules --exclude-dir=.git "$root" 2>/dev/null | head -20)
done
[ "$found" = 0 ] && ok "no take-home UUIDs"

sub "A8. Git history: TZ-mismatch spoofing fingerprint"
found=0
for root in "${REPO_ROOTS[@]}"; do
  [ -d "$root" ] || continue
  while IFS= read -r repo; do
    cd "$repo" 2>/dev/null || continue
    sus=$(git log --all --format='%h|%ai|%ci|%ae|%ce|%s' 2>/dev/null | awk -F'|' '
      { atz=substr($2,length($2)-4); ctz=substr($3,length($3)-4);
        if (atz != ctz && $4 == $5) print $1" "atz"/"ctz" "$4" "substr($6,1,50) }' | head -3)
    if [ -n "$sus" ]; then warn "$repo:"; echo "$sus" | sed 's/^/      /'; found=1; fi
  done < <(find "$root" -maxdepth 4 -name .git -type d 2>/dev/null | sed 's/\/.git$//')
done
[ "$found" = 0 ] && ok "no TZ-mismatch commits"

section "PART B — HOST EXECUTION-EVIDENCE SCAN"

sub "B1. Beavertail staging directories"
found=0
for base in "$HOME/.npm" "/tmp" "/var/tmp" "$HOME/.cache" "$HOME/.local/share" "/dev/shm"; do
  [ -d "$base" ] || continue
  while IFS= read -r d; do hit "$d"; found=1
  done < <(find "$base" -maxdepth 3 -type d 2>/dev/null | grep -E "/$NPM_DIR_RE\$" | head -10)
done
[ "$found" = 0 ] && ok "no staging directories"

sub "B2. Staged file names"
found=0
while IFS= read -r f; do hit "$f"; found=1
done < <(find "$HOME/.npm" "/tmp" "/var/tmp" "$HOME/.cache" "$HOME/.local/share" "/dev/shm" \
   \( -name "_credentials.json" -o -name "_sysenv.json" -o -name "_sysenv.env" -o -name "_info.json" \) \
   2>/dev/null | head -20)
[ "$found" = 0 ] && ok "no staged JSONs"

sub "B3. Exfil archive pattern"
found=0
while IFS= read -r z; do hit "$z"; found=1
done < <(find "$HOME" "/tmp" "/var/tmp" "/dev/shm" -maxdepth 6 -type f -name "*.zip" 2>/dev/null | grep -E "$EXFIL_ZIP_RE" | head -10)
[ "$found" = 0 ] && ok "no exfil archives"

sub "B4. Lock files"
found=0
for lf in /tmp/tmp7A863DD1.tmp "$HOME/.cache/tmp7A863DD1.tmp" /var/tmp/tmp7A863DD1.tmp /dev/shm/tmp7A863DD1.tmp; do
  [ -e "$lf" ] && { hit "$lf"; found=1; }
done
[ "$found" = 0 ] && ok "no lock files"

sub "B5. systemd user services referencing IOCs"
found=0
for dir in "$HOME/.config/systemd/user" "/etc/systemd/system" "/etc/systemd/user"; do
  [ -d "$dir" ] || continue
  while IFS= read -r unit; do
    if grep -qiE "(node[[:space:]]+.*\.(woff|ttf|eot)|node[[:space:]]+.*fonts/|$C2_RPC|$C2_VERCEL|$C2_IP|$TRON_ADDRS|/tmp/[a-f0-9]+\.(js|py))" "$unit" 2>/dev/null; then
      hit "$unit"; found=1
    fi
  done < <(find "$dir" -name "*.service" -o -name "*.timer" 2>/dev/null)
done
[ "$found" = 0 ] && ok "no systemd units reference IOCs"

sub "B6. cron jobs referencing IOCs"
found=0
for f in /etc/crontab /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.weekly/* /etc/cron.monthly/* "$HOME/.crontab"; do
  [ -e "$f" ] || continue
  if grep -qiE "(node[[:space:]]+.*\.(woff|ttf|eot)|$C2_RPC|$C2_VERCEL|$C2_IP|$TRON_ADDRS)" "$f" 2>/dev/null; then
    hit "$f"; found=1
  fi
done
crontab -l 2>/dev/null | grep -qiE "(node.*\.(woff|ttf|eot)|$C2_RPC|$C2_IP)" && \
  { hit "user crontab"; found=1; }
[ "$found" = 0 ] && ok "no cron jobs reference IOCs"

sub "B7. Shell rc files referencing IOCs"
found=0
for f in "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshrc" "$HOME/.zshenv" "$HOME/.zprofile" \
         "$HOME/.config/fish/config.fish" /etc/profile /etc/bash.bashrc; do
  [ -f "$f" ] || continue
  if grep -qiE "(node[[:space:]]+.*\.(woff|ttf|eot)|$C2_RPC|$C2_IP|$TRON_ADDRS|$V1_MARKER|$V2_MARKER)" "$f" 2>/dev/null; then
    hit "$f references IOC"; found=1
  fi
done
[ "$found" = 0 ] && ok "no shell rc IOCs"

sub "B8. XDG autostart entries"
found=0
for dir in "$HOME/.config/autostart" /etc/xdg/autostart; do
  [ -d "$dir" ] || continue
  while IFS= read -r f; do
    if grep -qiE "(node[[:space:]]+.*\.(woff|ttf|eot)|$C2_RPC|$C2_VERCEL|$C2_IP)" "$f" 2>/dev/null; then
      hit "$f"; found=1
    fi
  done < <(find "$dir" -name "*.desktop" 2>/dev/null)
done
[ "$found" = 0 ] && ok "no autostart entries reference IOCs"

sub "B9. Dropper-shaped files in /tmp /dev/shm /var/tmp ~/.cache (last 180d)"
found=0
while IFS= read -r f; do
  if grep -qE "$C2_RPC|$C2_IP|$TRON_ADDRS|$BSC_TX|portalocker|tmp7A863DD1|$V1_MARKER|$V2_MARKER" "$f" 2>/dev/null; then
    hit "$f"; found=1
  fi
done < <(find "/tmp" "/var/tmp" "/dev/shm" "$HOME/.cache" -maxdepth 4 -type f \
            \( -name "*.py" -o -name "*.js" -o -name "*.sh" \) -mtime -180 2>/dev/null | head -500)
[ "$found" = 0 ] && ok "no droppers matching IOC content"

sub "B10. Running processes referencing IOCs"
ps_hits=$(ps auxww 2>/dev/null | grep -iE "node[[:space:]]+.*\.(woff|woff2|ttf|eot)|node[[:space:]]+.*fonts/|$C2_RPC|$C2_IP|$C2_VERCEL" | grep -v grep | grep -v check-polinrider)
if [ -n "$ps_hits" ]; then hit "process matches:"; echo "$ps_hits" | sed 's/^/    /'
else ok "no running processes match"; fi

sub "B11. Open network connections to known C2"
if command -v ss >/dev/null; then
  net_hits=$(ss -tunap 2>/dev/null | grep -iE "$C2_IP")
  ip_hits=$(ss -tunap 2>/dev/null | head -200)
else
  net_hits=$(netstat -tunap 2>/dev/null | grep -iE "$C2_IP")
fi
if [ -n "${net_hits:-}" ]; then hit "C2 connection match:"; echo "$net_hits" | sed 's/^/    /'
else ok "no live C2 connections"; fi

sub "B12. DNS / Resolver"
# NOTE: actively probing IOC domains causes resolution and pollutes results.
# Check /etc/resolv.conf and nscd cache passively only.
if command -v nscd >/dev/null 2>&1; then
  nscd -g 2>/dev/null | head -20 | sed 's/^/    /'
fi
note "for actual resolved-host evidence, run with --full and check journalctl/auditd"

sub "B13. Shell history search"
hist_hits=$(grep -hE "$C2_RPC|$C2_IP|$C2_VERCEL|$TRON_ADDRS|$V1_MARKER|$V2_MARKER|$PROPAGATION|fa-solid-400\.woff2" \
   "$HOME/.zsh_history" "$HOME/.bash_history" "$HOME/.history" "$HOME/.local/share/fish/fish_history" 2>/dev/null | head -10)
if [ -n "$hist_hits" ]; then hit "shell history:"; echo "$hist_hits" | sed 's/^/    /'
else ok "shell history clean"; fi

sub "B14. Browser credential DB last-modified"
db_paths=(
  "$HOME/.config/google-chrome/Default/Login Data"
  "$HOME/.config/google-chrome/Default/Cookies"
  "$HOME/.config/BraveSoftware/Brave-Browser/Default/Login Data"
  "$HOME/.config/microsoft-edge/Default/Login Data"
  "$HOME/.config/vivaldi/Default/Login Data"
)
for p in "${db_paths[@]}"; do
  [ -f "$p" ] && note "$p  ($(stat -c '%y' "$p" 2>/dev/null))"
done
ff="$HOME/.mozilla/firefox"
[ -d "$ff" ] && find "$ff" -name "logins.json" 2>/dev/null | head -5 | while read -r f; do note "$f  ($(stat -c '%y' "$f"))"; done

sub "B15. Crypto wallet directories"
for w in \
  "$HOME/.config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" \
  "$HOME/.config/BraveSoftware/Brave-Browser/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" \
  "$HOME/.config/Exodus" \
  "$HOME/.electrum" \
  "$HOME/.bitcoin" \
  "$HOME/.ethereum"; do
  [ -e "$w" ] && note "wallet found: $w  ($(stat -c '%y' "$w" 2>/dev/null))"
done

if [ "$FULL" = 1 ]; then
  section "PART C — DEEP SYSTEM-LOG SCAN (sudo recommended)"
  if [ "$(id -u)" = "0" ] && command -v journalctl >/dev/null; then
    sub "C1. journalctl search (last 14 days)"
    journalctl --since "14 days ago" 2>/dev/null | grep -iE "$C2_RPC|$C2_IP|$C2_VERCEL|$TRON_ADDRS|fa-solid-400\.woff2" | head -50 | sed 's/^/    /'
    sub "C2. All processes (full)"
    ps -ef 2>/dev/null | grep -iE "node.*\.(woff|ttf)|node.*fonts/|$C2_IP|$C2_RPC" | grep -v grep | grep -v check-polinrider | sed 's/^/    /'
    sub "C3. iptables/nftables logs"
    if command -v iptables >/dev/null; then iptables -L -n 2>/dev/null | grep -E "$C2_IP" | head -10 | sed 's/^/    /'; fi
    if command -v nft >/dev/null; then nft list ruleset 2>/dev/null | grep -E "$C2_IP" | head -10 | sed 's/^/    /'; fi
    sub "C4. /var/log search"
    grep -rEi "$C2_IP|trongrid|fa-solid-400\.woff2|$V1_MARKER" /var/log/*.log /var/log/syslog* /var/log/messages* 2>/dev/null | head -20 | sed 's/^/    /'
  else
    note "skip — re-run with: sudo bash $0 --full"
  fi
fi

section "SUMMARY"
if [ "$hits" = 0 ] && [ "$warns" = 0 ]; then
  printf "  ${GRN}No IOC matches and no items requiring review.${RST}\n"
elif [ "$hits" = 0 ]; then
  printf "  ${YEL}%d item(s) flagged for review.${RST}\n" "$warns"
else
  printf "  ${RED}%d HIT(s)${RST}, ${YEL}%d for review${RST}.\n" "$hits" "$warns"
fi
printf "  ${DIM}A clean scan does not prove uninfection — Beavertail variants self-clean.${RST}\n"
exit "$hits"
