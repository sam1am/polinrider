#!/usr/bin/env bash
# SIXSIXNINE forensic audit — read-only.
# Run as the daily user on SIXSIXNINE (the one who uses gh / git / VS Code).
# Paste the entire output back to the analyst.

set +e
export LC_ALL=C
sep() { printf '\n=== %s ===\n' "$*"; }

sep "0. Identity / time / boot"
hostname
whoami; id
date -u; date
timedatectl 2>/dev/null | grep -iE 'zone|ntp|synchronized|rtc'
uptime
who -b 2>/dev/null
last -n 15 reboot 2>/dev/null | head -20

sep "1. Recent user logins (last 30) — look for unfamiliar tty/host"
last -n 30 2>/dev/null | head -30

sep "2. gh CLI presence + token state"
command -v gh && gh --version
ls -la ~/.config/gh/ 2>/dev/null
# Show hosts.yml but redact the actual token string
if [ -f ~/.config/gh/hosts.yml ]; then
  sed -E 's/(oauth_token|token): .+/\1: <REDACTED but PRESENT>/' ~/.config/gh/hosts.yml
fi
ls -la ~/.cache/gh ~/.local/share/gh 2>/dev/null

sep "3. git global config + credential helpers"
cat ~/.gitconfig 2>/dev/null
git config --global --list 2>/dev/null
echo "--- credential helpers ---"
git config --global --get-all credential.helper 2>/dev/null
echo "--- core.hooksPath / init.templatedir ---"
git config --global --get core.hooksPath 2>/dev/null
git config --global --get init.templatedir 2>/dev/null
ls -la ~/.git-template ~/.gittemplate 2>/dev/null
echo "--- ~/.git-credentials (should not exist) ---"
ls -la ~/.git-credentials 2>/dev/null || echo "(absent — good)"

sep "4. PATH shadowing of git / gh"
which -a git
which -a gh
type git 2>/dev/null
type gh 2>/dev/null
echo "--- shell function shims for git/gh ---"
typeset -f git 2>/dev/null
typeset -f gh 2>/dev/null
echo "--- LD_PRELOAD ---"
env | grep -i LD_PRELOAD
cat /etc/ld.so.preload 2>/dev/null

sep "5. Shell rc files (look for sourcing of weird things, TZ exports, gh wrappers)"
for f in ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zshenv ~/.zprofile ~/.bashrc.d/* /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh; do
  [ -f "$f" ] || continue
  echo "--- $f ---"
  # Filter for likely-suspect patterns
  grep -nE 'TZ=|GIT_|GH_|github|octokit|preload|alias git|alias gh|function git|function gh|/.config/gh|tmp_auto_push|temp_auto_push|_\$_1e42|rmcej' "$f" 2>/dev/null | head -20
  # Also flag any source/. lines that load external files
  grep -nE '^[[:space:]]*(\.|source)[[:space:]]+[^[:space:]]+' "$f" 2>/dev/null | head -10
done

sep "6. systemd user units (custom only)"
ls -la ~/.config/systemd/user/ 2>/dev/null
systemctl --user list-units --type=service --no-pager 2>/dev/null | grep -vE '^(UNIT|LOAD|ACTIVE|SUB|JOB|listed|To)' | head -40
systemctl --user list-timers --no-pager 2>/dev/null | head -20

sep "7. cron / anacron / at"
crontab -l 2>/dev/null
ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ 2>/dev/null
ls -la /var/spool/cron/crontabs/ 2>/dev/null
ls -la /etc/anacrontab 2>/dev/null
atq 2>/dev/null

sep "8. Autostart entries (XDG, desktop)"
ls -la ~/.config/autostart/ 2>/dev/null
ls -la /etc/xdg/autostart/ 2>/dev/null | head -20

sep "9. Snap services + packages"
snap version 2>/dev/null
snap list 2>/dev/null
snap services 2>/dev/null
snap connections 2>/dev/null | grep -vE '^(:|Plug|core:|snapd-control)' | head -20

sep "10. Flatpak apps"
flatpak list --app 2>/dev/null

sep "11. apt packages installed in the last 60 days"
zgrep -h 'install ' /var/log/dpkg.log /var/log/dpkg.log.* 2>/dev/null \
  | awk -v cutoff="$(date -d '60 days ago' '+%Y-%m-%d')" '$1 >= cutoff' \
  | awk '{print $1, $2, $4}' \
  | tail -60

sep "12. Globally-installed npm packages"
command -v npm && npm ls -g --depth=0 2>/dev/null

sep "13. pnpm / yarn global"
command -v pnpm && pnpm list -g --depth=0 2>/dev/null
command -v yarn && yarn global list 2>/dev/null

sep "14. pipx / pip --user installed"
command -v pipx && pipx list --short 2>/dev/null
command -v pip && pip list --user 2>/dev/null

sep "15. VS Code / VSCodium extensions"
for cli in code codium code-insiders cursor; do
  command -v "$cli" >/dev/null && { echo "--- $cli ---"; "$cli" --list-extensions --show-versions 2>/dev/null; }
done
ls ~/.vscode/extensions 2>/dev/null | head -100
ls ~/.vscode-oss/extensions 2>/dev/null | head -100
ls ~/.cursor/extensions 2>/dev/null | head -50

sep "16. Firefox / Librewolf — extensions and recent profile activity"
for prof_root in ~/.mozilla/firefox ~/.var/app/org.mozilla.firefox/.mozilla/firefox ~/.librewolf; do
  [ -d "$prof_root" ] || continue
  echo "--- $prof_root ---"
  ls -la "$prof_root" 2>/dev/null
  for p in "$prof_root"/*.default* "$prof_root"/*.default-release; do
    [ -d "$p" ] || continue
    echo "  profile: $p"
    ls -la "$p"/extensions/ 2>/dev/null | head -30
    if [ -f "$p/extensions.json" ]; then
      python3 -c "
import json
try:
    d = json.load(open('$p/extensions.json'))
    for a in d.get('addons', []):
        print('   ', a.get('id'), '/', a.get('defaultLocale',{}).get('name','?'), '/', a.get('updateDate',0))
except Exception as e:
    print('  (parse err:', e, ')')
" 2>/dev/null | head -50
    fi
  done
done

sep "17. Docker / podman state"
command -v docker && docker ps -a --format 'table {{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}' 2>/dev/null
command -v podman && podman ps -a 2>/dev/null

sep "18. Currently-running processes (long-lived, sorted by start)"
ps -eo pid,etime,user,command --sort=-etime 2>/dev/null | head -40

sep "19. Outbound network — anything currently talking to api.github.com / github / npm"
ss -tnp 2>/dev/null | grep -iE 'api.github|github|registry.npmjs|raw.githubusercontent|gist' | head -20
lsof -i -n -P 2>/dev/null | grep -iE 'github|npm' | head -20

sep "20. Files modified in 24h window around the May 14 attack"
find /home -xdev -type f -newermt '2026-05-13 21:00' -not -newermt '2026-05-14 03:00' 2>/dev/null \
  | grep -vE '/\.(cache|mozilla|config/google-chrome|local/share/Trash|local/state)/' \
  | grep -vE '\.(log|cache|sqlite|sqlite-wal|sqlite-journal|swp)$' \
  | head -50

sep "21. Files modified in 24h window around the April 4 attack"
find /home -xdev -type f -newermt '2026-04-04 09:00' -not -newermt '2026-04-04 15:00' 2>/dev/null \
  | grep -vE '/\.(cache|mozilla|config/google-chrome|local/share/Trash|local/state)/' \
  | grep -vE '\.(log|cache|sqlite|sqlite-wal|sqlite-journal|swp)$' \
  | head -50

sep "22. Search HOME for code that uses octokit / git via API"
grep -rlsI --include='*.js' --include='*.ts' --include='*.cjs' --include='*.mjs' --include='*.py' \
  --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.cache --exclude-dir=.mozilla \
  -E '@octokit/|octokit\.rest|isomorphic-git|simple-git|nodegit|git/data/commits|git\.createCommit' \
  ~ 2>/dev/null | head -30

sep "23. Search HOME for the malware signatures"
grep -rlsI --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.cache --exclude-dir=.mozilla \
  -e 'rmcej%otb%' -e '_$_1e42' -e 'temp_auto_push' -e 'temp_interactive_push' \
  ~ 2>/dev/null | head -30

sep "24. Search HOME for anything that hardcodes Pacific TZ or manipulates GIT_COMMITTER_DATE"
grep -rlsI --include='*.js' --include='*.ts' --include='*.cjs' --include='*.mjs' --include='*.py' --include='*.sh' --include='*.bash' --include='*.zsh' \
  --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.cache --exclude-dir=.mozilla \
  -e 'America/Los_Angeles' -e 'US/Pacific' -e 'PST8PDT' -e 'GIT_COMMITTER_DATE' -e 'GIT_AUTHOR_DATE' \
  ~ 2>/dev/null | head -30

sep "25. Recently-modified executables in $HOME (last 90 days)"
find ~ -xdev -type f -perm -u+x -newermt '90 days ago' 2>/dev/null \
  | grep -vE '/(node_modules|\.git|\.cache|\.mozilla|\.local/share/Trash)/' \
  | grep -vE '\.(log|md|txt)$' \
  | head -40

sep "26. AI agent state directories (pi / cline / aider / continue / claude / etc.)"
for d in ~/.pi ~/.config/pi ~/.aider ~/.config/aider ~/.continue ~/.config/continue ~/.claude ~/.config/claude ~/.cline ~/.config/cline ~/.config/cursor ~/.config/windsurf; do
  [ -e "$d" ] && { echo "--- $d ---"; ls -la "$d" 2>/dev/null | head -10; }
done

sep "DONE"
