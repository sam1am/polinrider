#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  canary-sentinel.sh — PolinRider // THREAT SENTINEL                       ║
# ║  A continuous, full-screen sci-fi monitoring console.                     ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# WHAT IT DOES
#   Runs forever in your terminal as a live mission-control dashboard that:
#     • SURVEILS remote GitHub repos for the PolinRider attack signature
#       (force-pushes, pushes/branches/PR-merges by untrusted actors).
#     • SCANS the local machine on an interval for PolinRider / Beavertail /
#       TasksJacker signatures (payload markers, fake fonts, malicious VS Code
#       tasks, C2 endpoints, exfil staging dirs, rogue processes & launch
#       agents, propagation .bat droppers).
#     • Escalates the THREAT LEVEL and throws a screen-filling, blinking,
#       bell-ringing INTRUSION banner the instant anything is detected.
#
#   It reuses the same intel as canary-watch.sh (remote) and
#   check-polinrider-mac.sh (local signatures), unified into one console.
#
# USAGE
#   bash canary-sentinel.sh                 # launch the live TUI
#   bash canary-sentinel.sh --repos ~/code  # scan repos under a custom root
#   bash canary-sentinel.sh --once          # single headless sweep (cron/CI)
#   bash canary-sentinel.sh --demo          # inject a fake hit to see the alarm
#
# KEYS (while running)
#   q  quit       p  pause/resume sweeps     r  remote sweep now
#   l  local scan now     a  acknowledge/clear alert banner
#
# ALERT FAN-OUT (same env vars as canary-watch.sh, all optional)
#   CANARY_NTFY_TOPIC   ntfy.sh push topic        CANARY_DISCORD_URL  webhook
#   CANARY_SLACK_URL    Slack webhook             CANARY_NATIVE=1     desktop
#
# TUNING (env)
#   SENTINEL_REMOTE_INTERVAL   seconds between remote sweeps   (default 300)
#   SENTINEL_LOCAL_INTERVAL    seconds between local scans     (default 120)
#   CANARY_REPOS / CANARY_REPO_FILE / CANARY_TRUSTED_ACTORS    (see below)
#
# REQUIREMENTS:  bash 4+, jq, gh (for remote; auth via `gh auth login`).
#                Local scan works without gh.

set -u
export LC_ALL=C

# ═════════════════════════════════ CONFIG ═════════════════════════════════
CANARY_REPOS_DEFAULT=(
  # PolinRider new-wave targets (May 2026)
  sam1am/cairn sam1am/termux_crt sam1am/anyapk sam1am/inkit
  sam1am/samandnat sam1am/polinrider
  # Older infected targets (HEAD-clean as of cleanup PRs)
  sam1am/Sunshine sam1am/resumaker sam1am/cocofintel sam1am/SageChat
  sam1am/sidekick sam1am/pennyQ
  # Second-wave cleanup set
  sam1am/Ryzen-Master-Commander sam1am/bookmarklets sam1am/cli-viz
  sam1am/inmo_air_3_wiki sam1am/poetroid sam1am/sekrits sam1am/air-canary
  sam1am/saltonsun sam1am/sagenotes-premium sam1am/autonews
  sam1am/worker-whisperx sam1am/jackalope sam1am/voicekeyboard
  sam1am/timeline sam1am/stockbot sam1am/secure-askpass
  sam1am/restorelakebonnevile sam1am/pavegsl sam1am/nbfc-linux
  sam1am/minibook-support sam1am/mini-scraper sam1am/beedaddykb.com
)
CANARY_TRUSTED_ACTORS_DEFAULT=(
  sam1am github-actions[bot] dependabot[bot] renovate[bot]
)

REMOTE_INTERVAL="${SENTINEL_REMOTE_INTERVAL:-300}"
LOCAL_INTERVAL="${SENTINEL_LOCAL_INTERVAL:-120}"
REPO_ROOTS=("$HOME/Documents/GitHub")
MODE="tui"          # tui | once
DEMO=0
NOCOLOR=0

while [ $# -gt 0 ]; do
  case "$1" in
    --repos) shift; REPO_ROOTS=("$1"); shift ;;
    --once)  MODE="once"; shift ;;
    --demo)  DEMO=1; shift ;;
    --no-color) NOCOLOR=1; shift ;;
    --remote-interval) shift; REMOTE_INTERVAL="$1"; shift ;;
    --local-interval)  shift; LOCAL_INTERVAL="$1"; shift ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) shift ;;
  esac
done

# Resolve repo list / trusted actors from env overrides (shared with canary-watch.sh)
if [[ -n "${CANARY_REPO_FILE:-}" && -f "${CANARY_REPO_FILE:-}" ]]; then
  REPOS=(); while IFS= read -r _l; do REPOS+=("$_l"); done < <(grep -vE '^[[:space:]]*(#|$)' "$CANARY_REPO_FILE")
elif [[ -n "${CANARY_REPOS:-}" ]]; then
  read -r -a REPOS <<<"$CANARY_REPOS"
else
  REPOS=("${CANARY_REPOS_DEFAULT[@]}")
fi
if [[ -n "${CANARY_TRUSTED_ACTORS:-}" ]]; then
  read -r -a TRUSTED <<<"$CANARY_TRUSTED_ACTORS"
else
  TRUSTED=("${CANARY_TRUSTED_ACTORS_DEFAULT[@]}")
fi

# ═══════════════════════════ IOC SIGNATURES ═══════════════════════════════
# (kept in lock-step with check-polinrider-mac.sh)
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
ALL_SIG="$V1_MARKER|$V2_MARKER|$V1_GLOBAL|$TRON_ADDRS|$BSC_TX|$C2_IP|$C2_VERCEL"

# ════════════════════════════ RUNTIME STATE DIR ═══════════════════════════
RUN="$(mktemp -d "${TMPDIR:-/tmp}/sentinel.XXXXXX")"
R_STATE="$RUN/remote.state"   ; : >"$R_STATE"
R_META="$RUN/remote.meta"     ; printf 'idle|0|0|\n' >"$R_META"
L_STATE="$RUN/local.state"    ; : >"$L_STATE"
L_META="$RUN/local.meta"      ; printf 'idle|0|0|\n' >"$L_META"
ALERTS="$RUN/alerts.log"      ; : >"$ALERTS"
R_TRIGGER="$RUN/remote.trigger"
L_TRIGGER="$RUN/local.trigger"
SEEN_DIR="$RUN/seen"          ; mkdir -p "$SEEN_DIR"
SIG_DIR="$RUN/sig"            ; mkdir -p "$SIG_DIR"
WORKER_PIDS=()

cleanup() {
  for pid in "${WORKER_PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  if [[ "$MODE" == "tui" ]]; then
    printf '\033[?25h\033[?1049l'   # show cursor, leave alt screen
    stty echo 2>/dev/null
  fi
  rm -rf "$RUN" 2>/dev/null
}
trap cleanup EXIT INT TERM

# ════════════════════════════════ TOOLING ═════════════════════════════════
have() { command -v "$1" >/dev/null 2>&1; }
HAVE_JQ=0; have jq && HAVE_JQ=1
HAVE_GH=0; have gh && HAVE_GH=1
GH_AUTH=0
if [[ "$HAVE_GH" == 1 ]] && gh auth status >/dev/null 2>&1; then GH_AUTH=1; fi
REMOTE_ENABLED=$(( HAVE_GH && GH_AUTH && HAVE_JQ ))

# epoch helper
now() { date +%s; }
ts_to_ms() { # ISO8601 -> epoch ms (GNU or python fallback)
  local t="$1" v
  v=$(date -u -d "$t" +%s%3N 2>/dev/null) && { printf '%s' "$v"; return; }
  python3 -c "import sys,datetime;print(int(datetime.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00')).timestamp()*1000))" "$t" 2>/dev/null
}

is_trusted() { local a="$1" t; for t in "${TRUSTED[@]}"; do [[ "$a" == "$t" ]] && return 0; done; return 1; }

# Append a structured alert event: epoch \t SEV \t SOURCE \t MSG
emit() { printf '%s\t%s\t%s\t%s\n' "$(now)" "$1" "$2" "$3" >>"$ALERTS"; }

# ══════════════════════════ REMOTE SURVEILLANCE WORKER ═════════════════════
remote_check_one() {
  local repo="$1" sf="$SEEN_DIR/${repo//\//__}.last"
  local last=0; [[ -f "$sf" ]] && last=$(cat "$sf" 2>/dev/null || echo 0)
  [[ "$last" =~ ^[0-9]+$ ]] || last=0
  local activity newest=$last code="OK" detail="clean" worst=0

  if ! activity=$(gh api -X GET "repos/$repo/activity" -F per_page=30 2>&1); then
    if echo "$activity" | grep -q '"Not Found"'; then
      printf 'SKIP|%s|private or missing|%s\n' "$repo" "$(now)" >>"$R_STATE.tmp"; return
    fi
    printf 'ERR|%s|api error|%s\n' "$repo" "$(now)" >>"$R_STATE.tmp"; return
  fi

  while IFS=$'\t' read -r t atype actor ref before after; do
    [[ -z "$t" ]] && continue
    local ms; ms=$(ts_to_ms "$t"); [[ "$ms" =~ ^[0-9]+$ ]] || continue
    (( ms > newest )) && newest=$ms
    (( ms <= last )) && continue
    (( last == 0 )) && continue   # baseline first run, don't alert on history
    local d="actor=$actor ref=${ref##*/} ${before:0:7}..${after:0:7}"
    case "$atype" in
      force_push)
        emit CRIT "remote:$repo" "FORCE PUSH — PolinRider attack signature ($d)"
        code="CRIT"; detail="FORCE PUSH by $actor"; worst=2 ;;
      push)
        if ! is_trusted "$actor"; then
          emit WARN "remote:$repo" "push from untrusted actor '$actor' ($d)"
          (( worst<1 )) && { code="WARN"; detail="push by $actor"; worst=1; }
        fi ;;
      branch_creation|branch_deletion|pr_merge)
        if ! is_trusted "$actor"; then
          emit WARN "remote:$repo" "$atype by untrusted actor '$actor' ($d)"
          (( worst<1 )) && { code="WARN"; detail="$atype by $actor"; worst=1; }
        fi ;;
    esac
  done < <(echo "$activity" | jq -r '.[]|[.timestamp,.activity_type,.actor.login,(.ref//""),(.before//""),(.after//"")]|@tsv' 2>/dev/null)

  echo "$newest" >"$sf"
  printf '%s|%s|%s|%s\n' "$code" "$repo" "$detail" "$(now)" >>"$R_STATE.tmp"
}

remote_worker() {
  while :; do
    printf 'running|%s|0|\n' "$(now)" >"$R_META"
    : >"$R_STATE.tmp"
    local i=0 n=${#REPOS[@]}
    for repo in "${REPOS[@]}"; do
      i=$((i+1))
      printf 'running|%s|%s|%s\n' "$(now)" "$((i*100/n))" "$repo" >"$R_META"
      remote_check_one "$repo"
    done
    mv -f "$R_STATE.tmp" "$R_STATE" 2>/dev/null
    local next=$(( $(now) + REMOTE_INTERVAL ))
    printf 'idle|%s|%s|\n' "$(now)" "$next" >"$R_META"
    # interruptible sleep
    while (( $(now) < next )); do
      [[ -f "$R_TRIGGER" ]] && { rm -f "$R_TRIGGER"; break; }
      sleep 1
    done
  done
}

# ════════════════════════════ LOCAL SCAN WORKER ═══════════════════════════
# Each finding category writes:  SEV|label|detail   to L_STATE
# and emits a deduped alert (only on appear / count-increase).
scan_emit() { # cat sev label detail
  local cat="$1" sev="$2" label="$3" detail="$4"
  printf '%s|%s|%s\n' "$sev" "$label" "$detail" >>"$L_STATE.tmp"
  local sigf="$SIG_DIR/$cat" prev=""
  [[ -f "$sigf" ]] && prev=$(cat "$sigf")
  local cur="$sev|$detail"
  if [[ "$sev" != "OK" && "$cur" != "$prev" ]]; then
    emit "$sev" "local:$cat" "$label — $detail"
  fi
  echo "$cur" >"$sigf"
}

local_scan() {
  : >"$L_STATE.tmp"
  local prog=0
  set_prog() { printf 'running|%s|%s|%s\n' "$(now)" "$1" "$2" >"$L_META"; }

  # roots that exist
  local roots=() r
  for r in "${REPO_ROOTS[@]}"; do [[ -d "$r" ]] && roots+=("$r"); done

  # demo injection
  if [[ "$DEMO" == 1 ]]; then
    scan_emit demo CRIT "Payload signature" "DEMO: rmcej%otb% in fake-repo/public/fonts/fa-solid-400.woff2"
  fi

  # 1) Source payload signatures -----------------------------------------
  set_prog 10 "source payload signatures"
  local n=0 f
  if ((${#roots[@]})); then
    while IFS= read -r f; do [[ -n "$f" ]] && n=$((n+1)); done < <(
      grep -rlE "$ALL_SIG" \
        --include='*.js' --include='*.mjs' --include='*.cjs' \
        --include='*.ts' --include='*.tsx' --include='*.jsx' \
        --include='*.vue' --include='*.svelte' --include='*.json' \
        --exclude-dir=node_modules --exclude-dir=.git \
        "${roots[@]}" 2>/dev/null | head -50)
  fi
  if (( n>0 )); then scan_emit src CRIT "Payload signatures" "$n file(s) match V1/V2/C2 markers";
  else scan_emit src OK "Payload signatures" "clear"; fi

  # 2) Fake fonts (fa-solid-400.woff2 that is text / wrong magic) ---------
  set_prog 25 "fake font payloads"
  n=0
  if ((${#roots[@]})); then
    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      local magic; magic=$(xxd -p -l4 "$f" 2>/dev/null)
      if [[ "$magic" != "774f4632" ]]; then
        if grep -qE "$V1_MARKER|$V2_MARKER|$V1_GLOBAL|rmcej|require|child_process" "$f" 2>/dev/null \
           || [[ "$(file -b "$f" 2>/dev/null)" == *text* ]]; then n=$((n+1)); fi
      fi
    done < <(find "${roots[@]}" -maxdepth 7 -name 'fa-solid-400.woff2' -not -path '*/node_modules/*' 2>/dev/null | head -20)
  fi
  if (( n>0 )); then scan_emit font CRIT "Fake font payloads" "$n trojaned fa-solid-400.woff2";
  else scan_emit font OK "Fake font payloads" "clear"; fi

  # 3) Malicious .vscode/tasks.json (folderOpen auto-exec) ---------------
  set_prog 40 "VS Code auto-tasks"
  n=0
  if ((${#roots[@]})); then
    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      if grep -qE "runOn[\"' ]*:[\"' ]*folderOpen" "$f" 2>/dev/null \
         && grep -qE "node[[:space:]]+.*\.(woff|woff2|ttf|eot)|node[[:space:]]+.*fonts/|curl[^|]*\|[[:space:]]*(ba)?sh|$C2_VERCEL|$C2_RPC|$EVIL_UUIDS" "$f" 2>/dev/null; then
        n=$((n+1))
      fi
    done < <(find "${roots[@]}" -maxdepth 7 -path '*/.vscode/tasks.json' -not -path '*/node_modules/*' 2>/dev/null | head -20)
  fi
  if (( n>0 )); then scan_emit task CRIT "VS Code auto-tasks" "$n folderOpen auto-exec task(s)";
  else scan_emit task OK "VS Code auto-tasks" "clear"; fi

  # 4) Propagation .bat droppers -----------------------------------------
  set_prog 55 "propagation droppers"
  n=0
  if ((${#roots[@]})); then
    while IFS= read -r f; do [[ -n "$f" ]] && n=$((n+1)); done < <(
      find "${roots[@]}" -maxdepth 7 \( -name 'temp_auto_push.bat' -o -name 'temp_interactive_push.bat' \) -not -path '*/.git/*' 2>/dev/null | head -20)
  fi
  if (( n>0 )); then scan_emit prop CRIT "Propagation droppers" "$n temp_*_push.bat present";
  else scan_emit prop OK "Propagation droppers" "clear"; fi

  # 5) Malicious npm dependency ------------------------------------------
  set_prog 65 "malicious npm deps"
  n=0
  if ((${#roots[@]})); then
    while IFS= read -r f; do [[ -n "$f" ]] && n=$((n+1)); done < <(
      grep -rl "$EVIL_NPM" --include=package.json --exclude-dir=node_modules "${roots[@]}" 2>/dev/null | head -20)
  fi
  if (( n>0 )); then scan_emit npm CRIT "Malicious npm dep" "$n manifest(s) list $EVIL_NPM";
  else scan_emit npm OK "Malicious npm dep" "clear"; fi

  # 6) Rogue running processes -------------------------------------------
  set_prog 78 "rogue processes"
  local ps_hits
  ps_hits=$(ps auxww 2>/dev/null | grep -iE "node[[:space:]]+.*\.(woff|woff2|ttf|eot)|node[[:space:]]+.*fonts/|$C2_IP|$C2_RPC|$C2_VERCEL" | grep -vE 'grep|check-polinrider|canary-sentinel' | head -10)
  if [[ -n "$ps_hits" ]]; then
    scan_emit proc CRIT "Rogue processes" "$(echo "$ps_hits" | wc -l | tr -d ' ') suspicious node process(es)"
  else scan_emit proc OK "Rogue processes" "clear"; fi

  # 7) Live C2 network connections ---------------------------------------
  set_prog 88 "C2 network links"
  local net_hits=""
  if have lsof; then
    net_hits=$(lsof -i -nP 2>/dev/null | grep -iE "$C2_IP|trongrid|aptoslabs|bsc-dataseed|publicnode" | head -10)
  fi
  if [[ -n "$net_hits" ]]; then
    scan_emit net CRIT "C2 network links" "$(echo "$net_hits" | wc -l | tr -d ' ') live connection(s) to C2"
  else scan_emit net OK "C2 network links" "clear"; fi

  # 8) Rogue launch agents / persistence (macOS) -------------------------
  set_prog 95 "persistence / launch agents"
  n=0
  for d in "$HOME/Library/LaunchAgents" "$HOME/Library/LaunchDaemons" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
    [[ -d "$d" ]] || continue
    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      if grep -qiE "node[[:space:]]+.*\.(woff|woff2|ttf|eot)|node[[:space:]]+.*fonts/|$C2_RPC|$C2_IP|$C2_VERCEL|$TRON_ADDRS" "$f" 2>/dev/null; then n=$((n+1)); fi
    done < <(find "$d" -maxdepth 1 -name '*.plist' 2>/dev/null | head -100)
  done
  if (( n>0 )); then scan_emit persist CRIT "Persistence agents" "$n rogue launch agent/daemon";
  else scan_emit persist OK "Persistence agents" "clear"; fi

  set_prog 100 "complete"
  mv -f "$L_STATE.tmp" "$L_STATE" 2>/dev/null
}

local_worker() {
  while :; do
    local_scan
    local next=$(( $(now) + LOCAL_INTERVAL ))
    printf 'idle|%s|%s|\n' "$(now)" "$next" >"$L_META"
    while (( $(now) < next )); do
      [[ -f "$L_TRIGGER" ]] && { rm -f "$L_TRIGGER"; break; }
      sleep 1
    done
  done
}

# ═══════════════════════════════ HEADLESS (--once) ═════════════════════════
if [[ "$MODE" == "once" ]]; then
  echo "PolinRider Sentinel — single sweep @ $(date -u +%FT%TZ)"
  echo "Local roots: ${REPO_ROOTS[*]}"
  local_scan
  echo; echo "── LOCAL ──"
  while IFS='|' read -r sev label detail; do
    [[ -z "$sev" ]] && continue
    case "$sev" in
      CRIT) printf '  [HIT ] %-22s %s\n' "$label" "$detail" ;;
      WARN) printf '  [WARN] %-22s %s\n' "$label" "$detail" ;;
      *)    printf '  [ ok ] %-22s %s\n' "$label" "$detail" ;;
    esac
  done <"$L_STATE"
  if [[ "$REMOTE_ENABLED" == 1 ]]; then
    echo; echo "── REMOTE (${#REPOS[@]} repos) ──"
    : >"$R_STATE.tmp"
    for repo in "${REPOS[@]}"; do remote_check_one "$repo"; done
    mv -f "$R_STATE.tmp" "$R_STATE"
    awk -F'|' '$1!="OK"&&$1!="SKIP"{print "  ["$1"] "$2" — "$3}' "$R_STATE" || true
    nonok=$(awk -F'|' '$1!="OK"&&$1!="SKIP"' "$R_STATE" | wc -l | tr -d ' ')
    [[ "$nonok" == 0 ]] && echo "  all repos clean"
  else
    echo; echo "── REMOTE ── (disabled: need gh authenticated + jq)"
  fi
  hits=$(grep -cE $'\tCRIT\t' "$ALERTS" 2>/dev/null); hits=${hits:-0}
  echo; echo "Alerts this sweep: $(wc -l <"$ALERTS" | tr -d ' ')  (critical: $hits)"
  exit "$hits"
fi

# ═══════════════════════════════ TUI ENGINE ═══════════════════════════════
# ---- palette --------------------------------------------------------------
if [[ "$NOCOLOR" == 1 || ! -t 1 ]]; then
  FRAME='' FRAMEd='' TITLE='' ACC='' OKc='' WARNc='' CRITc='' DIM='' TXT='' LBL='' B='' RST='' INV=''
else
  cc(){ printf '\033[%sm' "$1"; }
  FRAME=$(cc '38;5;37');  FRAMEd=$(cc '38;5;23'); TITLE=$(cc '1;38;5;51')
  ACC=$(cc '38;5;45');    OKc=$(cc '38;5;46');    WARNc=$(cc '1;38;5;214')
  CRITc=$(cc '1;38;5;196'); DIM=$(cc '38;5;240'); TXT=$(cc '38;5;152')
  LBL=$(cc '38;5;81');    B=$(cc '1');            RST=$(cc 0);  INV=$(cc 7)
fi

SPIN=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
PULSE=('░' '▒' '▓' '█' '▓' '▒')
GL_OK='◉'; GL_WARN='▲'; GL_CRIT='⊗'; GL_PEND='◌'; GL_SKIP='·'; GL_ERR='✕'

# ---- terminal -------------------------------------------------------------
W=80; H=24
get_size(){ W=$(tput cols 2>/dev/null||echo 80); H=$(tput lines 2>/dev/null||echo 24); }
FB=''
flush(){ printf '%s' "$FB"; FB=''; }
at(){ FB+=$'\033['"$1;$2"'H'; }
rep(){ local n=$1 c=$2 o=''; while ((n-->0)); do o+="$c"; done; printf '%s' "$o"; }
# fit string to exactly n display columns. Pads with explicit spaces (NOT printf
# field-width, which counts bytes) so multibyte glyphs align under a UTF-8 locale.
fit(){ local s="$1" n="$2" len
  (( n < 1 )) && return
  if (( ${#s} > n )); then printf '%s…' "${s:0:n-1}"; return; fi
  len=${#s}; printf '%s%*s' "$s" $((n-len)) ''
}
# Switch the rendering process to a UTF-8 locale so ${#s} counts characters
# (display columns) rather than bytes. Workers stay in C for fast binary-safe grep.
set_tui_locale(){
  local cand
  for cand in "${LANG:-}" en_US.UTF-8 C.UTF-8 en_GB.UTF-8; do
    [[ "$cand" == *[Uu][Tt][Ff]* ]] || continue
    if locale -a 2>/dev/null | grep -qix "$cand"; then export LC_ALL="$cand" LANG="$cand"; return 0; fi
  done
  cand=$(locale -a 2>/dev/null | grep -im1 'utf-\{0,1\}8')
  [[ -n "$cand" ]] && export LC_ALL="$cand" LANG="$cand"
}

declare -a FEED=()
ALERT_OFFSET=0
THREAT="NOMINAL"; PREV_THREAT="NOMINAL"
PAUSED=0
ACK=0                 # acknowledged current alert banner
LAST_BELL=0
START=$(now)
SCROLL=0
TICK=0

# ---- alert fan-out (same channels as canary-watch.sh) ---------------------
dispatch(){ local sev="$1" src="$2" msg="$3"
  if [[ -n "${CANARY_NTFY_TOPIC:-}" ]]; then
    local prio=default; [[ "$sev" == CRIT ]] && prio=urgent; [[ "$sev" == WARN ]] && prio=high
    curl -fsS -X POST "https://ntfy.sh/${CANARY_NTFY_TOPIC}" -H "Title: Sentinel: $src" \
      -H "Priority: $prio" -H "Tags: rotating_light" -d "$msg" >/dev/null 2>&1 || true
  fi
  if [[ -n "${CANARY_DISCORD_URL:-}" ]]; then
    curl -fsS -X POST -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg c "[$sev] **$src** — $msg" '{content:$c}')" "$CANARY_DISCORD_URL" >/dev/null 2>&1 || true
  fi
  if [[ -n "${CANARY_SLACK_URL:-}" ]]; then
    curl -fsS -X POST -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg t "[$sev] *$src* — $msg" '{text:$t}')" "$CANARY_SLACK_URL" >/dev/null 2>&1 || true
  fi
  if [[ "${CANARY_NATIVE:-0}" == 1 ]]; then
    if have osascript; then osascript -e "display notification \"$msg\" with title \"⚠ Sentinel: $src\" sound name \"Sosumi\"" 2>/dev/null || true
    elif have notify-send; then notify-send -u critical "Sentinel: $src" "$msg" 2>/dev/null || true; fi
  fi
}

# ---- ingest new alerts; update feed + threat; fan-out ---------------------
ingest(){
  local total; total=$(wc -l <"$ALERTS" 2>/dev/null||echo 0)
  if (( total > ALERT_OFFSET )); then
    local line
    while IFS=$'\t' read -r ep sev src msg; do
      [[ -z "$ep" ]] && continue
      local hhmm; hhmm=$(date -d "@$ep" +%H:%M:%S 2>/dev/null || date -r "$ep" +%H:%M:%S 2>/dev/null || echo "--:--:--")
      FEED+=("$hhmm|$sev|$src|$msg")
      ACK=0                       # new event un-acknowledges the banner
      dispatch "$sev" "$src" "$msg"
    done < <(tail -n +$((ALERT_OFFSET+1)) "$ALERTS")
    ALERT_OFFSET=$total
    (( ${#FEED[@]} > 200 )) && FEED=("${FEED[@]:${#FEED[@]}-200}")
  fi
}

# ---- compute current threat from live state -------------------------------
compute_threat(){
  local crit=0 warn=0
  if [[ -s "$L_STATE" ]]; then
    crit=$(( crit + $(grep -c '^CRIT|' "$L_STATE" 2>/dev/null) ))
    warn=$(( warn + $(grep -c '^WARN|' "$L_STATE" 2>/dev/null) ))
  fi
  if [[ -s "$R_STATE" ]]; then
    crit=$(( crit + $(grep -c '^CRIT|' "$R_STATE" 2>/dev/null) ))
    warn=$(( warn + $(grep -c '^WARN|' "$R_STATE" 2>/dev/null) ))
  fi
  PREV_THREAT="$THREAT"
  if (( crit>0 )); then THREAT="CRITICAL"; elif (( warn>0 )); then THREAT="ELEVATED"; else THREAT="NOMINAL"; fi
  THREAT_CRIT=$crit; THREAT_WARN=$warn
}

# ---- drawing primitives ---------------------------------------------------
box_top(){ # row col width title color
  local r=$1 c=$2 w=$3 title="$4" col=$5
  at "$r" "$c"; FB+="${col}╭─${RST}${B}${TITLE} ${title} ${RST}${col}$(rep $((w-6-${#title})) ─)╮${RST}"
}
box_bot(){ local r=$1 c=$2 w=$3 col=$4; at "$r" "$c"; FB+="${col}╰$(rep $((w-2)) ─)╯${RST}"; }
# interior line: row col innerwidth coloredcontent  (content must already be visible-width<=inner)
ilineraw(){ local r=$1 c=$2 w=$3 col=$4 content="$5"; at "$r" "$c"; FB+="${col}│${RST}${content}${col}│${RST}"; }
# plain interior line padded to inner width with text color
iline(){ local r=$1 c=$2 w=$3 col=$4 tcol=$5 text="$6"; at "$r" "$c"; FB+="${col}│${RST} ${tcol}$(fit "$text" $((w-4)))${RST} ${col}│${RST}"; }

sev_color(){ case "$1" in CRIT) printf '%s' "$CRITc";; WARN) printf '%s' "$WARNc";; OK) printf '%s' "$OKc";; ERR) printf '%s' "$WARNc";; SKIP) printf '%s' "$DIM";; *) printf '%s' "$DIM";; esac; }
sev_glyph(){ case "$1" in CRIT) printf '%s' "$GL_CRIT";; WARN) printf '%s' "$GL_WARN";; OK) printf '%s' "$GL_OK";; ERR) printf '%s' "$GL_ERR";; SKIP) printf '%s' "$GL_SKIP";; PEND) printf '%s' "$GL_PEND";; *) printf '%s' "$GL_PEND";; esac; }

fmt_age(){ local s=$1; (( s<0 )) && s=0
  if (( s<60 )); then printf '%ds' "$s"
  elif (( s<3600 )); then printf '%dm%02ds' $((s/60)) $((s%60))
  else printf '%dh%02dm' $((s/3600)) $(((s%3600)/60)); fi; }

# ---- the banner logo ------------------------------------------------------
# block letters spell SENTINEL — all three rows padded to 63 display columns
LOGO1='███████ ███████ ███    ██ ████████ ██ ███    ██ ███████ ██     '
LOGO2='██      █████   ██ ██  ██    ██    ██ ██ ██  ██ █████   ██     '
LOGO3='███████ ███████ ██   ████    ██    ██ ██   ████ ███████ ███████'
LOGOW=63; SLOGOW=22
# compact box-letter fallback used when terminal is narrow
SLOGO1='╔═╗╔═╗╔╗╔╔╦╗╦╔╗╔╔═╗╦  '
SLOGO2='╚═╗║╣ ║║║ ║ ║║║║║╣ ║  '
SLOGO3='╚═╝╚═╝╝╚╝ ╩ ╩╝╚╝╚═╝╩═╝'

NEED_CLEAR=1
draw(){
  if [[ -n "${NEED_CLEAR:-}" ]]; then FB=$'\033[2J\033[H'; NEED_CLEAR=''; else FB=$'\033[H'; fi
  local mid=$(( (W+1)/2 ))

  # ── BANNER ──────────────────────────────────────────────────────────
  # top rule
  at 1 1; FB+="${FRAME}$(rep $W ─)${RST}"
  local logo_color="$TITLE"
  [[ "$THREAT" == CRITICAL ]] && { (( TICK%2 )) && logo_color="$CRITc" || logo_color="$B$CRITc"; }
  local L1 L2 L3 lw
  if (( W >= 70 )); then L1="$LOGO1"; L2="$LOGO2"; L3="$LOGO3"; lw=$LOGOW; else L1="$SLOGO1"; L2="$SLOGO2"; L3="$SLOGO3"; lw=$SLOGOW; fi
  local lc=$(( (W-lw)/2 )); (( lc<2 )) && lc=2
  at 2 "$lc"; FB+="${logo_color}${L1}${RST}"
  at 3 "$lc"; FB+="${logo_color}${L2}${RST}"
  at 4 "$lc"; FB+="${logo_color}${L3}${RST}"
  local sub="P O L I N R I D E R   ///   T H R E A T   S E N T I N E L"
  at 5 $(( (W-${#sub})/2 )); FB+="${ACC}${sub}${RST}"

  # status strip (clock / host / uptime / channels)
  local clock host up chans=""
  clock=$(date +%H:%M:%S); host=$(hostname -s 2>/dev/null||echo host)
  up=$(fmt_age $(( $(now)-START )))
  [[ -n "${CANARY_NTFY_TOPIC:-}" ]] && chans+=" ntfy"
  [[ -n "${CANARY_DISCORD_URL:-}" ]] && chans+=" discord"
  [[ -n "${CANARY_SLACK_URL:-}" ]] && chans+=" slack"
  [[ "${CANARY_NATIVE:-0}" == 1 ]] && chans+=" native"
  [[ -z "$chans" ]] && chans=" log-only"
  local strip="◷ ${clock}   ⌂ ${host}   ↑ uptime ${up}   ⊹ alert:${chans# }"
  [[ "$PAUSED" == 1 ]] && strip+="   ⏸ PAUSED"
  at 6 $(( (W-${#strip})/2 )); FB+="${DIM}${strip}${RST}"

  # ── THREAT BAR (row 7) ──────────────────────────────────────────────
  local tcol="$OKc" tlabel="NOMINAL" filled=2 bars=24
  case "$THREAT" in
    ELEVATED) tcol="$WARNc"; tlabel="ELEVATED"; filled=12 ;;
    CRITICAL) tcol="$CRITc"; tlabel="◆ CRITICAL ◆"; filled=24 ;;
  esac
  local pulse="${PULSE[$(( TICK % ${#PULSE[@]} ))]}"
  local bar=""; local i
  for ((i=0;i<bars;i++)); do if (( i<filled )); then bar+='▓'; else bar+="${DIM}░${tcol}"; fi; done
  local meter="THREAT LEVEL  ${tcol}[${bar}]${RST}  ${tcol}${B}${tlabel}${RST}"
  meter+="   ${DIM}crit:${RST}${CRITc}${THREAT_CRIT:-0}${RST} ${DIM}warn:${RST}${WARNc}${THREAT_WARN:-0}${RST}"
  [[ "$THREAT" == CRITICAL && "$W" -ge 96 ]] && meter+="   ${CRITc}${B}${pulse}${pulse}${pulse} BREACH ${pulse}${pulse}${pulse}${RST}"
  at 7 4; FB+="$meter"
  at 7 1; FB+="${tcol}▌${RST}"; at 7 "$W"; FB+="${tcol}▐${RST}"

  # ── PANELS LAYOUT ───────────────────────────────────────────────────
  local ptop=9
  local feed_h=8
  local pbot=$(( H - feed_h - 2 ))
  local pheight=$(( pbot - ptop ))
  local lw2=$(( mid - 2 ))            # left panel width
  local lc1=2                          # left panel col
  local rc1=$(( mid + 1 ))            # right panel col
  local rw2=$(( W - rc1 ))            # right panel width
  (( rw2 < 10 )) && rw2=10

  # ---- LEFT: REMOTE SURVEILLANCE ----
  draw_remote "$ptop" "$lc1" "$lw2" "$pheight"
  # ---- RIGHT: LOCAL SIGNATURE SCAN ----
  draw_local "$ptop" "$rc1" "$rw2" "$pheight"

  # ── ALERT FEED (bottom) ─────────────────────────────────────────────
  local ftop=$(( H - feed_h - 1 ))
  draw_feed "$ftop" 2 "$((W-2))" "$feed_h"

  # ── FOOTER ──────────────────────────────────────────────────────────
  local keys="${LBL}q${DIM}·quit  ${LBL}p${DIM}·pause  ${LBL}r${DIM}·remote now  ${LBL}l${DIM}·local now  ${LBL}a${DIM}·ack alarm${RST}"
  at "$H" 2; FB+="${DIM}$(rep $((W-1)) ' ')${RST}"
  at "$H" 2; FB+="$keys"
  local ver="sentinel v1.0"
  at "$H" $(( W-${#ver} )); FB+="${FRAMEd}${ver}${RST}"

  # ── CRITICAL OVERLAY ────────────────────────────────────────────────
  if [[ "$THREAT" == CRITICAL && "$ACK" == 0 ]]; then draw_overlay; fi

  flush
}

draw_remote(){
  local r=$1 c=$2 w=$3 h=$4
  box_top "$r" "$c" "$w" "REMOTE SURVEILLANCE" "$FRAME"
  # meta
  IFS='|' read -r st last next cur <"$R_META"
  local i=1
  local spin="${SPIN[$(( TICK % ${#SPIN[@]} ))]}"
  if [[ "$REMOTE_ENABLED" != 1 ]]; then
    iline $((r+i)) "$c" "$w" "$FRAME" "$WARNc" "⚠ remote disabled — run 'gh auth login' + install jq"; i=$((i+1))
    iline $((r+i)) "$c" "$w" "$FRAME" "$DIM" "monitoring ${#REPOS[@]} repos when enabled"; i=$((i+1))
    for ((;i<h;i++)); do iline $((r+i)) "$c" "$w" "$FRAME" "$DIM" ""; done
    box_bot $((r+h)) "$c" "$w" "$FRAME"; return
  fi
  # counts
  local ok wn cr sk total=${#REPOS[@]}
  ok=$(grep -c '^OK|'   "$R_STATE" 2>/dev/null); ok=${ok:-0}
  wn=$(grep -c '^WARN|' "$R_STATE" 2>/dev/null); wn=${wn:-0}
  cr=$(grep -c '^CRIT|' "$R_STATE" 2>/dev/null); cr=${cr:-0}
  sk=$(grep -c '^SKIP|' "$R_STATE" 2>/dev/null); sk=${sk:-0}
  local plainfull="${GL_OK} ${ok} clear  ${GL_WARN} ${wn} watch  ${GL_CRIT} ${cr} breach  ${GL_SKIP} ${sk} priv"
  local statusline
  if (( ${#plainfull} <= w-4 )); then
    statusline="${OKc}${GL_OK} ${ok} clear${RST}  ${WARNc}${GL_WARN} ${wn} watch${RST}  ${CRITc}${GL_CRIT} ${cr} breach${RST}  ${DIM}${GL_SKIP} ${sk} priv${RST}"
  else
    statusline="${OKc}${GL_OK}${ok}${RST} ${WARNc}${GL_WARN}${wn}${RST} ${CRITc}${GL_CRIT}${cr}${RST} ${DIM}${GL_SKIP}${sk}${RST}"
  fi
  ilineraw $((r+i)) "$c" "$w" "$FRAME" "$(printf '%-*s' $((w-2)) '')"; at $((r+i)) $((c+2)); FB+="$statusline"; i=$((i+1))

  if [[ "$st" == running ]]; then
    iline $((r+i)) "$c" "$w" "$FRAME" "$ACC" "$spin sweeping… ${next}% — ${cur##*/}"
  else
    local age nxt; age=$(fmt_age $(( $(now)-${last:-0} ))); nxt=$(fmt_age $(( ${next:-0}-$(now) )))
    iline $((r+i)) "$c" "$w" "$FRAME" "$DIM" "last sweep ${age} ago   next in ${nxt}"
  fi
  i=$((i+1))
  iline $((r+i)) "$c" "$w" "$FRAME" "$FRAMEd" "$(rep $((w-4)) ┄)"; i=$((i+1))

  # rows: non-OK pinned first, then a scrolling window of the rest
  local lines_avail=$(( h - i ))
  local bad=() good=() _l
  while IFS= read -r _l; do [[ -n "$_l" ]] && bad+=("$_l"); done < <(grep -E '^(CRIT|WARN|ERR)\|' "$R_STATE" 2>/dev/null)
  while IFS= read -r _l; do [[ -n "$_l" ]] && good+=("$_l"); done < <(grep -E '^(OK|SKIP)\|' "$R_STATE" 2>/dev/null)
  local rows=()
  ((${#bad[@]})) && rows+=("${bad[@]}")
  # scroll window through the 'good' list
  local gn=${#good[@]}
  if (( gn>0 )); then
    local slot=$(( lines_avail - ${#bad[@]} )); (( slot<0 )) && slot=0
    local off=$(( (SCROLL/2) % gn ))
    local k
    for ((k=0;k<slot && k<gn;k++)); do rows+=("${good[$(( (off+k)%gn ))]}"); done
  fi
  local shown=0
  for row in ${rows[@]+"${rows[@]}"}; do
    (( shown>=lines_avail )) && break
    IFS='|' read -r code repo detail rest <<<"$row"
    local g col; g=$(sev_glyph "$code"); col=$(sev_color "$code")
    at $((r+i+shown)) "$c"; FB+="${FRAME}│${RST} ${col}${g}${RST} ${TXT}$(fit "${repo#*/}" $((w-21)))${RST} ${DIM}$(fit "$detail" 14)${RST} ${FRAME}│${RST}"
    shown=$((shown+1))
  done
  for ((;shown<lines_avail;shown++)); do iline $((r+i+shown)) "$c" "$w" "$FRAME" "$DIM" ""; done
  box_bot $((r+h)) "$c" "$w" "$FRAME"
}

draw_local(){
  local r=$1 c=$2 w=$3 h=$4
  box_top "$r" "$c" "$w" "LOCAL SIGNATURE SCAN" "$FRAME"
  IFS='|' read -r st last next cur <"$L_META"
  local i=1
  local spin="${SPIN[$(( TICK % ${#SPIN[@]} ))]}"
  local roots="${REPO_ROOTS[*]}"
  iline $((r+i)) "$c" "$w" "$FRAME" "$DIM" "roots: ${roots/#$HOME/~}"; i=$((i+1))
  if [[ "$st" == running ]]; then
    iline $((r+i)) "$c" "$w" "$FRAME" "$ACC" "$spin scanning ${next}% — $cur"
  else
    local age nxt; age=$(fmt_age $(( $(now)-${last:-0} ))); nxt=$(fmt_age $(( ${next:-0}-$(now) )))
    iline $((r+i)) "$c" "$w" "$FRAME" "$DIM" "last scan ${age} ago   next in ${nxt}"
  fi
  i=$((i+1))
  iline $((r+i)) "$c" "$w" "$FRAME" "$FRAMEd" "$(rep $((w-4)) ┄)"; i=$((i+1))
  local lines_avail=$(( h - i ))
  local shown=0
  if [[ -s "$L_STATE" ]]; then
    while IFS='|' read -r sev label detail; do
      [[ -z "$sev" ]] && continue
      (( shown>=lines_avail )) && break
      local g col; g=$(sev_glyph "$sev"); col=$(sev_color "$sev")
      at $((r+i+shown)) "$c"; FB+="${FRAME}│${RST} ${col}${g}${RST} ${TXT}$(fit "$label" $((w-21)))${RST} ${col}$(fit "$detail" 14)${RST} ${FRAME}│${RST}"
      shown=$((shown+1))
    done <"$L_STATE"
  else
    iline $((r+i+shown)) "$c" "$w" "$FRAME" "$DIM" "$spin initializing first scan…"; shown=$((shown+1))
  fi
  for ((;shown<lines_avail;shown++)); do iline $((r+i+shown)) "$c" "$w" "$FRAME" "$DIM" ""; done
  box_bot $((r+h)) "$c" "$w" "$FRAME"
}

draw_feed(){
  local r=$1 c=$2 w=$3 h=$4
  local col="$FRAME"; [[ "$THREAT" == CRITICAL ]] && { (( TICK%2 )) && col="$CRITc"; }
  box_top "$r" "$c" "$w" "ALERT FEED" "$col"
  local inner=$(( h - 1 ))
  local start=$(( ${#FEED[@]} - inner )); (( start<0 )) && start=0
  local shown=0 idx
  for ((idx=start; idx<${#FEED[@]}; idx++)); do
    IFS='|' read -r tm sev src msg <<<"${FEED[$idx]}"
    local g cc2; g=$(sev_glyph "$sev"); cc2=$(sev_color "$sev")
    at $((r+1+shown)) "$c"; FB+="${col}│${RST} ${DIM}${tm}${RST} ${cc2}${g} $(printf '%-4s' "$sev")${RST} ${TXT}$(fit "$src — $msg" $((w-20)))${RST} ${col}│${RST}"
    shown=$((shown+1))
  done
  if (( shown==0 )); then
    at $((r+1)) "$c"; FB+="${col}│${RST} ${DIM}$(fit "no events — all systems nominal" $((w-4)))${RST} ${col}│${RST}"
    shown=1
  fi
  for ((;shown<inner;shown++)); do at $((r+shown+1)) "$c"; FB+="${col}│${RST}$(rep $((w-2)) ' ')${col}│${RST}"; done
  box_bot $((r+h)) "$c" "$w" "$col"
}

draw_overlay(){
  local bw=$(( W*3/5 )); (( bw<44 )) && bw=44; (( bw>W-4 )) && bw=$((W-4))
  local bh=9
  local bc=$(( (W-bw)/2 ))
  local br=$(( (H-bh)/2 ))
  local blink="$CRITc"; (( TICK%2 )) && blink="${INV}${CRITc}"
  local i
  # solid red frame
  at "$br" "$bc"; FB+="${blink}╔$(rep $((bw-2)) ═)╗${RST}"
  for ((i=1;i<bh-1;i++)); do at $((br+i)) "$bc"; FB+="${blink}║${RST}$(rep $((bw-2)) ' ')${blink}║${RST}"; done
  at $((br+bh-1)) "$bc"; FB+="${blink}╚$(rep $((bw-2)) ═)╝${RST}"
  # centre a string inside the box, clipping to the inner width
  ccen(){ local s="$1"; (( ${#s} > bw-4 )) && s="$(fit "$s" $((bw-4)))"; local off=$(( bc + (bw-${#s})/2 )); (( off < bc+2 )) && off=$((bc+2)); CCEN_OFF=$off; CCEN_STR="$s"; }
  local t1="⚠   I N T R U S I O N   D E T E C T E D   ⚠"
  local t2="PolinRider signatures present on this system / fleet"
  ccen "$t1"; at $((br+2)) "$CCEN_OFF"; FB+="${B}${CRITc}${CCEN_STR}${RST}"
  ccen "$t2"; at $((br+3)) "$CCEN_OFF"; FB+="${TXT}${CCEN_STR}${RST}"
  # latest 2 critical messages
  local crit=(); local idx
  for ((idx=${#FEED[@]}-1; idx>=0 && ${#crit[@]}<2; idx--)); do
    IFS='|' read -r tm sev src msg <<<"${FEED[$idx]}"
    [[ "$sev" == CRIT ]] && crit=("${tm}  ${src} — ${msg}" ${crit[@]+"${crit[@]}"})
  done
  local row=$((br+5))
  for line in ${crit[@]+"${crit[@]}"}; do
    at "$row" $(( bc+2 )); FB+="${CRITc}▶ ${TXT}$(fit "$line" $((bw-6)))${RST}"; row=$((row+1))
  done
  local hint="[a] acknowledge  ·  investigate: check-polinrider-mac.sh --full"
  ccen "$hint"; at $((br+bh-2)) "$CCEN_OFF"; FB+="${DIM}${CCEN_STR}${RST}"
}

# ---- bell on new critical (rate-limited) ----------------------------------
maybe_bell(){
  if [[ "$THREAT" == CRITICAL && "$ACK" == 0 ]]; then
    local t; t=$(now)
    if (( t - LAST_BELL >= 2 )); then printf '\a'; LAST_BELL=$t; fi
  fi
}

# ═══════════════════════════════ LAUNCH ═══════════════════════════════════
get_size
if (( W<70 || H<20 )); then
  echo "Sentinel needs at least 70x20. Current: ${W}x${H}. Resize and retry."
  exit 1
fi

# ---- self-test / screenshot hook: seed sample state, render N frames, exit ----
if [[ -n "${SENTINEL_SELFTEST:-}" ]]; then
  set_tui_locale
  [[ -n "${SENTINEL_COLS:-}" ]] && W=$SENTINEL_COLS
  [[ -n "${SENTINEL_ROWS:-}" ]] && H=$SENTINEL_ROWS
  REMOTE_ENABLED=1
  printf 'CRIT|Payload signatures|2 file(s) match markers\nOK|Fake font payloads|clear\nOK|VS Code auto-tasks|clear\nCRIT|Propagation droppers|1 temp_auto_push.bat\nOK|Malicious npm dep|clear\nOK|Rogue processes|clear\nWARN|C2 network links|1 link to api.trongrid.io\nOK|Persistence agents|clear\n' >"$L_STATE"
  printf 'idle|%s|%s|\n' "$(now)" "$(( $(now)+97 ))" >"$L_META"
  {
    printf 'CRIT|sam1am/cairn|FORCE PUSH by mallory|%s\n' "$(now)"
    printf 'WARN|sam1am/inkit|push by drifter|%s\n' "$(now)"
    for r in polinrider Sunshine resumaker cocofintel SageChat sidekick pennyQ cli-viz poetroid sekrits; do
      printf 'OK|sam1am/%s|clean|%s\n' "$r" "$(now)"
    done
  } >"$R_STATE"
  printf 'idle|%s|%s|\n' "$(now)" "$(( $(now)+212 ))" >"$R_META"
  emit CRIT "remote:sam1am/cairn" "FORCE PUSH — PolinRider attack signature (actor=mallory)"
  emit CRIT "local:prop" "Propagation droppers — 1 temp_auto_push.bat present"
  emit WARN "local:net" "C2 network links — 1 live connection to api.trongrid.io"
  _frames="${SENTINEL_SELFTEST}"
  for ((TICK=0; TICK<_frames; TICK++)); do ingest; compute_threat; [[ "${SENTINEL_ACK:-0}" == 1 ]] && ACK=1; draw; done
  trap - EXIT INT TERM; rm -rf "$RUN"; exit 0
fi

# start workers (they inherit LC_ALL=C for fast, binary-safe grep)
if [[ "$REMOTE_ENABLED" == 1 ]]; then remote_worker & WORKER_PIDS+=($!); fi
local_worker & WORKER_PIDS+=($!)

# main process renders under UTF-8 so column math is correct
set_tui_locale

# enter alt screen, hide cursor, raw-ish input
printf '\033[?1049h\033[?25l'
stty -echo 2>/dev/null
trap 'get_size; NEED_CLEAR=1' WINCH

# main render loop
while :; do
  TICK=$((TICK+1)); SCROLL=$((SCROLL+1))
  ingest
  compute_threat
  draw
  maybe_bell

  # blocking-with-timeout key read; doubles as the 1s frame clock (bash 3.2: integer -t)
  if IFS= read -rsn1 -t 1 key 2>/dev/null; then
    case "$key" in
      q|Q) break ;;
      p|P) PAUSED=$(( PAUSED ? 0 : 1 ))
           if [[ "$PAUSED" == 1 ]]; then
             for pid in "${WORKER_PIDS[@]}"; do kill -STOP "$pid" 2>/dev/null; done
           else
             for pid in "${WORKER_PIDS[@]}"; do kill -CONT "$pid" 2>/dev/null; done
           fi ;;
      r|R) [[ "$PAUSED" == 0 ]] && : >"$R_TRIGGER" ;;
      l|L) [[ "$PAUSED" == 0 ]] && : >"$L_TRIGGER" ;;
      a|A) ACK=1 ;;
    esac
  fi
done
exit 0
