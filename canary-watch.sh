#!/usr/bin/env bash
# canary-watch.sh — alert on suspicious GitHub repo activity.
#
# Polls the GitHub "repository activity" endpoint for each watched repo,
# detects new events since the last run, and raises an alert on:
#   - any force_push (the PolinRider attack signature)
#   - any push by an actor NOT in CANARY_TRUSTED_ACTORS
#   - any branch_creation by an untrusted actor
#
# Designed to run as a cron job or systemd user timer on Linux/macOS.
# Read-only against GitHub (only GET calls); writes a tiny state file locally.
#
# REQUIREMENTS
#   - bash 4+
#   - gh (logged in: `gh auth login`)
#   - jq
#   - curl (only if you enable webhook alerts)
#
# QUICK START
#   1) Copy this script to your monitoring host.
#   2) Edit CANARY_REPOS or set the env var (see CONFIG below).
#   3) Run once manually:   bash canary-watch.sh
#   4) Schedule it (cron):  */15 * * * * /usr/bin/bash /path/to/canary-watch.sh >>/var/log/canary.log 2>&1
#      Or systemd user timer (see end of this file for a sample unit).
#
# ALERT CHANNELS (any/all can be enabled simultaneously via env vars)
#   CANARY_ALERT_FILE   - append-only log; default: $XDG_STATE_HOME/canary/alerts.log
#   CANARY_NTFY_TOPIC   - https://ntfy.sh/<topic> push notification (free, no signup;
#                         subscribe to the topic in the ntfy app on your phone)
#   CANARY_DISCORD_URL  - Discord channel webhook URL
#   CANARY_SLACK_URL    - Slack incoming-webhook URL
#   CANARY_NATIVE       - "1" to also use notify-send (Linux) / osascript (macOS)
#
# CONFIG ----------------------------------------------------------------------

# Repos to watch. Override by exporting CANARY_REPOS as a space-separated list,
# OR by placing a file at $CANARY_REPO_FILE (one "owner/name" per line).
CANARY_REPOS_DEFAULT=(
  # PolinRider new-wave targets (May 2026)
  sam1am/cairn
  sam1am/termux_crt
  sam1am/anyapk
  sam1am/inkit
  sam1am/samandnat
  sam1am/polinrider
  # Older infected targets (still HEAD-clean as of cleanup PRs)
  sam1am/Sunshine
  sam1am/resumaker
  sam1am/cocofintel
  sam1am/SageChat
  sam1am/sidekick
  sam1am/pennyQ
  # Second-wave cleanup set
  sam1am/Ryzen-Master-Commander
  sam1am/bookmarklets
  sam1am/cli-viz
  sam1am/inmo_air_3_wiki
  sam1am/poetroid
  sam1am/sekrits
  sam1am/air-canary
  sam1am/saltonsun
  sam1am/sagenotes-premium
  sam1am/autonews
  sam1am/worker-whisperx
  sam1am/jackalope
  sam1am/voicekeyboard
  sam1am/timeline
  sam1am/stockbot
  sam1am/secure-askpass
  sam1am/restorelakebonnevile
  sam1am/pavegsl
  sam1am/nbfc-linux
  sam1am/minibook-support
  sam1am/mini-scraper
  sam1am/beedaddykb.com
)

# Actors whose pushes are considered LEGITIMATE — anything else raises an alert.
# Add the bot accounts you actually run (release workflows, dependabot, etc.).
CANARY_TRUSTED_ACTORS_DEFAULT=(
  sam1am
  github-actions[bot]
  dependabot[bot]
  renovate[bot]
)

# State directory — last-seen activity timestamp is stored here per repo.
: "${CANARY_STATE_DIR:=${XDG_STATE_HOME:-$HOME/.local/state}/canary}"
: "${CANARY_ALERT_FILE:=$CANARY_STATE_DIR/alerts.log}"

# CONFIG END ------------------------------------------------------------------

set -uo pipefail
export LC_ALL=C

# Resolve config from env or defaults
if [[ -n "${CANARY_REPO_FILE:-}" && -f "$CANARY_REPO_FILE" ]]; then
  mapfile -t REPOS < <(grep -vE '^[[:space:]]*(#|$)' "$CANARY_REPO_FILE")
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

mkdir -p "$CANARY_STATE_DIR"
touch "$CANARY_ALERT_FILE"

# Sanity check tools
for tool in gh jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "FATAL: required tool '$tool' not on PATH" >&2
    exit 2
  fi
done

# Confirm gh is authenticated
if ! gh auth status >/dev/null 2>&1; then
  echo "FATAL: gh CLI is not authenticated. Run 'gh auth login' first." >&2
  exit 2
fi

is_trusted_actor() {
  local a="$1"
  for t in "${TRUSTED[@]}"; do
    [[ "$a" == "$t" ]] && return 0
  done
  return 1
}

# ---- alert dispatch ---------------------------------------------------------
send_alert() {
  local severity="$1" repo="$2" summary="$3" details="$4"
  local ts; ts="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  local line="[$ts] [$severity] $repo — $summary"

  # 1) Always: stdout + alert log file
  echo "$line"
  echo "$line" >> "$CANARY_ALERT_FILE"
  [[ -n "$details" ]] && echo "    $details" >> "$CANARY_ALERT_FILE"

  # 2) ntfy.sh push (free, no signup — subscribe to topic in app)
  if [[ -n "${CANARY_NTFY_TOPIC:-}" ]]; then
    local prio="default"
    [[ "$severity" == "CRITICAL" ]] && prio="urgent"
    [[ "$severity" == "WARN" ]] && prio="high"
    curl -fsS -X POST "https://ntfy.sh/${CANARY_NTFY_TOPIC}" \
      -H "Title: Canary: $repo" \
      -H "Priority: $prio" \
      -H "Tags: warning,github" \
      -d "$summary"$'\n'"$details" >/dev/null || true
  fi

  # 3) Discord webhook
  if [[ -n "${CANARY_DISCORD_URL:-}" ]]; then
    local payload
    payload=$(jq -nc --arg c "[$severity] **$repo** — $summary"$'\n'"$details" '{content:$c}')
    curl -fsS -X POST -H "Content-Type: application/json" \
      -d "$payload" "$CANARY_DISCORD_URL" >/dev/null || true
  fi

  # 4) Slack webhook
  if [[ -n "${CANARY_SLACK_URL:-}" ]]; then
    local payload
    payload=$(jq -nc --arg c "[$severity] *$repo* — $summary"$'\n'"$details" '{text:$c}')
    curl -fsS -X POST -H "Content-Type: application/json" \
      -d "$payload" "$CANARY_SLACK_URL" >/dev/null || true
  fi

  # 5) Native desktop notification
  if [[ "${CANARY_NATIVE:-0}" == "1" ]]; then
    if command -v notify-send >/dev/null 2>&1; then
      notify-send -u critical "Canary: $repo" "$summary"$'\n'"$details" || true
    elif command -v osascript >/dev/null 2>&1; then
      osascript -e "display notification \"$summary\" with title \"Canary: $repo\" sound name \"Sosumi\"" || true
    fi
  fi
}

# ---- per-repo check ---------------------------------------------------------
check_repo() {
  local repo="$1"
  local state_file="$CANARY_STATE_DIR/${repo//\//__}.last"
  local last_seen_ms=0
  [[ -f "$state_file" ]] && last_seen_ms=$(cat "$state_file" 2>/dev/null || echo 0)
  [[ "$last_seen_ms" =~ ^[0-9]+$ ]] || last_seen_ms=0

  # Pull activity (default per_page=30 is plenty between 15-min polls)
  local activity
  if ! activity=$(gh api -X GET "repos/$repo/activity" -F per_page=30 2>&1); then
    # Suppress 404 (private/missing) but log other errors loudly
    if echo "$activity" | grep -q '"Not Found"'; then
      return 0
    fi
    send_alert "ERROR" "$repo" "gh api failed" "$activity"
    return 1
  fi

  # Parse: jq gives us records sorted newest-first by default
  local newest_ms=$last_seen_ms
  while IFS=$'\t' read -r ts atype actor ref before after; do
    [[ -z "$ts" ]] && continue
    local ts_ms
    ts_ms=$(date -u -d "$ts" +%s%3N 2>/dev/null) || \
      ts_ms=$(python3 -c "import sys,datetime; print(int(datetime.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00')).timestamp()*1000))" "$ts" 2>/dev/null) || \
      continue
    if (( ts_ms > newest_ms )); then newest_ms=$ts_ms; fi
    (( ts_ms <= last_seen_ms )) && continue

    # Skip first run — only baseline the state, don't alert on history
    if (( last_seen_ms == 0 )); then continue; fi

    # Compose details
    local details="actor=$actor ref=$ref ${before:0:7}..${after:0:7} at $ts"

    case "$atype" in
      force_push)
        send_alert "CRITICAL" "$repo" "FORCE PUSH detected (PolinRider attack signature)" "$details"
        ;;
      push)
        if ! is_trusted_actor "$actor"; then
          send_alert "WARN" "$repo" "push from untrusted actor '$actor'" "$details"
        fi
        # Always also flag pushes to default branches by anyone, optionally:
        if [[ "${CANARY_ALERT_ALL_PUSHES:-0}" == "1" ]]; then
          send_alert "INFO" "$repo" "push by $actor" "$details"
        fi
        ;;
      branch_creation|branch_deletion)
        if ! is_trusted_actor "$actor"; then
          send_alert "WARN" "$repo" "$atype by untrusted actor '$actor'" "$details"
        fi
        ;;
      pr_merge)
        # Almost always legitimate; only flag from untrusted actor
        if ! is_trusted_actor "$actor"; then
          send_alert "WARN" "$repo" "PR merge by untrusted actor '$actor'" "$details"
        fi
        ;;
      merge_queue_merge)
        : ;;
      *)
        if [[ "${CANARY_DEBUG:-0}" == "1" ]]; then
          echo "  unknown activity_type: $atype on $repo by $actor at $ts"
        fi
        ;;
    esac
  done < <(echo "$activity" | jq -r '.[] | [.timestamp, .activity_type, .actor.login, (.ref//""), (.before//""), (.after//"")] | @tsv')

  # Persist newest seen
  echo "$newest_ms" > "$state_file"
}

# ---- main loop --------------------------------------------------------------
NEW_ALERTS_BEFORE=$(wc -l < "$CANARY_ALERT_FILE")
for repo in "${REPOS[@]}"; do
  check_repo "$repo"
done
NEW_ALERTS_AFTER=$(wc -l < "$CANARY_ALERT_FILE")
NEW_ALERTS=$((NEW_ALERTS_AFTER - NEW_ALERTS_BEFORE))

if [[ "${CANARY_VERBOSE:-0}" == "1" ]]; then
  echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] checked ${#REPOS[@]} repos, $NEW_ALERTS new alert(s)"
fi
exit 0

# -----------------------------------------------------------------------------
# Example systemd user timer (~/.config/systemd/user/canary.{service,timer})
# -----------------------------------------------------------------------------
#
# ~/.config/systemd/user/canary.service
# -------------------------------------
# [Unit]
# Description=PolinRider canary repo monitor
# After=network-online.target
#
# [Service]
# Type=oneshot
# # Set alert channel(s) here; ntfy is simplest — pick a hard-to-guess topic name
# Environment="CANARY_NTFY_TOPIC=my-canary-7f3a9b2c"
# Environment="CANARY_VERBOSE=1"
# ExecStart=/usr/bin/bash %h/bin/canary-watch.sh
#
# ~/.config/systemd/user/canary.timer
# -----------------------------------
# [Unit]
# Description=Run PolinRider canary every 15 minutes
#
# [Timer]
# OnBootSec=2min
# OnUnitActiveSec=15min
# Persistent=true
#
# [Install]
# WantedBy=timers.target
#
# Then:
#   systemctl --user daemon-reload
#   systemctl --user enable --now canary.timer
#   journalctl --user -u canary.service -f   # watch output
#
# For cron instead (every 15 min):
#   crontab -e
#   */15 * * * * CANARY_NTFY_TOPIC=my-canary-7f3a9b2c /usr/bin/bash $HOME/bin/canary-watch.sh
# -----------------------------------------------------------------------------
