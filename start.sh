#!/usr/bin/env bash
# CSM API — production start script
# Usage: ./start.sh            # foreground
#        ./start.sh --daemon   # background via nohup (prefer systemd)
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
# shellcheck disable=SC1091
source "$DIR/venv/bin/activate"

# ── defaults (override via env or a .env file next to this script) ──────────
if [[ -f "$DIR/.env" ]]; then
  set -a; # shellcheck disable=SC1091
  source "$DIR/.env"; set +a
fi

export SOLVER_ALLOW_PRIVATE="${SOLVER_ALLOW_PRIVATE:-1}"
export TURNSTILE_HEADLESS="${TURNSTILE_HEADLESS:-0}"
export RECAPTCHA_HEADLESS="${RECAPTCHA_HEADLESS:-0}"
export SOLVER_PROXY_ROTATE="${SOLVER_PROXY_ROTATE:-1}"
export SOLVER_PROXY_FILE="${SOLVER_PROXY_FILE:-$HOME/cf-factory/proxies.txt}"

# Pick first proxy for page-level CF/AWSWAF (IP-bound cookies need a sticky proxy).
if [[ -z "${CLOUDFLARE_PROXY:-}" && -f "$SOLVER_PROXY_FILE" ]]; then
  line=$(head -1 "$SOLVER_PROXY_FILE")
  h=$(echo "$line" | cut -d: -f1)
  p=$(echo "$line" | cut -d: -f2)
  u=$(echo "$line" | cut -d: -f3)
  pw=$(echo "$line" | cut -d: -f4-)
  if [[ -n "$h" && -n "$p" && -n "$u" ]]; then
    export CLOUDFLARE_PROXY="http://$u:$pw@$h:$p"
    export AWSWAF_PROXY="${AWSWAF_PROXY:-$CLOUDFLARE_PROXY}"
  fi
fi

LOG="${SOLVER_LOG:-/tmp/solver_max.log}"
HOST="${SOLVER_HOST:-0.0.0.0}"
PORT="${SOLVER_PORT:-8877}"

# Prefer xvfb for headful solvers (Turnstile checkbox path needs real window).
RUNNER=(python3 app.py)
if command -v xvfb-run >/dev/null 2>&1; then
  RUNNER=(xvfb-run -a --server-args="-screen 0 1920x1080x24" python3 app.py)
fi

echo "[start] host=$HOST port=$PORT proxy_rotate=$SOLVER_PROXY_ROTATE proxy_file=$SOLVER_PROXY_FILE"
echo "[start] log=$LOG"

if [[ "${1:-}" == "--daemon" ]]; then
  nohup "${RUNNER[@]}" >"$LOG" 2>&1 &
  echo $! > /tmp/solver_max.pid
  echo "[start] pid=$(cat /tmp/solver_max.pid)"
else
  exec "${RUNNER[@]}"
fi
