#!/usr/bin/env bash
# Start the whole TAD -> PETA workflow. Ctrl-C stops everything.
# A watchdog restarts PETA or TAD if either dies (PETA dying while TAD stayed up
# was a recurring failure). Set WATCHDOG=0 to disable and just run once.
set -e
cd "$(dirname "$0")"
ROOT="$PWD"
export PYTHONPATH="$ROOT/TAD/scripts"

# Per-run log directory so each run is saved separately (never overwritten/mixed).
# logs/<timestamp>/{server.log, detections.log, peta.log}; logs/latest -> newest.
RUN_TS="$(date +%Y%m%d-%H%M%S)"
LOG_ROOT="${LOG_ROOT:-$ROOT/logs}"
RUN_DIR="$LOG_ROOT/$RUN_TS"
mkdir -p "$RUN_DIR"
ln -sfn "$RUN_DIR" "$LOG_ROOT/latest"
SERVER_LOG="$RUN_DIR/server.log"        # raw: everything TAD prints
DETECT_LOG="$RUN_DIR/detections.log"    # TAD: clean detections
PETA_LOG="$RUN_DIR/peta.log"            # PETA

# TAD needs joblib/scikit-learn — the system python3 does not have them.
PY="${PY:-/home/sdt/gnn_env/bin/python}"
[ -x "$PY" ] || { echo "ERROR: python not found at $PY (set PY=/path/to/python)"; exit 1; }

# Threat-model consumer. Empty = skip delivery (no consumer deployed).
# A dead URL here costs a connect timeout PER DETECTION, inline in /ingest/raw.
OUTPUT_URL="${OUTPUT_URL:-}"
# curl -X POST http://192.168.1.50:4317/api/threats -H 'Content-Type: application/json' -d @samples/sample-dos.json
PETA_PORT="${PETA_PORT:-8000}"
TAD_PORT="${TAD_PORT:-8002}"
WATCHDOG="${WATCHDOG:-1}"          # 1 = auto-restart crashed services
CHECK_EVERY="${CHECK_EVERY:-5}"    # seconds between health checks
MIN_CONF="${MIN_CONF:-0.7}"        # don't fire a mitigation below this confidence (0..1)
COOLDOWN="${COOLDOWN:-30}"         # min seconds between PETA calls per (attack, target)

start_peta() {
  ( cd PETA && "$PY" -m uvicorn main:app --port "$PETA_PORT" --host 0.0.0.0 \
      >> "$PETA_LOG" 2>&1 ) &
  PETA_PID=$!
  echo "==> PETA  on :$PETA_PORT   (pid $PETA_PID)"
}

wait_for_peta() {
  for _ in $(seq 1 30); do
    curl -sf "http://127.0.0.1:$PETA_PORT/docs" >/dev/null && return 0
    sleep 1
  done
  echo "    WARN: PETA not healthy after 30s"
  return 1
}

start_tad() {
  "$PY" TAD/scripts/tad_api.py --port "$TAD_PORT" \
      --model TAD/models/multiclass/hgb_newdataset_5class.joblib \
      --dispatch \
      --peta-url "http://127.0.0.1:$PETA_PORT/PETA/sdt/impact" \
      --output-url "$OUTPUT_URL" \
      --dispatch-min-confidence "$MIN_CONF" \
      --dispatch-cooldown "$COOLDOWN" \
      --log-file "$DETECT_LOG" \
      --quiet-console >> "$SERVER_LOG" 2>&1 &
  TAD_PID=$!
  echo "==> TAD   on :$TAD_PORT   (pid $TAD_PID, dispatch -> PETA -> ${OUTPUT_URL:-<none>})"
}

start_peta
echo "    waiting for PETA ..."
wait_for_peta
start_tad

# Ctrl-C / kill: stop the watchdog AND both children. Uses current PIDs.
RUNNING=1
trap 'RUNNING=0; echo; echo "stopping..."; kill "$PETA_PID" "$TAD_PID" 2>/dev/null; exit 0' INT TERM

echo
echo "  TAD ingest : POST http://<host>:$TAD_PORT/ingest/raw"
echo "  health     : curl http://127.0.0.1:$TAD_PORT/health"
echo "  live view  : curl http://127.0.0.1:$TAD_PORT/active"
echo "  logs (this run) -> $RUN_DIR  (also logs/latest)"
echo "    raw (TAD console) : $SERVER_LOG"
echo "    TAD detections    : $DETECT_LOG"
echo "    PETA              : $PETA_LOG"
echo "  dispatch   : min_confidence=$MIN_CONF  cooldown=${COOLDOWN}s"
echo "  watchdog   : $([ "$WATCHDOG" = 1 ] && echo "on (restarts crashed services)" || echo off)"
echo "  Ctrl-C to stop."

if [ "$WATCHDOG" != 1 ]; then
  wait                             # legacy behaviour: run until a child exits
  exit 0
fi

# Supervisor: restart whichever service has died. PETA is restarted first so TAD
# has something to dispatch to.
while [ "$RUNNING" = 1 ]; do
  sleep "$CHECK_EVERY"
  if ! kill -0 "$PETA_PID" 2>/dev/null; then
    echo "[watchdog] PETA (pid $PETA_PID) is down — restarting"
    start_peta; wait_for_peta || true      # don't let a slow restart kill the watchdog
  fi
  if ! kill -0 "$TAD_PID" 2>/dev/null; then
    echo "[watchdog] TAD (pid $TAD_PID) is down — restarting"
    start_tad
  fi
done
