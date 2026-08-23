#!/usr/bin/env sh
set -eu

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ARTIFACTS=${1:-"$LAB_DIR/artifacts"}
mkdir -p "$ARTIFACTS"

if [ -f "$ARTIFACTS/otlp.json" ]; then
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  mv "$ARTIFACTS/otlp.json" "$ARTIFACTS/otlp.$stamp.json"
fi

export TRACEPROOF_LAB_ARTIFACTS="$ARTIFACTS"
cleanup() {
  docker compose -f "$LAB_DIR/docker-compose.yml" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker compose -f "$LAB_DIR/docker-compose.yml" up \
  --abort-on-container-exit --exit-code-from agent

dspy-security-bench trace import "$ARTIFACTS/otlp.json" \
  --out "$ARTIFACTS/trace-evidence.json"
dspy-security-bench trace analyze "$ARTIFACTS/trace-evidence.json" \
  --out "$ARTIFACTS/trace-report.json" \
  --sarif-out "$ARTIFACTS/trace-results.sarif"
dspy-security-bench trace mcp analyze "$ARTIFACTS/trace-evidence.json" \
  --out "$ARTIFACTS/mcp-authorization-report.json"

printf '%s\n' "TraceProof reference lab complete: $ARTIFACTS"
