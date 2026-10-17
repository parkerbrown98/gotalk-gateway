#!/bin/sh
# Smoke-test a running gateway: health, readiness, discovery and metrics.
# Usage: scripts/smoke.sh [BASE_URL]   (default http://localhost:8090)
set -eu

base="${1:-http://localhost:8090}"
fail() { echo "FAIL: $*" >&2; exit 1; }

check() {
	path="$1"; want="$2"
	body=$(curl -fsS "$base$path") || fail "GET $path"
	case "$body" in
	*"$want"*) echo "ok   GET $path" ;;
	*) fail "GET $path: expected $want in: $body" ;;
	esac
}

check /healthz '"status":"ok"'
check /readyz '"status":"ready"'
check /.well-known/gotalk-gateway '"software":"gotalk-gateway"'
check /v1/gateway '"api_versions":["v1"]'
check /metrics 'gotalk_gateway_build_info'

cache=$(curl -fsS -D - -o /dev/null "$base/v1/gateway" | tr -d '\r' | grep -i '^cache-control:' || true)
case "$cache" in
*"public, max-age=300"*) echo "ok   discovery Cache-Control" ;;
*) fail "discovery Cache-Control: $cache" ;;
esac

[ "$(curl -fsS "$base/.well-known/gotalk-gateway")" = "$(curl -fsS "$base/v1/gateway")" ] \
	|| fail "the two discovery paths differ"
echo "ok   discovery paths match"
