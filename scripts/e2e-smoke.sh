#!/usr/bin/env bash
# End-to-end smoke test for a running NetSentry Cloud stack:
#   admin login -> enrollment token -> sensor enroll -> ingest a critical alert
#   -> alert visible + block proposed (manual mode) -> approve -> sensor sync lists it.
#
#   BASE_URL=https://localhost ADMIN_EMAIL=... ADMIN_PASSWORD=... ./scripts/e2e-smoke.sh
#
# For a stack without a reverse proxy set CONSOLE_URL and GATEWAY_URL instead of BASE_URL.
set -euo pipefail

BASE_URL="${BASE_URL:-https://localhost}"
CONSOLE_URL="${CONSOLE_URL:-$BASE_URL}"
GATEWAY_URL="${GATEWAY_URL:-$BASE_URL}"
: "${ADMIN_EMAIL:?set ADMIN_EMAIL}"
: "${ADMIN_PASSWORD:?set ADMIN_PASSWORD}"
CURL=(curl -fsS --max-time 20)
if [ "${INSECURE:-0}" = "1" ]; then CURL+=(-k); fi

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
jget() { jq -er "$1"; }

command -v jq >/dev/null 2>&1 || fail "jq is required"

step "login"
LOGIN_BODY="$(jq -n --arg e "$ADMIN_EMAIL" --arg p "$ADMIN_PASSWORD" '{email:$e,password:$p}')"
JWT="$("${CURL[@]}" -H 'content-type: application/json' -d "$LOGIN_BODY" "$CONSOLE_URL/api/auth/login" | jget .access_token)"
AUTH=(-H "authorization: Bearer $JWT")

step "create enrollment token"
TOKEN="$("${CURL[@]}" "${AUTH[@]}" -H 'content-type: application/json' -d '{"label":"smoke","ttlHours":1,"maxUses":1}' \
    "$CONSOLE_URL/api/enrollment-tokens" | jget .token)"

step "enroll sensor"
ENROLL="$("${CURL[@]}" -H "x-enrollment-token: $TOKEN" -H 'content-type: application/json' \
    -d '{"hostname":"smoke-sensor","arch":"amd64","mode":"span"}' "$GATEWAY_URL/api/v1/sensors/enroll")"
API_KEY="$(jget .api_key <<<"$ENROLL")"
SENSOR_ID="$(jget .sensor_id <<<"$ENROLL")"
jget .command_hmac_secret <<<"$ENROLL" >/dev/null
jget .ws_url <<<"$ENROLL" >/dev/null
echo "sensor $SENSOR_ID enrolled"

step "token is single use"
if "${CURL[@]}" -H "x-enrollment-token: $TOKEN" -H 'content-type: application/json' \
    -d '{"hostname":"again","arch":"amd64","mode":"span"}' "$GATEWAY_URL/api/v1/sensors/enroll" >/dev/null 2>&1; then
    fail "enrollment token was accepted twice"
fi

step "ingest a critical Suricata alert from 203.0.113.77"
EVENT='{"source_ip":"203.0.113.77","dest_ip":"10.0.0.5","source_port":40000,"dest_port":22,"protocol":"tcp","event_type":"alert",
 "payload":{"alert":{"severity":1,"signature":"SMOKE TEST exploit","category":"Exploit","signature_id":9000001,"action":"allowed"}}}'
"${CURL[@]}" -H "x-api-key: $API_KEY" -H 'content-type: application/json' -d "$EVENT" "$GATEWAY_URL/api/traffic" | jget '.alerts == 1' >/dev/null

step "alert visible, block proposed"
ALERTS="$("${CURL[@]}" "${AUTH[@]}" "$GATEWAY_URL/api/v1/alerts?ip=203.0.113.77")"
jget '.total >= 1' <<<"$ALERTS" >/dev/null || fail "alert not found"
BLOCK_ID="$("${CURL[@]}" "${AUTH[@]}" "$GATEWAY_URL/api/v1/blocked?status=pending" | jq -er '[.items[] | select(.ip=="203.0.113.77")][0].id')"

step "nothing enforced before approval"
COUNT="$("${CURL[@]}" -H "x-api-key: $API_KEY" "$GATEWAY_URL/api/prevention/blocked" | jq '[.data[] | select(.ip=="203.0.113.77")] | length')"
[ "$COUNT" = "0" ] || fail "block active before approval"

step "approve"
"${CURL[@]}" "${AUTH[@]}" -X POST "$GATEWAY_URL/api/v1/blocked/$BLOCK_ID/approve" | jget '.status == "active"' >/dev/null

step "sensor sync lists the block"
"${CURL[@]}" -H "x-api-key: $API_KEY" "$GATEWAY_URL/api/prevention/blocked" \
    | jq -e '[.data[] | select(.ip=="203.0.113.77")] | length == 1' >/dev/null || fail "block missing from sensor sync"

step "cleanup"
"${CURL[@]}" "${AUTH[@]}" -X DELETE "$GATEWAY_URL/api/v1/blocked/$BLOCK_ID" >/dev/null
"${CURL[@]}" "${AUTH[@]}" -X DELETE "$CONSOLE_URL/api/sensors/$SENSOR_ID" >/dev/null || true

printf '\nSMOKE TEST PASSED\n'
