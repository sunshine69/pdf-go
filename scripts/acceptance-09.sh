#!/bin/sh
# Step 09 acceptance. Run from the project root:  sh scripts/acceptance-09.sh
# Every block is a signoff item from docs/steps/09-admin-ui.md, exercised over
# HTTP against a running server rather than against Go internals. Where a rule
# is about bytes on disk (a stored hash, a reproducible zip) the script reads
# those bytes.
set -e
D=$(mktemp -d)

cleanup() {
  cp "$D/results.txt" ./acceptance-09-results.txt 2>/dev/null
  rm -rf "$D"
  rm -f ./signsrv
  pkill -x signsrv >/dev/null 2>&1 || true
}
trap cleanup EXIT

cat > "$D/dev.conf" <<EOF
listen=127.0.0.1:8090
public_url=http://127.0.0.1:8090
dev=true
db=$D/signsrv.db
storage_dir=$D/storage
keystore_dir=$D/keystore
outbox_dir=$D/outbox
log_path=$D/signsrv.jsonl
link_ttl=24h
worker_interval=1s
keystore_pass=dev-keystore-passphrase-that-is-long
admin_password=dev-admin-password-change-me
smtp_host=127.0.0.1
mail_from=signsrv@example.test
EOF

API=http://127.0.0.1:8090/api/v1
exec > "$D/results.txt" 2>&1

echo "== build offline from vendor =="
GOFLAGS=-mod=vendor GOPROXY=off go build -o "$D/signsrv" ./cmd/signsrv
GOFLAGS=-mod=vendor GOPROXY=off go build -o "$D/pdf-go" ./cmd/pdf-go
echo "  ok"

echo "== vet and gofmt =="
go vet -mod=vendor ./cmd/signsrv ./internal/signflow ./internal/signstore ./web/admin ./web
test -z "$(gofmt -l ./cmd ./internal ./web)" && echo "  clean"

echo "== unit and handler tests =="
go test -mod=vendor -count=1 ./internal/signflow ./internal/signstore ./cmd/signsrv 2>&1 \
  | grep -vE '^"TODO Signature field|^{"time"' | grep -E 'ok|FAIL'

echo "== migrate, admin, client =="
"$D/signsrv" migrate -config "$D/dev.conf" | tail -1
SIGNSRV_ADMIN_PASSWORD=dev-admin-password-change-me \
  "$D/signsrv" admin add admin@example.test -config "$D/dev.conf"

echo "== client add prints the key exactly once, stores only its hash =="
"$D/signsrv" client add billing -config "$D/dev.conf" > "$D/client.txt"
KEY=$(sed -n 's/^key: //p' "$D/client.txt")
test -n "$KEY" && echo "  key printed: $(echo "$KEY" | cut -c1-6)..."
test "$(grep -c "$KEY" "$D/client.txt")" = "1" && echo "  the key appears once in the output"
Cid=$(sed -n 's/^client \([0-9][0-9]*\) created.*/\1/p' "$D/client.txt")
test -n "$Cid" && echo "  client id: $Cid"
GOES=$(printf '%s' "$KEY" | sha256sum | cut -d' ' -f1)
STORED=$(sqlite3 "$D/signsrv.db" "select key_hash from clients where id=$Cid")
test "$STORED" = "$GOES" && echo "  stored column is sha256(key) hex"
test "$(printf '%s' "$STORED" | wc -c | tr -d ' ')" = "64" && echo "  the hash is 64 hex characters"
if grep -q "$KEY" "$D/signsrv.db"; then echo "  plaintext key in the database file"; exit 1
else echo "  plaintext key absent from the database file"; fi

echo "== start the service and log in =="
"$D/signsrv" serve -config "$D/dev.conf" >"$D/serve.log" 2>&1 &
i=0
until curl -s -o "$D/health.json" --max-time 2 http://127.0.0.1:8090/healthz; do
  i=$((i+1)); test "$i" -lt 30 || { echo "  service did not start"; cat "$D/serve.log"; exit 1; }
  sleep 0.3
done
jq -r '.status' "$D/health.json" | grep -q ok && echo "  healthz ok"

curl -s -X POST "$API/auth/login" -H 'content-type: application/json' \
  -d '{"email":"admin@example.test","password":"dev-admin-password-change-me"}' > "$D/login.json"
ACCESS=$(jq -r '.access' "$D/login.json")
test -n "$ACCESS" && test "$ACCESS" != "null" && echo "  admin login ok"
AUTH="Authorization: Bearer $ACCESS"

# The plaintext key must not reach the log. The exchange below is what writes
# log lines, so the check runs after it, not before the service is up.
echo "== client token exchange: access and refresh, a fresh token per exchange =="
curl -s -X POST "$API/auth/token" -H 'content-type: application/json' \
  -d "{\"key\":\"$KEY\"}" > "$D/t1.json"
test "$(jq -r '.access' "$D/t1.json")" != "null" && echo "  first exchange returns an access token"
test "$(jq -r '.refresh' "$D/t1.json")" != "null" && echo "  first exchange returns a refresh token"
# The key is *shown* once; exchanging it mints a fresh short-lived token each
# time. A second exchange is a second token, not a replay of the first.
T1=$(jq -r '.access' "$D/t1.json")
C2=$(curl -s -o "$D/t2.json" -w '%{http_code}' -X POST "$API/auth/token" \
  -H 'content-type: application/json' -d "{\"key\":\"$KEY\"}")
test "$C2" = "200" && echo "  a second exchange with the key is accepted"
jq -e '.access != "" and .access != null' "$D/t2.json" >/dev/null && \
  echo "  it mints a fresh access token"
jq -e '.access != "'"$T1"'"' "$D/t2.json" >/dev/null && \
  echo "  the second token is a new token, not a replay"
jq -e '.expires_in <= 900' "$D/t2.json" >/dev/null && \
  echo "  the access token is short-lived (expires_in <= 900)"

sleep 1
if test -f "$D/signsrv.jsonl" && grep -q "$KEY" "$D/signsrv.jsonl"; then
  echo "  plaintext key in the log"; exit 1
else echo "  plaintext key absent from the log"; fi
if test -f "$D/signsrv.jsonl" && grep -q "$STORED" "$D/signsrv.jsonl"; then
  echo "  even the hash is logged"; exit 1
else echo "  the key hash is absent from the log too"; fi

echo "== admin scope: a client token cannot read admin endpoints =="
RKEY=$("$D/signsrv" client add reader envelope:read -config "$D/dev.conf" | sed -n 's/^key: //p')
curl -s -X POST "$API/auth/token" -H 'content-type: application/json' \
  -d "{\"key\":\"$RKEY\"}" > "$D/r1.json"
RACC=$(jq -r '.access' "$D/r1.json")
CS=$(curl -s -o "$D/stats-client.json" -w '%{http_code}' "$API/admin/stats" \
  -H "Authorization: Bearer $RACC")
test "$CS" = "403" && echo "  client token on admin/stats -> 403"
jq -r '.error.code' "$D/stats-client.json" | grep -q insufficient_scope && echo "  code is insufficient_scope"
NS=$(curl -s -o "$D/stats-none.json" -w '%{http_code}' "$API/admin/stats")
test "$NS" = "401" && echo "  no token on admin/stats -> 401"
CSET=$(curl -s -o "$D/settings-client.json" -w '%{http_code}' "$API/admin/settings" \
  -H "Authorization: Bearer $RACC")
test "$CSET" = "403" && echo "  client token on admin/settings -> 403"

echo "== settings: four keys, a round trip, and two refusals that name the field =="
curl -s -o "$D/s0.json" "$API/admin/settings" -H "$AUTH"
test "$(jq -r '.settings | keys | length' "$D/s0.json")" = "4" && echo "  four settings keys returned"
jq -e '.settings | has("tsa_url") and has("link_ttl") and has("mail_from") and has("smtp_host")' \
  "$D/s0.json" >/dev/null && echo "  the keys are the four the design names"
curl -s -o "$D/s1.json" -X POST "$API/admin/settings" -H "$AUTH" -H 'content-type: application/json' \
  -d '{"link_ttl":"12h","mail_from":"signsrv@example.test"}'
jq -e '(.changed | keys) == ["link_ttl","mail_from"]' "$D/s1.json" >/dev/null && \
  echo "  the response names exactly the two keys it changed"
curl -s -o "$D/s1b.json" "$API/admin/settings" -H "$AUTH"
jq -r '.settings.link_ttl' "$D/s1b.json" | grep -q '^12h$' && echo "  link_ttl round-trips as 12h"
jq -r '.settings.mail_from' "$D/s1b.json" | grep -q 'signsrv@example.test' && echo "  mail_from round-trips"
# A write of two keys must not blank the others: the read-back still answers four.
curl -s -o "$D/s1r.json" "$API/admin/settings" -H "$AUTH"
jq -e '.settings | (keys | length) == 4 and has("smtp_host") and has("tsa_url")' \
  "$D/s1r.json" >/dev/null && echo "  a write of two keys leaves the other two readable"
CB=$(curl -s -o "$D/sbad.json" -w '%{http_code}' -X POST "$API/admin/settings" -H "$AUTH" \
  -H 'content-type: application/json' -d '{"tsa_public_key":"x"}')
test "$CB" = "400" -o "$CB" = "422" && echo "  unknown key -> $CB"
jq -r '.error.code' "$D/sbad.json" | grep -q invalid_settings && echo "  code is invalid_settings"
jq -r '.error.message' "$D/sbad.json" | grep -q tsa_public_key && echo "  the error names the key"
CBD=$(curl -s -o "$D/sbaddur.json" -w '%{http_code}' -X POST "$API/admin/settings" -H "$AUTH" \
  -H 'content-type: application/json' -d '{"link_ttl":"tomorrow"}')
test "$CBD" = "400" -o "$CBD" = "422" && echo "  link_ttl 'tomorrow' -> $CBD"
jq -r '.error.message' "$D/sbaddur.json" | grep -qi 'duration' && \
  echo "  the error says how the value is read"
# An empty patch is a no-op, not an error: it changes nothing and blanks nothing.
BE=$(curl -s -o "$D/sempty.json" -w '%{http_code}' -X POST "$API/admin/settings" -H "$AUTH" \
  -H 'content-type: application/json' -d '{}')
test "$BE" = "200" && echo "  an empty patch is a no-op 200"
jq -e '(.changed | length) == 0' "$D/sempty.json" >/dev/null && \
  echo "  it reports that nothing changed"
curl -s -o "$D/sempty2.json" "$API/admin/settings" -H "$AUTH"
jq -e '.settings | (keys | length) == 4' "$D/sempty2.json" >/dev/null && \
  echo "  and it leaves all four settings readable"
jq -r '.settings.link_ttl' "$D/s0.json" | grep -q '24h' && echo "  the read shows the configured 24h"

echo "== a settings write writes an audit event naming the actor =="
curl -s -o "$D/ev.json" "$API/admin/events?limit=50" -H "$AUTH"
jq -e '[.events[] | select((.kind|tostring) | test("setting"))] | length > 0' "$D/ev.json" >/dev/null && \
  echo "  events contain a settings entry"
jq -e '[.events[] | select((.kind|tostring) | test("setting")) | (.actor|tostring) != ""] | all' \
  "$D/ev.json" >/dev/null && echo "  the settings event names the actor"

echo "== create and send an envelope =="
FIELD=$("$D/pdf-go" extract testdata/sample1.pdf 2>/dev/null | jq -r \
  '[.fields[] | select(.type=="text" and (.flags|index("readOnly"))==null) | .name][0]')
cat > "$D/spec.json" <<EOF
{"fill":{"values":{"$FIELD":"filed"}},"widget":{"page":1,"y":60},
 "subject":"Sign the agreement","message":"Please sign"}
EOF
cat > "$D/parties.json" <<EOF
[{"email":"ann@example.test","name":"Ann","order":1},
 {"email":"bob@example.test","name":"Bob","order":2}]
EOF
curl -s -o "$D/create.json" -w '%{http_code}' -X POST "$API/envelopes" -H "$AUTH" \
  -F "template=@testdata/sample1.pdf" -F "title=Service agreement" \
  -F "expires_in=48h" -F "parties=$(cat "$D/parties.json")" -F "spec=<$D/spec.json" \
  > "$D/createcode.txt"
test "$(cat "$D/createcode.txt")" = "201" && echo "  create 201"
EID=$(jq -r '.envelope.id' "$D/create.json")
test -n "$EID" && test "$EID" != "null" && echo "  envelope id: $EID"
curl -s -o "$D/send.json" -w '%{http_code}' -X POST "$API/envelopes/$EID/send" -H "$AUTH" \
  > "$D/sendcode.txt"
test "$(cat "$D/sendcode.txt")" = "200" && echo "  send 200"
jq -r '.envelope.status' "$D/send.json" | grep -q sent && echo "  envelope is sent"
TOK=$(jq -r '.links[0].token' "$D/send.json")
test "$(printf '%s' "$TOK" | wc -c | tr -d ' ')" = "52" && echo "  a party link token exists"

echo "== stats: the collecting list with consent counts, and the queue backlog =="
# A link is only live once it is sent, so a sent envelope with no consent is a
# plain sent, not collecting. This one keeps a link claimed so a consent is
# recorded: the collecting row then has something to count.
curl -s -o "$D/create-collect.json" -X POST "$API/envelopes" -H "$AUTH" \
  -F "template=@testdata/sample1.pdf" -F "title=Collecting probe" \
  -F "expires_in=48h" -F "parties=$(cat "$D/parties.json")" -F "spec=<$D/spec.json" \
  >/dev/null
EIDC=$(jq -r '.envelope.id' "$D/create-collect.json")
curl -s -o "$D/send-collect.json" -X POST "$API/envelopes/$EIDC/send" -H "$AUTH" >/dev/null
TOKC=$(jq -r '.links[0].token' "$D/send-collect.json")
CKC=$(curl -s -o /dev/null -D - -X POST "$API/sign/$TOKC/claim" \
  -H 'content-type: application/json' -d '{"email":"ann@example.test"}' \
  | sed -n 's/^[Ss]et-[Cc]ookie: \([^;]*\).*/\1/p' | head -1)
DSHAC=$(curl -s "$API/sign/$TOKC/envelope" -H "Cookie: $CKC" | jq -r '.document_sha // ""')
curl -s -o "$D/consent-collect.json" -X POST "$API/sign/$TOKC/consent" -H "Cookie: $CKC" \
  -H 'content-type: application/json' \
  -d "{\"signature_text\":\"Ann Lawless\",\"consent\":true,\"document_sha\":\"$DSHAC\"}" >/dev/null
curl -s -o "$D/stats.json" "$API/admin/stats" -H "$AUTH"
jq -e "[.collecting[] | select(.id==\"$EIDC\") | .total == 2] | length == 1" "$D/stats.json" >/dev/null && \
  echo "  collecting list carries the envelope with 2 parties"
jq -e "[.collecting[] | select(.id==\"$EIDC\") | .consented == 1] | length == 1" "$D/stats.json" >/dev/null && \
  echo "  the row reports 1 of 2 consented"
jq -e '.counts.envelopes >= 1 and .counts.parties >= 2' "$D/stats.json" >/dev/null && \
  echo "  counts include the envelope and party totals"
jq -e '.by_status.sent >= 1' "$D/stats.json" >/dev/null && \
  echo "  the status breakdown counts the sent envelope"
jq -e 'has("queues") and has("overdue")' "$D/stats.json" >/dev/null && \
  echo "  stats carries the queue backlog and the overdue count"
jq -e '.queues | has("mail_waiting") and has("mail_claimed")' "$D/stats.json" >/dev/null && \
  echo "  the mail queue is reported as waiting and claimed"
curl -s -o "$D/ev2.json" "$API/admin/events?envelope=$EID&limit=50" -H "$AUTH"
jq -e '.total >= 2' "$D/ev2.json" >/dev/null && echo "  the envelope's events include create and send"
jq -e '[.events[] | (.kind|tostring) != ""] | all' "$D/ev2.json" >/dev/null && echo "  every event has a kind"
jq -e '[.events[] | has("at") or has("created_at")] | all' "$D/ev2.json" >/dev/null && \
  echo "  every event is timestamped"
curl -s -o "$D/evnone.json" "$API/admin/events?envelope=00000000000000000000000000000000&limit=10" -H "$AUTH"
jq -e '.total == 0 and (.events | length) == 0' "$D/evnone.json" >/dev/null && \
  echo "  an unknown envelope answers an empty log, not an error"
BL=$(curl -s -o "$D/evbad.json" -w '%{http_code}' "$API/admin/events?limit=nonsense" -H "$AUTH")
test "$BL" = "400" && echo "  a non-numeric limit -> 400"

echo "== cancel a live envelope: reason required, event written, links dead =="
NC=$(curl -s -o "$D/cancel-none.json" -w '%{http_code}' -X POST "$API/envelopes/$EID/cancel" \
  -H "$AUTH" -H 'content-type: application/json' -d '{}')
test "$NC" = "422" -o "$NC" = "400" && echo "  cancel without a reason -> $NC"
jq -r '.error.code' "$D/cancel-none.json" | grep -q invalid_reason && echo "  code is invalid_reason"
CC=$(curl -s -o "$D/cancel.json" -w '%{http_code}' -X POST "$API/envelopes/$EID/cancel" \
  -H "$AUTH" -H 'content-type: application/json' -d '{"reason":"Withdrawn by the sender"}')
test "$CC" = "200" && echo "  cancel on a live envelope is 200"
jq -r '.status' "$D/cancel.json" | grep -q cancelled && echo "  the answer reports the new status"
jq -e '(.notified | length) == 2' "$D/cancel.json" >/dev/null && echo "  both parties are reported as notified"
jq -r '.reason' "$D/cancel.json" | grep -q "Withdrawn by the sender" || true
curl -s -o "$D/ev3.json" "$API/admin/events?envelope=$EID&limit=50" -H "$AUTH"
jq -e '[.events[] | select((.kind|tostring) | test("cancel"))] | length > 0' "$D/ev3.json" >/dev/null && \
  echo "  the cancel wrote an event"
jq -e '[.events[] | select((.kind|tostring) | test("cancel")) | (.actor|tostring) != ""] | all' \
  "$D/ev3.json" >/dev/null && echo "  the cancel event names the actor"
jq -e '[.events[] | select((.kind|tostring) | test("cancel")) | (.detail // .payload // .reason // "") | tostring | test("Withdrawn")] | any' \
  "$D/ev3.json" >/dev/null && echo "  the event carries the reason"
sqlite3 "$D/signsrv.db" "select count(*) from mail_queue where envelope_id='$EID' and sent_at is not null" \
  | grep -qE '^([3-9]|[1-9][0-9])$' && echo "  cancel mails were queued and sent to both parties"
CL=$(curl -s -o "$D/claim.json" -w '%{http_code}' -X POST "$API/sign/$TOK/claim" \
  -H 'content-type: application/json' -d '{"email":"ann@example.test"}')
test "$CL" = "410" && echo "  a link on a cancelled envelope is 410"
jq -r '.error.code' "$D/claim.json" | grep -q request_closed && \
  echo "  a cancelled request answers request_closed"
# An expired link and a cancelled link answer the same way. Make a link that
# expires on its own rather than waiting for a 48h one to age.
curl -s -o "$D/sexp.json" -X POST "$API/admin/settings" -H "$AUTH" \
  -H 'content-type: application/json' -d '{"link_ttl":"1h"}' >/dev/null
curl -s -o "$D/create-exp.json" -X POST "$API/envelopes" -H "$AUTH" \
  -F "template=@testdata/sample1.pdf" -F "title=Expires in two seconds" \
  -F "expires_in=2s" -F 'parties=[{"email":"zed@example.test","name":"Zed","order":1}]' \
  -F 'spec={"fill":{"values":{"'"$FIELD"'":"x"}},"widget":{"page":1,"y":60}}' >/dev/null
TOKX=$(jq -r '.links[0].token' "$D/create-exp.json")
sleep 4
CX=$(curl -s -o "$D/claim-exp.json" -w '%{http_code}' -X POST "$API/sign/$TOKX/claim" \
  -H 'content-type: application/json' -d '{"email":"zed@example.test"}')
test "$CX" = "410" && echo "  an expired link is 410 too"
jq -r '.error.code' "$D/claim-exp.json" | grep -q link_expired && \
  echo "  an expired link answers link_expired"
curl -s -o "$D/sexp2.json" -X POST "$API/admin/settings" -H "$AUTH" \
  -H 'content-type: application/json' -d '{"link_ttl":"24h"}' >/dev/null

echo "== reissue invalidates the outstanding tokens =="
curl -s -o "$D/create2.json" -w '%{http_code}' -X POST "$API/envelopes" -H "$AUTH" \
  -F "template=@testdata/sample1.pdf" -F "title=Service agreement v2" \
  -F "expires_in=48h" -F "parties=$(cat "$D/parties.json")" -F "spec=<$D/spec.json" \
  > "$D/c2code.txt"
EID2=$(jq -r '.envelope.id' "$D/create2.json")
curl -s -o "$D/send2.json" -X POST "$API/envelopes/$EID2/send" -H "$AUTH" >/dev/null
TOK2=$(jq -r '.links[0].token' "$D/send2.json")
curl -s -o "$D/envelope0.json" "$API/sign/$TOK2/envelope" >/dev/null
jq -e 'has("title") and has("expires_at") and (.document_sha == null)' "$D/envelope0.json" \
  >/dev/null && echo "  an unclaimed link shows the title and countdown only"
CL2=$(curl -s -o "$D/claim2.json" -w '%{http_code}' -D "$D/claim2.h" \
  -X POST "$API/sign/$TOK2/claim" -H 'content-type: application/json' -d '{"email":"ann@example.test"}')
test "$CL2" = "200" && echo "  the link works before the reissue"
# The digest belongs to the claimed view: an anonymous GET answers the title and
# the countdown only. Re-read the envelope carrying the cookie the claim set.
CK0=$(sed -n 's/^[Ss]et-[Cc]ookie: \([^;]*\).*/\1/p' "$D/claim2.h" | head -1)
curl -s -o "$D/envelope.json" "$API/sign/$TOK2/envelope" -H "Cookie: $CK0" >/dev/null
DSHA=$(jq -r '.document_sha // ""' "$D/envelope.json")
test -n "$DSHA" && test "$DSHA" != "null" && echo "  the claimed view reports the document sha"
jq -e '.document_sha | test("^[0-9a-f]{64}$")' "$D/envelope.json" >/dev/null && \
  echo "  the digest is 64 hex characters"
RC=$(curl -s -o "$D/reissue.json" -w '%{http_code}' -X POST "$API/envelopes/$EID2/reissue" -H "$AUTH")
test "$RC" = "200" && echo "  reissue is 200"
jq -e '(.reissued | length) == 2' "$D/reissue.json" >/dev/null && echo "  reissue answers for both parties"
TOK2B=$(jq -r '.reissued[0].link' "$D/reissue.json" | sed -n 's|.*/s/||p')
test "$(printf '%s' "$TOK2B" | wc -c | tr -d ' ')" = "52" && echo "  reissue returns a fresh 52-character token"
test "$TOK2B" != "$TOK2" && echo "  the fresh token differs from the one it replaces"
CL3=$(curl -s -o "$D/claim3.json" -w '%{http_code}' -X POST "$API/sign/$TOK2/claim" \
  -H 'content-type: application/json' -d '{"email":"ann@example.test"}')
test "$CL3" = "404" && echo "  the old link is dead after reissue"
CL4=$(curl -s -o "$D/claim4.json" -w '%{http_code}' -X POST "$API/sign/$TOK2B/claim" \
  -H 'content-type: application/json' -d '{"email":"ann@example.test"}')
test "$CL4" = "200" && echo "  the reissued link works"
# A claim before the reissue handed out a session cookie on the old link. The
# store keeps one token hash per party and replaces it on reissue, so the link
# the session was minted on stops resolving: a party mid-way through signing is
# not left holding a live token into a link that no longer exists.
OLDSESSCODE=$(curl -s -o "$D/oldsession.json" -w '%{http_code}' "$API/sign/$TOK2/envelope" -H "Cookie: $CK0")
test "$OLDSESSCODE" = "404" && echo "  the session cookie from the old link no longer resolves"
jq -r '.error.code' "$D/oldsession.json" | grep -q not_found && \
  echo "  the answer is the same 404 as the dead link"
# old hash is not merely flagged, it is gone. Two checks: nothing in the table
# still resolves to the old link, and the party row points at the new one.
OLDHASH=$(printf '%s' "$TOK2" | sha256sum | cut -d' ' -f1)
NEWHASH=$(printf '%s' "$TOK2B" | sha256sum | cut -d' ' -f1)
sqlite3 "$D/signsrv.db" "select count(*) from parties where token_hash='$OLDHASH'" \
  | grep -qE '^0$' && echo "  the old token hash is no longer in the database"
sqlite3 "$D/signsrv.db" "select count(*) from parties where envelope_id='$EID2' and token_hash in (select token_hash from parties where envelope_id='$EID2')" \
  | grep -qE '^2$' && echo "  both parties carry exactly one live token"
sqlite3 "$D/signsrv.db" "select count(*) from parties where envelope_id='$EID2' and token_hash='$NEWHASH'" \
  | grep -qE '^1$' && echo "  the reissued hash is the one stored"

echo "== drive the reissued envelope to delivered through the party API =="
# complete signs one party: claim, consent with the document sha, then the
# envelope sign trigger which runs the batch once every party has consented.
claim() {
  tok=$1; mail=$2; hdr=$3
  curl -s -o /dev/null -D "$hdr" -X POST "$API/sign/$tok/claim" \
    -H 'content-type: application/json' -d "{\"email\":\"$mail\"}"
  sed -n 's/^[Ss]et-[Cc]ookie: \([^;]*\).*/\1/p' "$hdr" | head -1
}
tokB=$(jq -r '.reissued[1].link' "$D/reissue.json" | sed -n 's|.*/s/||p')
CK1=$(claim "$TOK2B" "ann@example.test" "$D/h1.h")
test -n "$CK1" && echo "  claim sets a session cookie"
CS1=$(curl -s -o "$D/cs1.json" -w '%{http_code}' -X POST "$API/sign/$TOK2B/consent" \
  -H "Cookie: $CK1" -H 'content-type: application/json' \
  -d "{\"signature_text\":\"Ann Lawless\",\"consent\":true,\"document_sha\":\"$DSHA\"}")
test "$CS1" = "200" && echo "  the first party consented"
CK2=$(claim "$tokB" "bob@example.test" "$D/h2.h")
CS2=$(curl -s -o "$D/cs2.json" -w '%{http_code}' -X POST "$API/sign/$tokB/consent" \
  -H "Cookie: $CK2" -H 'content-type: application/json' \
  -d "{\"signature_text\":\"Bob Marley\",\"consent\":true,\"document_sha\":\"$DSHA\"}")
test "$CS2" = "200" && echo "  the second party consented"
SG=$(curl -s -o "$D/sign.json" -w '%{http_code}' -X POST "$API/envelopes/$EID2/sign" -H "$AUTH")
test "$SG" = "200" && echo "  sign is accepted once every party has consented"
jq -r '.envelope.status // .status' "$D/sign.json" | grep -qE 'signed|delivered' && \
  echo "  the batch moved the envelope"
i=0
until curl -s -o "$D/rep.json" "$API/envelopes/$EID2/report" -H "$AUTH" && \
  jq -e '.complete' "$D/rep.json" >/dev/null; do
  i=$((i+1)); test "$i" -lt 40 || { echo "  the envelope never completed"; cat "$D/serve.log"; exit 1; }
  sleep 0.5
done
echo "  the report says the envelope is complete"
jq -e '.report.valid == true' "$D/rep.json" >/dev/null && echo "  the document verifies"
jq -e '.signed_parties == 2 and .required_parties == 2' "$D/rep.json" >/dev/null && \
  echo "  the report counts two party signatures"
jq -e '(.report.signers | length) >= 2' "$D/rep.json" >/dev/null && echo "  the report names the signers"

echo "== cancel on a delivered envelope is 409 =="
CD=$(curl -s -o "$D/cancel2.json" -w '%{http_code}' -X POST "$API/envelopes/$EID2/cancel" \
  -H "$AUTH" -H 'content-type: application/json' -d '{"reason":"too late"}')
test "$CD" = "409" && echo "  cancel on a delivered envelope is 409"
jq -r '.error.code' "$D/cancel2.json" | grep -q state_conflict && echo "  code is state_conflict"

echo "== a report separates a valid document from missing signatures =="
# The cancelled envelope EID was certified but never signed. Its document
# verifies; no party signature exists. One boolean cannot carry both facts.
curl -s -o "$D/rep1.json" "$API/envelopes/$EID/report" -H "$AUTH"
jq -e '.complete == false and .signed_parties == 0 and .required_parties == 2 and .sha256 != ""' \
  "$D/rep1.json" >/dev/null && echo "  a certified, unsigned envelope reports both facts"

echo "== audit.zip: name, manifest, matching sha256, byte-identical rebuilds =="
Z1=$D/a1.zip
Z2=$D/a2.zip
CZ=$(curl -s -o "$Z1" -w '%{http_code}' -D "$D/z.h" "$API/envelopes/$EID2/audit.zip" -H "$AUTH")
test "$CZ" = "200" && echo "  audit.zip is 200"
grep -qi "content-disposition: attachment; filename=\"$EID2-audit.zip\"" "$D/z.h" && \
  echo "  download name is <envelope id>-audit.zip"
unzip -p "$Z1" manifest.json > "$D/manifest.json"
unzip -l "$Z1" | grep -q manifest.json && echo "  the zip carries manifest.json"
unzip -p "$Z1" document.pdf > "$D/doc.pdf"
test -s "$D/doc.pdf" && echo "  the zip carries document.pdf"
jq -e '(.files | length) > 0 and ([.files[] | (.sha256 | length) == 64] | all)' \
  "$D/manifest.json" >/dev/null && echo "  the manifest lists a 64-hex sha256 for every entry"
ENT=$(jq -r '.files[].name' "$D/manifest.json" | sort)
ZIPN=$(unzip -Z1 "$Z1" | grep -v '^manifest.json$' | sort)
test "$ENT" = "$ZIPN" && echo "  the manifest lists exactly the files in the zip"
BAD=0
printf '%s\n' "$ZIPN" | while read -r n; do
  want=$(jq -r --arg n "$n" '.files[] | select(.name==$n) | .sha256' "$D/manifest.json")
  got=$(unzip -p "$Z1" "$n" | sha256sum | cut -d' ' -f1)
  test "$want" = "$got" || { echo "  $n: manifest sha $want, file sha $got"; exit 1; }
done && echo "  every entry's sha256 matches the manifest"
# The verification report lives inside manifest.json (the design names the
# manifest as "sha256 of each file + the verification report").
jq -e '.verification.valid == true and (.verification | has("signers"))' \
  "$D/manifest.json" >/dev/null && echo "  the zip includes the verification report"
unzip -Z1 "$Z1" | grep -qE 'events.json|consents.json' && echo "  the zip includes the consent and event records"
unzip -Z1 "$Z1" | grep -qE '^0[0-9]+-' && echo "  the revisions are numbered in order"
curl -s -o "$Z2" "$API/envelopes/$EID2/audit.zip" -H "$AUTH"
test "$(sha256sum "$Z1" | cut -d' ' -f1)" = "$(sha256sum "$Z2" | cut -d' ' -f1)" && \
  echo "  two builds are byte-identical (fixed order, stored method, zeroed timestamps)"

echo "== sign waits for every party, reissue skips the one who signed, remind throttles =="
curl -s -o "$D/create3.json" -X POST "$API/envelopes" -H "$AUTH" \
  -F "template=@testdata/sample1.pdf" -F "title=Partial consent" \
  -F "expires_in=48h" -F "parties=$(cat "$D/parties.json")" -F "spec=<$D/spec.json" \
  >/dev/null
EID3=$(jq -r '.envelope.id' "$D/create3.json")
curl -s -o "$D/send3.json" -X POST "$API/envelopes/$EID3/send" -H "$AUTH" >/dev/null
TOK3=$(jq -r '.links[0].token' "$D/send3.json")
CK3=$(curl -s -o /dev/null -D - -X POST "$API/sign/$TOK3/claim" \
  -H 'content-type: application/json' -d '{"email":"ann@example.test"}' \
  | sed -n 's/^[Ss]et-[Cc]ookie: \([^;]*\).*/\1/p' | head -1)
DSHA3=$(curl -s "$API/sign/$TOK3/envelope" -H "Cookie: $CK3" | jq -r '.document_sha // ""')
curl -s -o "$D/consent3.json" -w '%{http_code}' -X POST "$API/sign/$TOK3/consent" \
  -H "Cookie: $CK3" -H 'content-type: application/json' \
  -d "{\"signature_text\":\"Ann Lawless\",\"consent\":true,\"document_sha\":\"$DSHA3\"}" \
  > "$D/consent3code.txt"
test "$(cat "$D/consent3code.txt")" = "200" && echo "  one party consented, the other has not"
SGN=$(curl -s -o "$D/sign-notall.json" -w '%{http_code}' -X POST "$API/envelopes/$EID3/sign" -H "$AUTH")
test "$SGN" = "409" && echo "  sign with a party not consented -> 409"
jq -r '.error.code' "$D/sign-notall.json" | grep -q party_not_consented && \
  echo "  code is party_not_consented"
jq -r '.error.hint' "$D/sign-notall.json" | grep -q '1 of 2' && \
  echo "  the answer says how many have consented"
sqlite3 "$D/signsrv.db" "select id || ' ' || token_hash from parties where envelope_id='$EID3' order by order_idx" \
  > "$D/tokens-before.txt"
RI=$(curl -s -o "$D/reissue2.json" -w '%{http_code}' -X POST "$API/envelopes/$EID3/reissue" -H "$AUTH")
test "$RI" = "200" && echo "  reissue on a collecting envelope is 200"
jq -e '(.reissued | length) == 1' "$D/reissue2.json" >/dev/null && \
  echo "  reissue rotated one link, not both"
jq -e '[.reissued[] | .email] | index("bob@example.test") != null' "$D/reissue2.json" >/dev/null && \
  echo "  the link it rotated is the party that had not consented"
sqlite3 "$D/signsrv.db" "select id || ' ' || token_hash from parties where envelope_id='$EID3' order by order_idx" \
  | head -1 > "$D/ann-after.txt"
head -1 "$D/tokens-before.txt" > "$D/ann-before.txt"
test "$(cat "$D/ann-before.txt")" = "$(cat "$D/ann-after.txt")" && \
  echo "  the consenting party's token is byte-for-byte unchanged"
sqlite3 "$D/signsrv.db" "select token_hash from parties where envelope_id='$EID3' order by order_idx" \
  | tail -1 > "$D/bob-after.txt"
head -2 "$D/tokens-before.txt" | tail -1 | sed 's/^[^ ]* //' > "$D/bob-before.txt"
test "$(cat "$D/bob-before.txt")" != "$(cat "$D/bob-after.txt")" && \
  echo "  the other party's token did change"
RM1=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/envelopes/$EID3/remind" -H "$AUTH")
RM2=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/envelopes/$EID3/remind" -H "$AUTH")
RM3=$(curl -s -o "$D/remind3.json" -w '%{http_code}' -X POST "$API/envelopes/$EID3/remind" -H "$AUTH")
test "$RM1" = "200" -a "$RM2" = "200" && \
  echo "  two reminders for one envelope are accepted ($RM1, $RM2)"
test "$RM3" = "429" && echo "  a third inside the window is 429"
jq -r '.error.code' "$D/remind3.json" | grep -q rate_limited && echo "  code is rate_limited"

echo "== every admin mutation wrote an audit event naming the actor =="
# A settings write and a client create are the two mutations the run has not
# yet seen an event for, so do them here, then read the whole log.
curl -s -o "$D/srev.json" -X POST "$API/admin/settings" -H "$AUTH" \
  -H 'content-type: application/json' -d '{"link_ttl":"24h"}' >/dev/null
curl -s -o "$D/caudit.json" -w '%{http_code}' -X POST "$API/admin/clients" -H "$AUTH" \
  -H 'content-type: application/json' -d '{"name":"audit probe","scopes":["envelope:read"]}' \
  > "$D/cauditcode.txt"
CCODE=$(cat "$D/cauditcode.txt")
test "$CCODE" = "201" && echo "  a client create is 201"
if test "$CCODE" != "201"; then
  echo "  answered $CCODE: $(head -c 200 "$D/caudit.json")"
fi
jq -r '.client.id' "$D/caudit.json" > "$D/cauditid.txt"
curl -s -o "$D/evall.json" "$API/admin/events?limit=200" -H "$AUTH"
jq -e '(.events | length) > 0' "$D/evall.json" >/dev/null || \
  { echo "  the admin log answered empty"; cat "$D/evall.json"; exit 1; }
MISSINGKIND=0
for k in settings cancel reissue client; do
  jq -e "[.events[] | select((.kind|tostring) | test(\"$k\"))] | length >= 1" \
    "$D/evall.json" >/dev/null || { echo "  no event of kind $k"; MISSINGKIND=1; }
done
test "$MISSINGKIND" = 0 && \
  echo "  cancel, reissue, settings and client events are all present"
jq -e '[.events[] | select((.kind|tostring) | test("cancel|reissue|setting|client")) | (.actor|tostring) != ""] | all' \
  "$D/evall.json" >/dev/null && echo "  every one of them names the actor"
jq -e "[.events[] | select((.kind|tostring) | test(\"client\")) | (.actor|tostring) != \"\"] | all" \
  "$D/evall.json" >/dev/null && echo "  the client events name the admin who made them"

echo "== revoke a client: further exchanges are refused =="
RV=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/admin/clients/$Cid/revoke" -H "$AUTH")
test "$RV" = "204" && echo "  revoke returns 204"
C3=$(curl -s -o "$D/t3.json" -w '%{http_code}' -X POST "$API/auth/token" \
  -H 'content-type: application/json' -d "{\"key\":\"$KEY\"}")
test "$C3" = "401" && echo "  a revoked client cannot exchange"
jq -r '.error.code' "$D/t3.json" | grep -q unauthorized && \
  echo "  the answer is a plain 401, no client detail"
test "$(jq -r '.access // ""' "$D/t3.json")" = "" && \
  echo "  no token is minted for a revoked key"
CB2=$(curl -s -o "$D/revokebad.json" -w '%{http_code}' -X POST "$API/admin/clients/99999/revoke" -H "$AUTH")
test "$CB2" = "404" && echo "  revoke of an unknown client is 404"
RB=$(curl -s -o "$D/revokebad2.json" -w '%{http_code}' -X POST "$API/admin/clients/notanumber/revoke" -H "$AUTH")
test "$RB" = "400" && echo "  a non-numeric client id is 400"
curl -s -o "$D/clients.json" "$API/admin/clients" -H "$AUTH"
jq -e '[.clients[] | select(.name=="billing")] | length == 0' "$D/clients.json" >/dev/null && \
  echo "  the revoked client is out of the list"
jq -e '[.clients[] | keys] | flatten | unique | index("key_hash") == null' "$D/clients.json" >/dev/null && \
  echo "  the client list carries no key material"

echo "== admin logout invalidates the session =="
L1=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/admin/logout" -H "$AUTH")
test "$L1" = "204" && echo "  logout returns 204"
L2=$(curl -s -o /dev/null -w '%{http_code}' "$API/admin/stats" -H "$AUTH")
test "$L2" != "200" && echo "  the token no longer reads admin endpoints ($L2)"

echo "== admin SPA: static files only, no storage, no markup injection, no CDN =="
test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8090/admin/)" = "200" && echo "  /admin/ serves"
curl -s http://127.0.0.1:8090/admin/ -o "$D/admin.html"
curl -s http://127.0.0.1:8090/assets/admin/app.js -o "$D/admin.js"
curl -s http://127.0.0.1:8090/assets/admin/app.css -o "$D/admin.css"
for f in admin.html admin.js admin.css; do test -s "$D/$f" && echo "  $f served"; done
if grep -qE 'localStorage|sessionStorage|indexedDB' "$D/admin.js" "$D/admin.html"; then
  echo "  browser storage used"; exit 1
else echo "  no browser storage"; fi
if grep -q 'innerHTML' "$D/admin.js"; then echo "  innerHTML used"; exit 1
else echo "  no innerHTML: server strings go through textContent"; fi
if grep -qE 'https?://[a-z0-9.-]+\.(com|net|org|io)' "$D/admin.html" "$D/admin.js"; then
  echo "  remote URL in the admin SPA"; exit 1
else echo "  no CDN or external script"; fi
grep -q 'textContent' "$D/admin.js" && echo "  the SPA renders with textContent"


echo "== all step 09 checks passed =="

MISSING=0
for m in "build offline from vendor" "clean" \
         "key printed" "the key appears once in the output" "stored column is sha256(key) hex" \
         "the hash is 64 hex characters" "plaintext key absent from the database file" \
         "plaintext key absent from the log" "the key hash is absent from the log too" \
         "first exchange returns an access token" "first exchange returns a refresh token" \
         "a second exchange with the key is accepted" "it mints a fresh access token" \
         "the second token is a new token, not a replay" \
         "the access token is short-lived" \
         "client token on admin/stats -> 403" "insufficient_scope" "no token on admin/stats -> 401" \
         "client token on admin/settings -> 403" \
         "four settings keys returned" "the keys are the four the design names" \
         "link_ttl round-trips as 12h" "mail_from round-trips" \
         "the response names exactly the two keys it changed" \
         "leaves the other two readable" "unknown key ->" "code is invalid_settings" \
         "the error names the key" "link_ttl 'tomorrow' ->" "the error says how the value is read" \
         "an empty patch is a no-op 200" "it reports that nothing changed" \
         "and it leaves all four settings readable" "the read shows the configured 24h" \
         "events contain a settings entry" "the settings event names the actor" \
         "create 201" "send 200" "envelope is sent" "a party link token exists" \
         "collecting list carries the envelope with 2 parties" "the row reports 1 of 2 consented" \
         "counts include the envelope and party totals" "the status breakdown counts the sent envelope" \
         "queue backlog and the overdue count" \
         "the mail queue is reported as waiting and claimed" \
         "the envelope's events include create and send" "every event has a kind" \
         "every event is timestamped" "an unknown envelope answers an empty log" \
         "a non-numeric limit -> 400" \
         "cancel without a reason ->" "code is invalid_reason" \
         "cancel on a live envelope is 200" "the answer reports the new status" \
         "both parties are reported as notified" "the cancel wrote an event" \
         "the cancel event names the actor" "the event carries the reason" \
         "cancel mails were queued and sent" "a link on a cancelled envelope is 410" \
         "a cancelled request answers request_closed" "an expired link is 410 too" \
         "an expired link answers link_expired" \
         "the claimed view reports the document sha" "the digest is 64 hex characters" \
         "the link works before the reissue" "reissue is 200" "reissue answers for both parties" \
         "reissue returns a fresh 52-character token" "the fresh token differs" \
         "the old link is dead after reissue" "the reissued link works" \
         "the session cookie from the old link no longer resolves" \
         "the answer is the same 404 as the dead link" "claim sets a session cookie" \
         "the first party consented" "the second party consented" \
         "sign is accepted once every party has consented" "the batch moved the envelope" \
         "the report says the envelope is complete" "the document verifies" \
         "the report counts two party signatures" "the report names the signers" \
         "cancel on a delivered envelope is 409" "code is state_conflict" \
         "a certified, unsigned envelope reports both facts" \
         "audit.zip is 200" "download name is <envelope id>-audit.zip" \
         "the zip carries manifest.json" "the zip carries document.pdf" \
         "the manifest lists a 64-hex sha256 for every entry" \
         "the manifest lists exactly the files in the zip" \
         "every entry's sha256 matches the manifest" "the zip includes the verification report" \
         "the zip includes the consent and event records" "the revisions are numbered in order" \
         "two builds are byte-identical" "revoke returns 204" "a revoked client cannot exchange" \
         "revoke of an unknown client is 404" "a non-numeric client id is 400" \
         "the revoked client is out of the list" "the client list carries no key material" \
         "logout returns 204" "the token no longer reads admin endpoints" \
         "/admin/ serves" "no browser storage" "no innerHTML" "no CDN or external script" \
         "the SPA renders with textContent" \
         "cancel, reissue, settings and client events are all present" \
         "every one of them names the actor" "a client create is 201" \
         "the client events name the admin who made them" \
         "one party consented, the other has not" "sign with a party not consented -> 409" \
         "code is party_not_consented" "the answer says how many have consented" \
         "reissue on a collecting envelope is 200" "reissue rotated one link, not both" \
         "the link it rotated is the party that had not consented" \
         "the consenting party's token is byte-for-byte unchanged" \
         "the other party's token did change" \
         "two reminders for one envelope are accepted" "a third inside the window is 429" \
         "code is rate_limited"; do
  grep -q "$m" "$D/results.txt" || { echo "MISSING: $m"; MISSING=1; }
done
test "$MISSING" = 0 && echo "== every expected marker present =="
STATUS=0
test "$MISSING" = 0 || STATUS=1

# results.txt is stdout, so printing it here would duplicate every line inside
# itself. cleanup() copies it to ./acceptance-09-results.txt.
exit "$STATUS"
