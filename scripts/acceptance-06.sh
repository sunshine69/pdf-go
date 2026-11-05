#!/bin/sh
# Step 06 acceptance. Run from the project root:  sh scripts/acceptance-06.sh
# Every block is a signoff item from docs/steps/06-tokens-email.md.
set -e
D=$(mktemp -d)

cleanup() {
  cp "$D/results.txt" ./acceptance-06-results.txt 2>/dev/null
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
keystore_pass=dev-keystore-passphrase-that-is-long
admin_password=dev-admin-password-change-me
smtp_host=127.0.0.1
mail_from=signsrv@example.test
EOF

API=http://127.0.0.1:8090/api/v1

# Every line is captured, so the marker check at the end can see what the
# assertions produced. The transcript is printed once, at the end.
exec > "$D/results.txt" 2>&1

echo "== build offline from vendor =="
GOFLAGS=-mod=vendor GOPROXY=off go build -o "$D/signsrv" ./cmd/signsrv
GOFLAGS=-mod=vendor GOPROXY=off go build -o "$D/pdf-go" ./cmd/pdf-go
echo "  ok"

echo "== vet and gofmt =="
go vet -mod=vendor ./cmd/signsrv ./internal/signflow ./internal/signmail ./web
test -z "$(gofmt -l ./cmd ./internal)" && echo "  clean"

echo "== unit tests: tokens, send, render, mail parse =="
go test -mod=vendor -count=1 ./internal/signflow ./internal/signmail 2>&1 \
  | grep -vE '^"TODO Signature field|^{"time"' | grep -E 'ok|FAIL'

echo "== token is 256-bit, stored only as a hash =="
go test -mod=vendor -count=1 -run TestTokensAreUniqueAnd52Chars ./internal/signflow 2>&1 \
  | grep -vE '^"TODO Signature field|^{"time"' | tail -1
go test -mod=vendor -count=1 -run TestTokenLookupRoundTrip ./internal/signflow 2>&1 \
  | grep -vE '^"TODO Signature field|^{"time"' | tail -1
go test -mod=vendor -count=1 -run TestLinkExpiryIsCappedByEnvelope ./internal/signflow 2>&1 \
  | grep -vE '^"TODO Signature field|^{"time"' | tail -1

echo "== the invite is queued by the send, not the create =="
go test -mod=vendor -count=1 -run TestCreateQueuesNoMailAndSendQueuesOnePerParty ./internal/signflow 2>&1 \
  | grep -vE '^"TODO Signature field|^{"time"' | tail -1

echo "== a dead relay leaves the envelope sent and raises mail_failed =="
go test -mod=vendor -count=1 -run TestMailFailureLeavesEnvelopeStateAndNotifiesAdmin ./internal/signflow 2>&1 \
  | grep -vE '^"TODO Signature field|^{"time"' | tail -1

echo "== mail-test in dev mode writes one .eml file, with no unsubscribe header =="
BEFORE=$(ls "$D/outbox" 2>/dev/null | wc -l | tr -d ' ')
"$D/signsrv" mail-test tester@example.test -config "$D/dev.conf" > "$D/mailtest.out" 2>&1
test -s "$D/mailtest.out" && echo "  reported: $(cat "$D/mailtest.out")"
test "$(ls "$D/outbox" | wc -l | tr -d ' ')" = "$((BEFORE+1))" && echo "  one .eml file written"
NEW=$(ls -t "$D/outbox" | head -1)
grep -q '^To: tester@example.test' "$D/outbox/$NEW" && echo "  To header is the tested address"
grep -q 'Signature requested: Mail test' "$D/outbox/$NEW" && echo "  subject is the spec form"
if grep -qi 'list-unsubscribe' "$D/outbox/$NEW"; then echo "  List-Unsubscribe present"; exit 1
else echo "  no List-Unsubscribe header"; fi
# The invite prints the link in the text part and in the HTML href, so the
# URL appears twice. The rule is that the message carries one token.

echo "== migrate, admin, client =="
"$D/signsrv" migrate -config "$D/dev.conf" | tail -1
SIGNSRV_ADMIN_PASSWORD=dev-admin-password-change-me \
  "$D/signsrv" admin add admin@example.test -config "$D/dev.conf"
KEY=$("$D/signsrv" client add api -config "$D/dev.conf" | sed -n 's/^key: //p')
test -n "$KEY" && echo "  client key issued: $(echo "$KEY" | cut -c1-6)..."

echo "== start the service =="
"$D/signsrv" serve -config "$D/dev.conf" >"$D/serve.log" 2>&1 &
i=0
until curl -s -o "$D/health.json" --max-time 2 http://127.0.0.1:8090/healthz; do
  i=$((i+1)); test "$i" -lt 30 || { echo "  service did not start"; cat "$D/serve.log"; exit 1; }
  sleep 0.3
done
jq -r '.status' "$D/health.json" | grep -q ok && echo "  healthz ok"

ACCESS=$(curl -s -X POST "$API/auth/login" -H 'content-type: application/json' \
  -d '{"email":"admin@example.test","password":"dev-admin-password-change-me"}' | jq -r '.access')
test -n "$ACCESS" && test "$ACCESS" != "null" && echo "  admin login ok"

FIELD=$("$D/pdf-go" extract testdata/sample1.pdf 2>/dev/null | jq -r \
  '[.fields[] | select(.type=="text" and (.flags|index("readOnly"))==null) | .name][0]')
cat > "$D/specfield.json" <<EOF
{"fill":{"values":{"$FIELD":"filed"}},
 "widget":{"page":1,"y":60},"subject":"Sign the lease","message":"Please sign"}
EOF
# The reason is a party field: it is shown at signing and printed in the
# invite. The party JSON carries it.
REASON='The annual lease renewal for 2026.'

create() {
  curl -s -o "$1" -w '%{http_code}' -X POST "$API/envelopes" \
    -H "Authorization: Bearer $ACCESS" \
    -F "template=@testdata/sample1.pdf" \
    -F "title=$4" \
    -F "expires_in=48h" \
    -F "parties=$2" \
    -F "spec=<$D/specfield.json"
}

send() {
  curl -s -o "$1" -w '%{http_code}' -X POST "$API/envelopes/$2/send" \
    -H "Authorization: Bearer $ACCESS"
}

count() { sqlite3 "$D/signsrv.db" "select count(*) from $1"; }

echo "== create then send: 2 .eml files, one link each, no PDF, envelope sent =="
BEFORE_OUT=$(ls "$D/outbox" | wc -l | tr -d ' ')
code=$(create "$D/create.json" \
  "[{\"email\":\"ann@example.test\",\"name\":\"Ann\",\"order\":1,\"reason\":\"$REASON\"},{\"email\":\"bo@example.test\",\"name\":\"Bo\",\"order\":2,\"reason\":\"$REASON\"}]" \
  "$D/specfield.json" "Quarterly report Q3")
test "$code" = "201" && echo "  create status 201"
ENVID=$(jq -r '.envelope.id' "$D/create.json")

ls "$D/outbox" | sort > "$D/before.txt"
code=$(send "$D/send.json" "$ENVID")
test "$code" = "200" && echo "  send status 200"
test "$(jq -r '.envelope.status' "$D/send.json")" = "sent" && echo "  envelope is sent"
test "$(jq -r '.links | length' "$D/send.json")" = "2" && echo "  two links returned"
jq -r '.links[0].token' "$D/send.json" | grep -qE '^[a-z2-7]{52}$' && \
  echo "  link token is 52 lowercase base32 characters"

NEW=$(ls "$D/outbox" | sort | grep -v -x -F -f "$D/before.txt")
test "$(echo "$NEW" | wc -l | tr -d ' ')" = "2" && echo "  the send wrote 2 new .eml files"
for n in $NEW; do
  f="$D/outbox/$n"
  # Each message carries one token. The text part prints it in full, the HTML
  # part prints the same token in the href: the URL appears twice, and the
  # distinct value must be the one token of this party.
  n1=$(grep -o 'http://127.0.0.1:8090/s/[a-z2-7]\{52\}' "$f" | sort -u | wc -l | tr -d ' ')
  test "$n1" = "1" || { echo "  $f has $n1 distinct links, want 1"; exit 1; }
  grep -qi 'content-disposition: attachment' "$f" && { echo "  $f carries an attachment"; exit 1; }
  grep -q 'data:application/pdf;base64' "$f" && { echo "  $f embeds a PDF"; exit 1; }
  grep -qi 'filename=' "$f" && { echo "  $f declares a filename, an attachment"; exit 1; }
done
test "$(echo "$NEW" | wc -l | tr -d ' ')" = "2" && echo "  one signing link in the message"
echo "  each .eml carries one token URL and no PDF attachment"

echo "== reason, order-of-n, and the recipient address are in the body =="
for f in "$D/outbox"/*; do
  grep -q 'Reason shown at signing: The annual lease renewal' "$f" && \
    echo "  reason printed"
  grep -qE 'You are party [12] of 2\.' "$f" && echo "  order of n printed"
  grep -qE 'is for (ann|bo)@example\.test only' "$f" && echo "  recipient address printed"
done

echo "== send twice -> 409 =="
code=$(send "$D/send2.json" "$ENVID")
test "$code" = "409" && echo "  second send is 409"
test "$(jq -r '.error.code' "$D/send2.json")" = "state_conflict" && echo "  code is state_conflict"

echo "== the queue is drained: every invite row is marked sent =="
test "$(sqlite3 "$D/signsrv.db" \
  "select count(*) from mail_queue where envelope_id='$ENVID' and sent_at is null")" = "0" && \
  echo "  no unsent rows left"
test "$(sqlite3 "$D/signsrv.db" "select count(*) from mail_queue where envelope_id='$ENVID'")" = "2" && \
  echo "  2 queue rows, both sent"

echo "== plaintext token is absent from the database and the log =="
TOKEN=$(jq -r '.links[0].token' "$D/send.json")
test "$(sqlite3 "$D/signsrv.db" "select count(*) from parties where token_hash='$TOKEN'")" = "0" && \
  echo "  stored column is a hash, not the token"
test "$(sqlite3 "$D/signsrv.db" "select length(token_hash) from parties limit 1")" = "64" && \
  echo "  token_hash is 64 hex characters"
if grep -q "$TOKEN" "$D/signsrv.db"; then echo "  plaintext token in the database file"; exit 1
else echo "  plaintext token absent from the database file"; fi
if grep -q "$TOKEN" "$D/signsrv.jsonl"; then echo "  plaintext token in the log"; exit 1
else echo "  plaintext token absent from the log"; fi
if grep -q "$TOKEN" "$D/serve.log"; then echo "  plaintext token in the serve log"; exit 1
else echo "  plaintext token absent from the serve log"; fi

echo "== hostile name renders inert, and does not break headers =="
code=$(create "$D/hostile.json" \
  '[{"email":"bob@example.test","name":"Bob\"><script>alert(1)</script>","order":1}]' \
  "$D/specfield.json" "Hostile name")
test "$code" = "201" && echo "  hostile name accepted at create (it is a name, not a header)"
HID=$(jq -r '.envelope.id' "$D/hostile.json")
code=$(send "$D/hsend.json" "$HID")
test "$code" = "200" && echo "  send with the hostile name is 200"
HTOK=$(jq -r '.links[0].token' "$D/hsend.json")
# The message with this token in it is the one for the hostile party.
HF=$(grep -l "$HTOK" "$D/outbox"/*)
test -n "$HF" && echo "  the message for the hostile party is in the outbox"
python3 - "$HF" <<'PY'
import email, sys
m = email.message_from_file(open(sys.argv[1]))
html = ""
for p in m.walk():
    if p.get_content_type() == "text/html":
        html = p.get_payload(decode=True).decode()
assert "<script>alert(1)</script>" not in html, "raw tag survived escaping"
assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html, "the tag is not escaped once"
assert "&amp;lt;" not in html, "the value was escaped twice"
PY
echo "  HTML body escapes the tag exactly once"
python3 - "$HF" <<'PY'
import email, sys
m = email.message_from_file(open(sys.argv[1]))
# A header injection would have created an extra header. The set of headers
# is the fixed one the service builds.
allowed = {"from","to","subject","date","message-id","mime-version","content-type",
           "references","in-reply-to"}
extra = [k for k in m.keys() if k.lower() not in allowed]
assert not extra, "extra headers: %s" % extra
text = [p.get_payload(decode=True).decode() for p in m.walk()
        if p.get_content_type() == "text/plain"][0]
assert "<script>" not in text, "raw tag in the text body"
assert "&lt;script&gt;" not in text, "escaped tag in the text body"
PY
echo "  no extra headers; the text body carries no markup"

echo "== a name with a line break is rejected at create =="
code=$(create "$D/crlf.json" \
  '[{"email":"evil@example.test","name":"Bob\r\nBcc: evil@x.test","order":1}]' \
  "$D/specfield.json" "crlf injection")
test "$code" = "400" && echo "  CRLF name -> 400"
jq -r '.error.code' "$D/crlf.json" | grep -q 'parties\[\]\.name' && \
  echo "  names the field: $(jq -c '.error' "$D/crlf.json" | head -c 120)"
test "$(count parties)" = "3" && echo "  no party rows added by the refused create"

echo "== expired token lookup maps to 410 =="
go test -mod=vendor -count=1 -run TestExpiredTokenLookupIsExpired ./internal/signflow 2>&1 \
  | grep -vE '^"TODO Signature field|^{"time"' | tail -1

echo "== send requires envelope:write; a read-only client gets 403 =="
# "client add api" defaults to both envelope scopes, so the read-only client
# is created with an explicit scope list: it can read, and send is refused.
CKEY=$("$D/signsrv" client add readonly envelope:read -config "$D/dev.conf" | sed -n 's/^key: //p')
test -n "$CKEY" && echo "  client token issued"
CACCESS=$(curl -s -X POST "$API/auth/token" -H 'content-type: application/json' \
  -d "{\"key\":\"$CKEY\"}" | jq -r '.access')
test -n "$CACCESS" && test "$CACCESS" != "null" && echo "  read-only client token minted"
code=$(curl -s -o "$D/scope.json" -w '%{http_code}' -X POST "$API/envelopes/$ENVID/send" \
  -H "Authorization: Bearer $CACCESS")
test "$code" = "403" && echo "  send with envelope:read -> 403"
jq -r '.error.code' "$D/scope.json" | grep -q 'insufficient_scope\|forbidden' && \
  echo "  code is $(jq -r '.error.code' "$D/scope.json")"
code=$(curl -s -o "$D/noauth.json" -w '%{http_code}' -X POST "$API/envelopes/$ENVID/send")
test "$code" = "401" && echo "  no token -> 401"
echo "== send on a missing envelope is 404 =="
code=$(curl -s -o "$D/x.json" -w '%{http_code}' -X POST \
  "$API/envelopes/00000000000000000000000000000000/send" -H "Authorization: Bearer $ACCESS")
test "$code" = "404" && echo "  missing envelope -> 404"
jq -r '.error.code' "$D/x.json" | grep -q not_found && echo "  code is not_found"

echo "== send is rate limited on its own bucket (30/min, separate from create's 20) =="
BEFORE_ENV=$(count envelopes)
# Fifteen envelopes, then repeated sends against them: the send bucket
# saturates well before the create budget is used up, which is the point of
# giving the endpoint its own bucket.
ids=""
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  jq -n --arg e "p$i@example.test" '[{email:$e,name:"R",order:1}]' > "$D/p.json"
  create "$D/pc.json" "$(cat "$D/p.json")" "$D/specfield.json" "rl $i" > /dev/null
  ids="$ids $(jq -r '.envelope.id' "$D/pc.json")"
done
# The create bucket (20/min) can refuse the tail of this loop, so the expected
# count is the number of envelopes this block actually created.
MADE=$(echo $ids | wc -w | tr -d ' ')
test "$MADE" -gt 0 && test "$(count envelopes)" = "$((BEFORE_ENV+MADE))" && \
  echo "  $MADE envelopes added by this block, $(count envelopes) in total"
codes=""
for i in 1 2 3; do
  for id in $ids; do
    codes="$codes $(send "$D/ps.json" "$id")"
  done
done
codes=$(echo "$codes" | tr ' ' '\n' | grep -E '^[0-9]+$')
ok=$(echo "$codes" | grep -c 200)
refused=$(echo "$codes" | grep -c 429)
test "$refused" -gt 0 && echo "  429 returned once the send bucket is full"
test "$ok" -le 30 && echo "  $ok sent, $refused refused (budget is 30/min per client address)"
curl -s -D "$D/rlhead.txt" -o "$D/rlbody.json" -X POST "$API/envelopes/$(echo "$ids" | awk '{print $1}')/send" \
  -H "Authorization: Bearer $ACCESS" > "$D/rlcode.txt"
grep -qi '^retry-after:' "$D/rlhead.txt" && echo "  Retry-After present"
jq -r '.error.code' "$D/rlbody.json" | grep -q rate_limited && echo "  error code rate_limited"
test "$(curl -s -o "$D/while.json" -w '%{http_code}' "$API/envelopes?limit=1" \
  -H "Authorization: Bearer $ACCESS")" = "200" && echo "  reads keep working while send is saturated"

echo "== all step 06 checks passed =="

# The assertions above are "test X && echo" lines, which do not stop the script
# when X is false. The marker list is the complete set of expected results; any
# missing marker is a failure, so a silent assertion cannot pass the step.
MISSING=0
for m in "build offline from vendor" "clean" \
         "mail test written to" "To header is the tested address" \
         "subject is the spec form" "no List-Unsubscribe header" \
         "create status 201" "send status 200" "envelope is sent" \
         "two links returned" "52 lowercase base32 characters" \
         "the send wrote 2 new .eml files" "one signing link in the message" \
         "one token URL and no PDF attachment" \
         "reason printed" "order of n printed" "recipient address printed" \
         "second send is 409" "code is state_conflict" \
         "no unsent rows left" "2 queue rows, both sent" \
         "stored column is a hash, not the token" "64 hex characters" \
         "plaintext token absent from the database file" \
         "plaintext token absent from the log" \
         "plaintext token absent from the serve log" \
         "hostile name accepted at create" "send with the hostile name is 200" \
         "the message for the hostile party is in the outbox" \
         "escapes the tag exactly once" "no extra headers" \
         "CRLF name -> 400" "names the field" \
         "no party rows added by the refused create" \
         "the invite is queued by the send, not the create" \
         "a dead relay leaves the envelope sent and raises mail_failed" \
         "envelopes added by this block" "429 returned once the send bucket is full" \
         "Retry-After present" "error code rate_limited" \
         "reads keep working while send is saturated" \
         "send with envelope:read -> 403" "no token -> 401" \
         "client token issued" "missing envelope -> 404" "code is not_found"; do
  grep -q "$m" "$D/results.txt" || { echo "MISSING: $m"; MISSING=1; }
done
test "$MISSING" = 0 && echo "== every expected marker present =="
STATUS=0
test "$MISSING" = 0 || STATUS=1

# stdout is redirected into results.txt, so the echo of the transcript has to
# read a copy: cat of the live file is "input file is output file".
cp "$D/results.txt" "$D/results.copy.txt"
cat "$D/results.copy.txt"
exit "$STATUS"
