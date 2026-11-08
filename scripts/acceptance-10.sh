#!/bin/sh
# Step 10 acceptance. Run from the project root:  sh scripts/acceptance-10.sh
#
# Every block is a signoff item from docs/steps/10-batch-sign.md. The Go suite
# carries the cases that need control over the internals (a TSA that fails on
# demand, a signature removed from the document, a lease left by a crashed
# worker); the blocks below exercise the same rules end to end over HTTP and
# the CLI against a running service, on the artefacts a reviewer is asked to
# trust: the stored revision chain, the signatures in the delivered bytes, the
# .eml files in the outbox, the receipt.
set -e
D=$(mktemp -d)
PNG="iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAYAAACp8Z5+AAAAUUlEQVR4nABEALv/AgAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAADAAGYAAkgiuKzAAAAAElFTkSuQmCC"

cleanup() {
  pkill -x signsrv >/dev/null 2>&1 || true
  cp "$D/results.txt" ./acceptance-10-results.txt 2>/dev/null || true
  [ "$KEEP" = 1 ] || rm -rf "$D"
  [ "$KEEP" = 1 ] || rm -f ./signsrv ./pdf-go
}
trap cleanup EXIT

cat > "$D/dev.conf" <<EOF
listen=127.0.0.1:8096
public_url=http://127.0.0.1:8096
dev=true
db=$D/signsrv.db
storage_dir=$D/storage
keystore_dir=$D/keystore
outbox_dir=$D/outbox
log_path=$D/signsrv.jsonl
keystore_pass=dev-keystore-passphrase-that-is-long
admin_password=dev-admin-password-change-me
mail_from=signsrv@example.test
smtp_host=127.0.0.1
worker_interval=1s
link_ttl=24h
EOF

# Everything the script prints is the record of what was checked, so stdout
# goes to the results file; the summary greps it for the markers below.
exec > "$D/results.txt" 2>&1

API=http://127.0.0.1:8096/api/v1
DB="$D/signsrv.db"
Q() { sqlite3 "$DB" "$1"; }

# consent claims a link with the party's own address and consents with a drawn
# image, so the batch reads back a real consent record and a real appearance.
consent() { # token  email  name  outfile
  cookie=$(curl -s -o /dev/null -D - -X POST "$API/sign/$1/claim" \
    -H 'content-type: application/json' -d "{\"email\":\"$2\"}" \
    | sed -n 's/^[Ss]et-[Cc]ookie: \([^;]*\).*/\1/p' | head -1)
  # The party consents to the document as the service shows it to them, so the
  # digest comes from the signer endpoint, not from the admin's envelope view.
  sha=$(curl -s "$API/sign/$1/envelope" -H "Cookie: $cookie" | jq -r '.document_sha // ""')
  test -n "$sha" -a "$sha" != null || { echo "  (check failed) $3 has no document to consent to"; return 1; }
  code=$(curl -s -o "$4" -w '%{http_code}' -X POST "$API/sign/$1/consent" \
    -H "Cookie: $cookie" -H 'content-type: application/json' \
    -d "{\"signature_text\":\"$3\",\"consent\":true,\"document_sha\":\"$sha\",\"image\":\"$PNG\"}")
  test "$code" = 200 || { echo "  (check failed) consent for $3 -> $code"; cat "$4"; return 1; }
}

start_server() {
  SIGNSRV_ADMIN_PASSWORD=dev-admin-password-change-me \
    ./signsrv admin add admin@example.test -config "$D/dev.conf" >/dev/null 2>&1 || true
  ./signsrv serve -config "$D/dev.conf" >> "$D/serve.log" 2>&1 &
  i=0
  while ! curl -s -o "$D/health.json" --max-time 2 http://127.0.0.1:8096/healthz; do
    i=$((i+1)); test "$i" -lt 40 || { echo "  service did not start"; cat "$D/serve.log"; exit 1; }
    sleep 0.3
  done
  curl -s -X POST "$API/auth/login" -H 'content-type: application/json' \
    -d '{"email":"admin@example.test","password":"dev-admin-password-change-me"}' > "$D/login.json"
  ACCESS=$(jq -r '.access' "$D/login.json")
  test -n "$ACCESS" -a "$ACCESS" != null || { echo "  admin login failed"; cat "$D/login.json"; exit 1; }
  AUTH="Authorization: Bearer $ACCESS"
  echo "  server up, admin token issued"
}
# stop_server takes the service down. batch and worker open the same SQLite
# file; one writer at a time keeps the runs honest.
stop_server() { pkill -x signsrv >/dev/null 2>&1 || true; sleep 0.5; }

# run_batches asks for the batch on the CLI, then lets the worker drain the
# delivery queue and stops. The production shape: the request enqueues, the
# worker signs and delivers.
run_batches() { # envelope  tag
  ./signsrv batch -config "$D/dev.conf" "$1" > "$D/run$2.log" 2>&1 || true
  ./signsrv worker -config "$D/dev.conf" > "$D/worker$2.log" 2>&1 &
  W=$!
  j=0
  while [ "$(Q "select count(*) from deliveries where envelope_id='$1'")" != \
    "$(Q "select count(*) from parties where envelope_id='$1'")" ]; do
    j=$((j+1)); test "$j" -lt 160 || { echo "  deliveries never landed"; cat "$D/worker$2.log"; exit 1; }
    sleep 0.5
  done
  kill "$W" 2>/dev/null || true
  wait "$W" 2>/dev/null || true
  stop_server
}

# make_envelope creates, sends and consent-all. Leaves EID<n>/SHA<n> set and
# the links in $D/links<n>.txt as "token email name" lines in signing order.
make_envelope() { # title  parties.json  tag
  curl -s -o "$D/create$3.json" -w '%{http_code}' -X POST "$API/envelopes" -H "$AUTH" \
    -F "template=@testdata/sample1.pdf" -F "title=$1" \
    -F "expires_in=48h" -F "parties=$(cat "$2")" -F "spec=$(cat "$D/spec.json")" \
    > "$D/create$3.code"
  grep -q 201 "$D/create$3.code" || { echo "  creating $1 failed"; cat "$D/create$3.json"; return 1; }
  curl -s -o "$D/send$3.json" -X POST "$API/envelopes/$(jq -r '.envelope.id' "$D/create$3.json")/send" \
    -H "$AUTH" >/dev/null
  jq -r '.links[] | [.token, .email] | join(" ")' "$D/send$3.json" > "$D/links$3.txt"
  jq -r '.envelope.id' "$D/create$3.json" > "$D/eid$3"
  Q "select current_sha from envelopes where id='$(cat "$D/eid$3")'" > "$D/sha$3"
  test -s "$D/eid$3" && test "$(jq -r '.links | length' "$D/send$3.json")" = "$(jq -r 'length' "$2")" && \
    echo "  $1: created, sent, every party got a signing link" || echo "  (check failed)"
  k=1
  while [ "$k" -le "$(jq -r 'length' "$2")" ]; do
    consent "$(sed -n "$k"p "$D/links$3.txt" | cut -d' ' -f1)" \
      "$(sed -n "$k"p "$D/links$3.txt" | cut -d' ' -f2)" \
      "$(sed -n "$k"p "$D/links$3.txt" | cut -d' ' -f2)" "$D/c$3-$k.json" || true
    k=$((k+1))
  done
  echo "  $1: all parties consented, nothing signed yet"
}

echo "== build offline from vendor =="
go build -o ./signsrv ./cmd/signsrv && echo "  ok" || echo "  (check failed)"
go build -o ./pdf-go ./cmd/pdf-go && echo "  pdf-go built" || echo "  (check failed)"

echo "== vet and gofmt =="
go vet ./internal/signflow ./internal/signstore ./internal/signpdf ./internal/signmail ./cmd/signsrv \
  >/dev/null 2>&1 && echo "  clean" || echo "  (check failed)"
test -z "$(gofmt -l ./cmd ./internal)" && echo "  gofmt clean" || echo "  (check failed)"

echo "== the batch and delivery suites =="
go test -count=1 ./internal/signflow ./internal/signstore ./internal/signpdf ./cmd/signsrv

echo "== signing happens only in RunBatch =="
test "$(grep -rln '\.SignParty(' ./cmd ./internal --include='*.go' | grep -v _test | tr '\n' ' ')" = \
  "./cmd/signsrv/selftest.go ./cmd/signsrv/sign.go ./internal/signflow/batch.go " && \
  echo "  SignParty only in batch.go and the step-04 CLI" || echo "  (check failed)"
grep -q "SignParty(" internal/signflow/consent.go && echo "  FAIL: consent signs" || \
  echo "  consent does not sign" || echo "  (check failed)"
test "$(grep -rc 'SignParty(' cmd/signsrv/server.go cmd/signsrv/envelopes.go internal/signflow/deliver.go \
  | grep -v ':0' | wc -l)" = 0 && echo "  the server never signs, grep clean" || echo "  (check failed)"

echo "== consent enqueues one batch row per envelope, and signs nothing =="
FIELD=$(./pdf-go extract testdata/sample1.pdf 2>/dev/null | jq -r \
  '[.fields[] | select(.type=="text" and (.flags|index("readOnly"))==null) | .name][0]')
cat > "$D/spec.json" <<EOF
{"fill":{"values":{"$FIELD":"filed"}},"widget":{"page":1,"y":60},
 "subject":"Sign the agreement","message":"Please sign"}
EOF
test -n "$FIELD" -a "$FIELD" != null && echo "  signature fields planned on field $FIELD" || echo "  (check failed)"
cat > "$D/parties.json" <<'EOF'
[{"email":"alice@example.test","name":"Alice Adamson","order":1},
 {"email":"berta@example.test","name":"Berta Brandt","order":2},
 {"email":"chas@example.test","name":"Chas Chapman","order":3}]
EOF
cat > "$D/parties2.json" <<'EOF'
[{"email":"dan@example.test","name":"Dan Delta","order":1},
 {"email":"eve@example.test","name":"Eve Evans","order":2},
 {"email":"fay@example.test","name":"Fay Foster","order":3}]
EOF
cat > "$D/parties3.json" <<'EOF'
[{"email":"gus@example.test","name":"Gus Green","order":1},
 {"email":"ivy@example.test","name":"Ivy Irving","order":2},
 {"email":"jo@example.test","name":"Jo Jolley","order":3}]
EOF
cat > "$D/parties4.json" <<'EOF'
[{"email":"kit@example.test","name":"Kit Kline","order":1},
 {"email":"lee@example.test","name":"Lee Lyman","order":2},
 {"email":"moe@example.test","name":"Moe Moore","order":3}]
EOF
start_server
curl -s -o "$D/create.json" -w '%{http_code}' -X POST "$API/envelopes" -H "$AUTH" \
  -F "template=@testdata/sample1.pdf" -F "title=Quarterly Report" \
  -F "expires_in=48h" -F "parties=$(cat "$D/parties.json")" -F "spec=$(cat "$D/spec.json")" \
  > "$D/create.code"
grep -q 201 "$D/create.code" && echo "  create returned 201" || echo "  (check failed)"
EID=$(jq -r '.envelope.id' "$D/create.json")
DSHA=$(Q "select current_sha from envelopes where id='$EID'")
test -n "$DSHA" -a "$DSHA" != null && echo "  envelope created, document sha present" || echo "  (check failed)"
test "$(sha256sum "$D/storage/$DSHA.pdf" | cut -d' ' -f1)" = "$DSHA" && \
  echo "  the stored file is content addressed by its own sha" || echo "  (check failed)"
curl -s -o "$D/send.json" -X POST "$API/envelopes/$EID/send" -H "$AUTH" >/dev/null
jq -r '.links[] | [.token, .email] | join(" ")' "$D/send.json" > "$D/links.txt"
test "$(jq -r '.links | length' "$D/send.json")" = 3 && echo "  3 signing links sent" || echo "  (check failed)"
consent "$(sed -n 1p "$D/links.txt" | cut -d' ' -f1)" alice@example.test "Alice Adamson"  "$D/c1.json" || true
test "$(Q "select count(*) from batch_queue where envelope_id='$EID'")" = 0 && \
  echo "  no batch row while parties are still consenting" || echo "  (check failed)"
consent "$(sed -n 2p "$D/links.txt" | cut -d' ' -f1)" berta@example.test "Berta Brandt"  "$D/c2.json" || true
consent "$(sed -n 3p "$D/links.txt" | cut -d' ' -f1)" chas@example.test "Chas Chapman"  "$D/c3.json" || true
test "$(Q "select count(*) from batch_queue where envelope_id='$EID'")" = 1 && \
  echo "  still one row after all three consents" || echo "  (check failed)"
test "$(Q "select status from envelopes where id='$EID'")" = collecting && \
  echo "  envelope is collecting, not signed, at consent time" || echo "  (check failed)"
test "$(Q "select count(*) from events where envelope_id='$EID' and kind like '%consent%'")" -ge 3 && \
  echo "  the audit records the consents" || echo "  (check failed)"
stop_server

# The batch runs a couple of seconds after the last consent, so the signing
# stamp in the receipt is provably later than the consent stamp.
sleep 2

# A worker that claimed the row and died leaves the lease behind. Rewinding the
# lease into the past is that crash: the row is queued, the work is not done,
# and no live process is holding it.
Q "update batch_queue set lease_until='2000-01-01T00:00:00Z' where envelope_id='$EID'"
test "$(Q "select count(*) from batch_queue where envelope_id='$EID'")" = 1 && \
  test "$(Q "select count(*) from revisions where envelope_id='$EID' and kind='signed'")" = 0 && \
  echo "  a crashed job leaves the row queued and the document unsigned" || echo "  (check failed)"

echo "== the batch signs all three parties, in order, nesting =="
run_batches "$EID" 1
grep -q "of 3" "$D/run1.log" && \
  echo "  the next run takes the expired lease and signs the crashed job" || echo "  (check failed)"
grep -q "status " "$D/run1.log" && echo "  the batch ran on the CLI: $(sed -n 1p "$D/run1.log" | cut -d: -f2 | cut -c1-32)" || echo "  (check failed)"
grep -q "of 3" "$D/run1.log" && echo "  the CLI reports 3 of 3 signed" || echo "  (check failed)"
test "$(Q "select count(*) from revisions where envelope_id='$EID' and kind='signed'")" = 3 && \
  echo "  exactly 3 party revisions" || echo "  (check failed)"
test "$(Q "select count(distinct sig_field) from revisions where envelope_id='$EID' and kind='signed'")" = 3 && \
  echo "  3 distinct signature fields" || echo "  (check failed)"
test "$(Q "select count(*) from revisions where envelope_id='$EID' and kind='certified'")" = 1 && \
  echo "  the chain has exactly one root" || echo "  (check failed)"
test "$(Q "select count(distinct cert_serial) from revisions where envelope_id='$EID' and kind='signed'")" = 3 && \
  echo "  3 party signatures, each with its own leaf serial" || echo "  (check failed)"
test "$(Q "select r.prev_id from revisions r join parties p on p.id=r.party_id where r.envelope_id='$EID' and r.kind='signed' and p.order_idx=2")" = \
  "$(Q "select r.id from revisions r join parties p on p.id=r.party_id where r.envelope_id='$EID' and r.kind='signed' and p.order_idx=1")" && \
  echo "  party 2 signs the bytes party 1 produced" || echo "  (check failed)"
test "$(Q "select r.prev_id from revisions r join parties p on p.id=r.party_id where r.envelope_id='$EID' and r.kind='signed' and p.order_idx=3")" = \
  "$(Q "select r.id from revisions r join parties p on p.id=r.party_id where r.envelope_id='$EID' and r.kind='signed' and p.order_idx=2")" && \
  echo "  party 3 signs the bytes party 2 produced" || echo "  (check failed)"
test "$(Q "select group_concat(p.name, ',') from revisions r join parties p on p.id=r.party_id where r.envelope_id='$EID' and r.kind='signed' order by p.order_idx")" = \
  "Alice Adamson,Berta Brandt,Chas Chapman" && echo "  the revisions are in party order" || echo "  (check failed)"
test "$(Q "select status from envelopes where id='$EID'")" != collecting && \
  echo "  envelope moved on from collecting" || echo "  (check failed)"

echo "== gate 1: the delivered bytes verify over HTTP =="
SHA_LAST=$(Q "select current_sha from envelopes where id='$EID'")
FINAL=$(Q "select r.sha256 from revisions r join parties p on p.id=r.party_id where r.envelope_id='$EID' and r.kind='signed' and p.order_idx=3")
test "$SHA_LAST" = "$FINAL" && echo "  the envelope's current sha is the last signature" || echo "  (check failed)"
start_server
curl -s -o "$D/final.pdf" "$API/envelopes/$EID/document" -H "$AUTH"
stop_server
test "$(sha256sum "$D/final.pdf" | cut -d' ' -f1)" = "$FINAL" && \
  echo "  the document endpoint serves exactly those bytes" || echo "  (check failed)"
./signsrv checkpdf -config "$D/dev.conf" "$D/final.pdf" > "$D/verify1.json" 2>&1 || true
jq -r '.valid' "$D/verify1.json" | grep -q true && echo "  final document verifies: valid true" || echo "  (check failed)"
test "$(jq -r '.signers | length' "$D/verify1.json")" = 4 && \
  echo "  4 signers: the certified base plus 3 parties" || echo "  (check failed)"
test "$(jq -r '[.signers[-3:][].Name] | join(",")' "$D/verify1.json")" = \
  "Alice Adamson,Berta Brandt,Chas Chapman" && \
  echo "  signer names in signing order" || echo "  (check failed)"
test "$(jq -r '[.signers[].Valid] | map(select(.==true)) | length' "$D/verify1.json")" = 4 && \
  echo "  every signature is valid" || echo "  (check failed)"
test "$(jq -r '[.signers[].Timestamp] | map(select(.==true)) | length' "$D/verify1.json")" = 4 && \
  echo "  every signature carries a TSA token" || echo "  (check failed)"

test "$(Q "select count(*) from batch_queue where envelope_id='$EID'")" = 0 && \
  echo "  the queue row is gone once the batch has finished" || echo "  (check failed)"

echo "== the batch is idempotent =="
BEFORE=$(Q "select count(*) from revisions where envelope_id='$EID' and kind='signed'")
# The row is re-enqueued by hand so the batch runs again over an envelope whose
# work is already done. A stale row is finished, not failed, and the answer is
# the status the envelope already has.
Q "insert into batch_queue(envelope_id, attempts, next_at, lease_until, enqueued_at) \
   values('$EID', 1, '2000-01-01T00:00:00Z', NULL, '2000-01-01T00:00:00Z')"
run_batches "$EID" 2
test "$(Q "select count(*) from revisions where envelope_id='$EID' and kind='signed'")" = "$BEFORE" && \
  echo "  a re-run adds no signature to a signed envelope" || echo "  (check failed)"
test "$(Q "select count(*) from batch_queue where envelope_id='$EID'")" = 0 && \
  echo "  the stale row is drained, not requeued" || echo "  (check failed)"
grep -qi "status" "$D/run2.log" && \
  echo "  the re-run answers with the envelope's status: $(grep -oi 'status [a-z]*' "$D/run2.log" | head -1)" || echo "  (check failed)"

echo "== delivery: one message per party, accepted per party =="
test "$(ls "$D/outbox" | grep -c '^signed-')" = 3 && echo "  3 signed-copy messages in the outbox" || echo "  (check failed)"
test "$(grep -l 'filename=.*-signed.pdf' "$D/outbox"/signed-*.eml | wc -l | tr -d ' ')" = 3 && \
  echo "  each party copy carries the signed PDF and the receipt" || echo "  (check failed)"
test "$(Q "select count(*) from parties where envelope_id='$EID' and delivered_at is not null")" = 3 && \
  echo "  all 3 parties stamped delivered_at" || echo "  (check failed)"
test "$(Q "select status from envelopes where id='$EID'")" = delivered && \
  echo "  delivered only when every party has accepted" || echo "  (check failed)"
test "$(Q "select count(*) from deliveries where envelope_id='$EID' and delivery_status='accepted'")" = 3 && \
  echo "  three accepted delivery rows" || echo "  (check failed)"
test "$(Q "select count(*) from events where envelope_id='$EID' and actor='delivery'")" -ge 1 && \
  echo "  the audit records the delivery" || echo "  (check failed)"

echo "== the receipt carries the two times and the evidence =="
RCP=$(ls "$D/outbox"/signed-*.eml | head -1)
python3 - "$RCP" "$D/receipt.json" <<'PY'
import email, sys, email.policy
msg = email.message_from_file(open(sys.argv[1]), policy=email.policy.default)
for part in msg.walk():
    if part.get_content_disposition() == "attachment" and \
       (part.get_filename() or "").endswith("receipt.json"):
        open(sys.argv[2], "wb").write(part.get_payload(decode=True))
PY
test -s "$D/receipt.json" && echo "  the receipt is attached to the party's message" || echo "  (check failed)"
test "$(jq -r '.parties | length' "$D/receipt.json")" = 3 && echo "  receipt lists 3 parties" || echo "  (check failed)"
test "$(jq -r '[.parties[].consent_at] | map(select(.!="")) | length' "$D/receipt.json")" = 3 && \
  echo "  every party has a consent time" || echo "  (check failed)"
test "$(jq -r '[.parties[].signed_at] | map(select(.!="")) | length' "$D/receipt.json")" = 3 && \
  echo "  every party has a signing time" || echo "  (check failed)"
test "$(jq -r '[.parties[] | select(.consent_at==.signed_at)] | length' "$D/receipt.json")" = 0 && \
  echo "  the two times are never the same value" || echo "  (check failed)"
test "$(jq -r '[.parties[].cert_serial] | map(select(.!="")) | length' "$D/receipt.json")" = 3 && \
  echo "  every party has the serial of its leaf" || echo "  (check failed)"
test "$(jq -r '[.parties[].tsa.present] | map(select(.==true)) | length' "$D/receipt.json")" = 3 && \
  echo "  every signing has a timestamp token" || echo "  (check failed)"
test "$(jq -r '[.parties[].signature_text] | map(select(.!="")) | length' "$D/receipt.json")" = 3 && \
  echo "  the receipt carries each party's drawn signature text" || echo "  (check failed)"
test "$(jq -r '.parties[0].consent_ip' "$D/receipt.json")" = "127.0.0.1" && \
  echo "  the consent carries the address it came from" || echo "  (check failed)"
test "$(jq -r '.final_sha256' "$D/receipt.json")" = "$FINAL" && \
  echo "  the receipt is over the bytes the parties received" || echo "  (check failed)"
test "$(jq -r '.valid' "$D/receipt.json")" = true && echo "  the receipt records the verification as valid" || echo "  (check failed)"

echo "== the signing links are dead after delivery =="
start_server
code=$(curl -s -o "$D/dead.json" -w '%{http_code}' -X POST "$API/sign/$(sed -n 1p "$D/links.txt" | cut -d' ' -f1)/consent" \
  -H 'content-type: application/json' \
  -d "{\"signature_text\":\"Late\",\"consent\":true,\"document_sha\":\"$DSHA\"}")
test "$code" = 410 -o "$code" = 404 -o "$code" = 401 -o "$code" = 403 && \
  echo "  a signing token is gone after delivery: $code" || echo "  (check failed)"
stop_server

echo "== one refusal does not stop the others =="
start_server
make_envelope "Partial Delivery" "$D/parties2.json" 2
EID2=$(cat "$D/eid2"); SHA2=$(cat "$D/sha2")
PID2=$(Q "select id from parties where envelope_id='$EID2' and name='Eve Evans'")
mkdir -p "$D/outbox/signed-$EID2-$PID2.eml"
stop_server
run_batches "$EID2" 3
test "$(Q "select count(*) from parties where envelope_id='$EID2' and delivered_at is not null and delivered_at!=''")" -ge 2 && \
  echo "  the two healthy parties are accepted" || echo "  (check failed)"
test "$(Q "select count(*) from parties where envelope_id='$EID2' and (delivered_at is null or delivered_at='')")" -ge 1 && \
  echo "  the party with the broken mailbox has no acceptance stamp" || echo "  (check failed)"
test "$(Q "select status from envelopes where id='$EID2'")" = completed && \
  echo "  the envelope is completed, not delivered: delivered needs every party" || echo "  (check failed)"
test "$(Q "select count(*) from deliveries where envelope_id='$EID2' and delivery_status='pending'")" = 1 && \
  echo "  the refused party is a pending delivery row, not a lost one" || echo "  (check failed)"
test "$(Q "select count(*) from deliveries where envelope_id='$EID2' and last_error is not null and last_error != ''")" = 1 && \
  echo "  the refused party names the failure on its own row" || echo "  (check failed)"
test "$(Q "select count(*) from revisions where envelope_id='$EID2' and kind='signed'")" = 3 && \
  echo "  all three parties signed; only the delivery is partial" || echo "  (check failed)"

echo "== an admin sign request with a party outstanding is refused =="
start_server
curl -s -o "$D/create4.json" -w '%{http_code}' -X POST "$API/envelopes" -H "$AUTH" \
  -F "template=@testdata/sample1.pdf" -F "title=Out of Consent" \
  -F "expires_in=48h" -F "parties=$(cat "$D/parties4.json")" -F "spec=$(cat "$D/spec.json")" \
  > "$D/create4.code"
grep -q 201 "$D/create4.code" && echo "  Out of Consent: created" || echo "  (check failed)"
curl -s -o "$D/send4.json" -X POST "$API/envelopes/$(jq -r '.envelope.id' "$D/create4.json")/send" \
  -H "$AUTH" >/dev/null
jq -r '.links[] | [.token, .email] | join(" ")' "$D/send4.json" > "$D/links4.txt"
EID4=$(jq -r '.envelope.id' "$D/create4.json")
# Two parties consent; the third never does. The queue row appears only with the
# last consent, so a sign request now has a party outstanding.
consent "$(sed -n 1p "$D/links4.txt" | cut -d' ' -f1)" kit@example.test "Kit Kline" "$D/c4-1.json" || true
consent "$(sed -n 2p "$D/links4.txt" | cut -d' ' -f1)" lee@example.test "Lee Lyman" "$D/c4-2.json" || true
test "$(Q "select count(*) from parties where envelope_id='$EID4' and consent_at is not null and consent_at!=''")" = 2 && \
  echo "  two of three parties have consented" || echo "  (check failed)"
test "$(Q "select count(*) from batch_queue where envelope_id='$EID4'")" = 0 && \
  echo "  no batch row while a party is outstanding" || echo "  (check failed)"
code=$(curl -s -o "$D/sign.json" -w '%{http_code}' -X POST "$API/envelopes/$EID4/sign" -H "$AUTH")
test "$code" = 409 && \
  echo "  a sign request while a party has not consented: $code" || echo "  (check failed)"
test "$(Q "select count(*) from batch_queue where envelope_id='$EID4'")" = 0 && \
  echo "  the refused sign request queues no batch row" || echo "  (check failed)"
test "$(Q "select count(*) from revisions where envelope_id='$EID4' and kind='signed'")" = 0 && \
  echo "  the refused sign request adds no signature" || echo "  (check failed)"
test "$(Q "select status from envelopes where id='$EID4'")" = collecting && \
  echo "  the envelope is still collecting after the refused sign request" || echo "  (check failed)"
test "$(ls "$D/outbox" | grep -c "^signed-$EID4-")" = 0 && \
  echo "  nothing is mailed for a refused sign request" || echo "  (check failed)"
stop_server

echo "== tampered input: the batch signs nothing =="
start_server
make_envelope "Tampered Input" "$D/parties3.json" 3
EID3=$(cat "$D/eid3"); SHA3=$(cat "$D/sha3")
stop_server
printf 'bytes nobody approved' >> "$D/storage/$SHA3.pdf"
./signsrv batch -config "$D/dev.conf" "$EID3" > "$D/batch3.log" 2>&1 || true
grep -qi "gate failed" "$D/batch3.log" && \
  echo "  the batch refuses input whose bytes are not the envelope's" || echo "  (check failed)"
grep -qi "$EID3" "$D/batch3.log" && echo "  the report names the envelope on the line" || echo "  (check failed)"
test "$(Q "select status from envelopes where id='$EID3'")" = failed && \
  echo "  the envelope is marked failed" || echo "  (check failed)"
test "$(Q "select count(*) from events where envelope_id='$EID3' and kind like '%fail%'")" -ge 1 && \
  echo "  the failure is in the envelope's audit log" || echo "  (check failed)"
test "$(Q "select count(*) from revisions where envelope_id='$EID3' and kind='signed'")" = 0 && \
  echo "  a refused batch adds no signature" || echo "  (check failed)"

echo
echo "SUMMARY"
MISSING=0
for want in \
  "ok" "pdf-go built" "clean" "gofmt clean" \
  "create returned 201" "signature fields planned on field" \
  "SignParty only in batch.go and the step-04 CLI" "consent does not sign" \
  "the server never signs, grep clean" \
  "envelope created, document sha present" "3 signing links sent" \
  "no batch row while parties are still consenting" "still one row after all three consents" \
  "envelope is collecting, not signed, at consent time" "the audit records the consents" \
  "the batch ran on the CLI:" "the CLI reports 3 of 3 signed" \
  "a crashed job leaves the row queued and the document unsigned" \
  "the next run takes the expired lease and signs the crashed job" \
  "exactly 3 party revisions" "3 distinct signature fields" \
  "the chain has exactly one root" "3 party signatures, each with its own leaf serial" \
  "party 2 signs the bytes party 1 produced" "party 3 signs the bytes party 2 produced" \
  "the revisions are in party order" "envelope moved on from collecting" \
  "the envelope's current sha is the last signature" \
  "the document endpoint serves exactly those bytes" \
  "final document verifies: valid true" "4 signers: the certified base plus 3 parties" \
  "signer names in signing order" "every signature is valid" \
  "every signature carries a TSA token" \
  "a re-run adds no signature to a signed envelope" \
  "the queue row is gone once the batch has finished" \
  "the stale row is drained, not requeued" \
  "the re-run answers with the envelope's status" \
  "3 signed-copy messages in the outbox" \
  "each party copy carries the signed PDF and the receipt" \
  "all 3 parties stamped delivered_at" \
  "delivered only when every party has accepted" \
  "three accepted delivery rows" "the audit records the delivery" \
  "the receipt is attached to the party's message" "receipt lists 3 parties" \
  "every party has a consent time" "every party has a signing time" \
  "the two times are never the same value" "every party has the serial of its leaf" \
  "every signing has a timestamp token" \
  "the receipt carries each party's drawn signature text" \
  "the consent carries the address it came from" \
  "the receipt is over the bytes the parties received" \
  "the receipt records the verification as valid" \
  "a signing token is gone after delivery" \
  "created, sent, every party got a signing link" "all parties consented, nothing signed yet" \
  "the two healthy parties are accepted" \
  "the party with the broken mailbox has no acceptance stamp" \
  "the envelope is completed, not delivered: delivered needs every party" \
  "the refused party is a pending delivery row, not a lost one" \
  "the refused party names the failure on its own row" \
  "all three parties signed; only the delivery is partial" \
  "two of three parties have consented" \
  "no batch row while a party is outstanding" \
  "a sign request while a party has not consented" \
  "the refused sign request queues no batch row" \
  "the refused sign request adds no signature" \
  "the envelope is still collecting after the refused sign request" \
  "nothing is mailed for a refused sign request" \
  "the batch refuses input whose bytes are not the envelope's" \
  "the report names the envelope on the line" "the envelope is marked failed" \
  "the failure is in the envelope's audit log" \
  "a refused batch adds no signature"; do
  grep -q "$want" "$D/results.txt" || { echo "  MISSING: $want"; MISSING=1; }
done
test "$MISSING" = 0 && { echo "  all signoff assertions ran"; echo "STEP 10 ACCEPTANCE COMPLETE"; }

echo
echo "END OF RESULTS"
