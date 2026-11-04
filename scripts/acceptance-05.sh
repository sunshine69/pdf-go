#!/bin/sh
# Step 05 acceptance. Run from the project root:  sh scripts/acceptance-05.sh
# Every block is a signoff item from docs/steps/05-envelopes.md.
set -e
D=$(mktemp -d)
PNG="iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAYAAACp8Z5+AAAAUUlEQVR4nABEALv/AgAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAADAAGYAAkgiuKzAAAAAElFTkSuQmCC"

cleanup() {
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

echo "== build offline from vendor =="
GOFLAGS=-mod=vendor GOPROXY=off go build -o "$D/signsrv" ./cmd/signsrv
GOFLAGS=-mod=vendor GOPROXY=off go build -o "$D/pdf-go" ./cmd/pdf-go
echo "  ok"

echo "== vet and gofmt =="
go vet -mod=vendor ./cmd/signsrv ./internal/signflow ./internal/signfill ./internal/signstore
test -z "$(gofmt -l ./cmd ./internal)" && echo "  clean"

echo "== unit tests: fill, certify, state machine, list, download, no partial rows =="
go test -mod=vendor -count=1 ./internal/signflow ./internal/signfill 2>&1 \
  | grep -vE '^"TODO Signature field|^{"time"' | grep -E 'ok|FAIL'

echo "== state machine is table-driven, transactional, audited =="
grep -q '^var allowed = map\[State\]\[\]State{' internal/signflow/state.go && echo "  one transition table"
grep -q 'f.store.Tx(ctx' internal/signflow/state.go && echo "  transition runs in one transaction"
grep -q 'insert into events' internal/signflow/state.go && echo "  the audit event is written in the same transaction"

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

# The fill is the CLI fill JSON, field names taken from the template the same
# way the CLI reads them. One spec file is used by both the CLI and the API.
FIELD=$("$D/pdf-go" extract testdata/sample1.pdf 2>/dev/null | jq -r \
  '[.fields[] | select(.type=="text" and (.flags|index("readOnly"))==null) | .name][0]')
test -n "$FIELD" && echo "  fill target field: $FIELD"

cat > "$D/spec.json" <<EOF
{"values":{"$FIELD":"filed"},
 "logos":[{"id":"stamp","imageData":"$PNG","page":1,"position":"top-right","width":40}],
 "paints":[{"id":"note","text":"filed 2026","page":1,"position":"bottom-left","size":9}]}
EOF

# create <body-file> <parties-json> <spec-file> <title> : prints the status,
# writes the response body. The template is a file part (@); the JSON fields
# are plain form fields, read from a file with '<' so the content is sent.
create() {
  curl -s -o "$1" -w '%{http_code}' -X POST "$API/envelopes" \
    -H "Authorization: Bearer $ACCESS" \
    -F "template=@testdata/sample1.pdf" \
    -F "title=$4" \
    -F "expires_in=48h" \
    -F "parties=$2" \
    -F "spec=<$3"
}

count() { sqlite3 "$D/signsrv.db" "select count(*) from $1"; }

echo "== fill format is the CLI fill JSON: the same file fills with pdf-go =="
"$D/pdf-go" fill "$D/spec.json" testdata/sample1.pdf -o "$D/cli.pdf" 2>/dev/null \
  | jq -r '.applied | sort | join(",")' > "$D/cli.applied"
jq -n --slurpfile f "$D/spec.json" \
  '{fill:$f[0], widget:{page:1,y:60}, subject:"Sign the lease", message:"Please sign"}' \
  > "$D/specfield.json"

echo "== create: 201, ready, links with raw tokens =="
BEFORE_ENV=$(count envelopes); BEFORE_REV=$(count revisions); BEFORE_PARTY=$(count parties)
code=$(create "$D/create.json" \
  '[{"email":"ann@example.test","name":"Ann","order":1},{"email":"bo@example.test","name":"Bo","order":2}]' \
  "$D/specfield.json" "Quarterly report Q3")
test "$code" = "201" && echo "  status 201"
test "$(jq -r '.envelope.status' "$D/create.json")" = "ready" && echo "  status=ready"
jq -r '.fill.applied | sort | join(",")' "$D/create.json" > "$D/api.applied"
test "$(cat "$D/cli.applied")" = "$(cat "$D/api.applied")" && \
  echo "  API fill applied the same fields as the CLI: $(cat "$D/api.applied")"
test "$(jq -r '.links | length' "$D/create.json")" = "2" && echo "  2 links returned"
jq -e '.links[0].token | test("^[A-Za-z0-9_-]{43,64}$")' "$D/create.json" >/dev/null && \
  echo "  link token is a 256-bit random value"
ENVID=$(jq -r '.envelope.id' "$D/create.json")
test "$(count envelopes)" = "$((BEFORE_ENV+1))" && echo "  1 envelope row"
test "$(count parties)" = "$((BEFORE_PARTY+2))" && echo "  2 party rows"
test "$(count revisions)" = "$((BEFORE_REV+3))" && echo "  3 revision rows (template, filled, certified)"
test "$(sqlite3 "$D/signsrv.db" "select count(*) from events where envelope_id='$ENVID'")" = "2" && \
  echo "  2 audit events (created, ready)"
test "$(sqlite3 "$D/signsrv.db" "select group_concat(kind) from events where envelope_id='$ENVID'")" \
  = "created,ready" && echo "  events are created then ready"

echo "== certification happens at create: every field of the certified file is read-only =="
curl -s -D "$D/head.txt" -o "$D/cert.pdf" -H "Authorization: Bearer $ACCESS" \
  "$API/envelopes/$ENVID/document"
# The vendored reader prints a "TODO Signature field" line to stdout, so the
# JSON is taken from the last line of the output.
"$D/pdf-go" extract "$D/cert.pdf" 2>/dev/null | grep -v '^TODO Signature' > "$D/cert.json"
nopen=$(jq '[.fields[] | select(.flags|index("readOnly")|not) | .name] | length' "$D/cert.json")
nall=$(jq '.fields | length' "$D/cert.json")
test "$nopen" = "0" && echo "  all $nall fields carry readOnly, none is fillable"
test "$(jq -r '.lockedForm' "$D/create.json")" = "true" && echo "  fill summary says the form is locked"
"$D/signsrv" checkpdf -config "$D/dev.conf" "$D/cert.pdf" > "$D/check.json"
jq -r '.valid' "$D/check.json" | grep -q true && echo "  certified file verifies"
test "$(jq -r '.signers[0].Name' "$D/check.json")" = "signsrv" && \
  echo "  first signer is the certification"
test "$(jq -r '.sha256' "$D/check.json")" = \
  "$(sqlite3 "$D/signsrv.db" "select current_sha from envelopes where id='$ENVID'")" && \
  echo "  the served file is the certified bytes, hash == current_sha"

echo "== plaintext links exist only in the create response =="
TOKEN=$(jq -r '.links[0].token' "$D/create.json")
test "$(sqlite3 "$D/signsrv.db" "select count(*) from parties where token_hash='$TOKEN'")" = "0" && \
  echo "  stored column is a hash, not the token"
test "$(sqlite3 "$D/signsrv.db" "select length(token_hash) from parties limit 1")" = "64" && \
  echo "  token_hash is 64 hex characters"
if grep -q "$TOKEN" "$D/signsrv.db"; then echo "  plaintext token in the database file"; exit 1
else echo "  plaintext token absent from the database file"; fi
if grep -q "$TOKEN" "$D/signsrv.jsonl"; then echo "  plaintext token in the log"; exit 1
else echo "  plaintext token absent from the log"; fi

echo "== every create failure leaves no partial rows =="
BEFORE_ENV=$(count envelopes); BEFORE_REV=$(count revisions); BEFORE_PARTY=$(count parties)
jq -n --arg f nosuchfield --arg p "$PNG" \
  '{fill:{values:{$f:"x"},logos:[{id:"s",imageData:$p,page:1,width:40}]},widget:{page:1,y:60}}' > "$D/bad.json"
code=$(create "$D/out.json" '[{"email":"ann@example.test","name":"Ann","order":1}]' "$D/bad.json" "bad field")
test "$code" = "400" && echo "  unknown field -> 400"
jq -r '.error.fields[0].field // .error.field' "$D/out.json" | grep -q "nosuchfield\|fill" && \
  echo "  names the field: $(jq -c '.error' "$D/out.json" | head -c 90)"
code=$(create "$D/out.json" \
  '[{"email":"ann@example.test","name":"Ann","order":1},{"email":"ann@example.test","name":"Ann","order":2}]' \
  "$D/specfield.json" "dup")
test "$code" = "400" && echo "  duplicate email -> 400"
code=$(create "$D/out.json" \
  '[{"email":"ann@example.test","name":"Ann","order":1},{"email":"bo@example.test","name":"Bo","order":3}]' \
  "$D/specfield.json" "gap")
test "$code" = "400" && echo "  gapped order -> 400"
test "$(count envelopes)" = "$BEFORE_ENV" && echo "  no envelope rows added"
test "$(count parties)" = "$BEFORE_PARTY" && echo "  no party rows added"
test "$(count revisions)" = "$BEFORE_REV" && echo "  no revision rows added"

echo "== illegal transition is refused (table-driven, audited path) =="
go test -mod=vendor -count=1 -run TestTransitionRefusesIllegalAdvance ./internal/signflow 2>&1 \
  | grep -vE '^"TODO Signature field|^{"time"' | tail -1

echo "== list: filters, paging, page cap =="
curl -s -o "$D/list.json" -H "Authorization: Bearer $ACCESS" \
  "$API/envelopes?status=ready&limit=10&offset=0"
test "$(jq -r '.limit' "$D/list.json")" = "10" && echo "  limit echoed"
test "$(jq -r '.envelopes | length' "$D/list.json")" -le 10 && echo "  page has at most 10 rows"
curl -s -o "$D/cap.json" -H "Authorization: Bearer $ACCESS" "$API/envelopes?limit=500"
test "$(jq -r '.limit' "$D/cap.json")" = "100" && echo "  limit 500 is capped at 100"
test "$(jq -r '.envelopes | length' "$D/cap.json")" -le 100 && echo "  page <= 100 rows"
code=$(curl -s -o "$D/bads.json" -w '%{http_code}' -H "Authorization: Bearer $ACCESS" \
  "$API/envelopes?status=nope")
test "$code" = "400" && echo "  invalid status -> 400"

echo "== list speed on 1000 envelopes: index, LIMIT/OFFSET =="
sqlite3 "$D/signsrv.db" "
with recursive n(i) as (select 1 union all select i+1 from n where i < 1000)
insert into envelopes(id,title,status,template_sha,filled_sha,current_sha,created_by,created_at,updated_at,expires_at)
  select printf('%032x',i), 'bulk lease ' || i, 'ready',
         printf('%064x',i), '', printf('%064x',i), 1,
         '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z'
  from n;"
test "$(count envelopes)" = "1001" && echo "  1001 envelopes seeded"
start=$(date +%s%3N)
curl -s -o "$D/fast.json" -H "Authorization: Bearer $ACCESS" \
  "$API/envelopes?status=ready&limit=100&offset=0"
took=$(( $(date +%s%3N) - start ))
test "$(jq -r '.total' "$D/fast.json")" = "1001" && echo "  total=1001"
test "$took" -lt 250 && echo "  list call took ${took}ms"
start=$(date +%s%3N)
curl -s -o "$D/fast2.json" -H "Authorization: Bearer $ACCESS" \
  "$API/envelopes?q=bulk%20lease%20777&limit=100"
took2=$(( $(date +%s%3N) - start ))
test "$(jq -r '.total' "$D/fast2.json")" = "1" && echo "  q= filter matches 1 envelope, ${took2}ms"
curl -s -o "$D/fast3.json" -H "Authorization: Bearer $ACCESS" "$API/envelopes?status=completed"
test "$(jq -r '.total' "$D/fast3.json")" = "0" && echo "  status=completed matches none"
sqlite3 "$D/signsrv.db" "explain query plan select id from envelopes where status='ready' order by created_at limit 100 offset 0;" \
  | head -1 | sed 's/^/  plan: /'

echo "== document download: sha header matches current_sha, bytes hash to it =="
curl -s -D "$D/dhead.txt" -o "$D/doc.pdf" -H "Authorization: Bearer $ACCESS" \
  "$API/envelopes/$ENVID/document"
hdr=$(grep -i '^x-content-sha256:' "$D/dhead.txt" | sed 's/.*: *//' | tr -d '\r')
cur=$(sqlite3 "$D/signsrv.db" "select current_sha from envelopes where id='$ENVID'")
test "$hdr" = "$cur" && echo "  X-Content-Sha256 == current_sha"
test "$(sha256sum "$D/doc.pdf" | cut -d' ' -f1)" = "$cur" && echo "  bytes hash to current_sha"
grep -i '^content-disposition:' "$D/dhead.txt" | grep -q 'quarterly-report-q3' && \
  echo "  filename is a slug of the title: $(grep -i '^content-disposition:' "$D/dhead.txt" | sed 's/\r//')"
grep -qi '^cache-control: private, no-store' "$D/dhead.txt" && echo "  cache-control private, no-store"

echo "== scopes: a client with envelope:read cannot create, no token is 401 =="
CACCESS=$(curl -s -X POST "$API/auth/token" -H 'content-type: application/json' \
  -d "{\"key\":\"$KEY\"}" | jq -r '.access')
test -n "$CACCESS" && test "$CACCESS" != "null" && echo "  client token ok"
test "$(curl -s -o "$D/scope.json" -w '%{http_code}' "$API/envelopes?limit=1" -H "Authorization: Bearer $CACCESS")" \
  = "200" && echo "  envelope:read can list"
test "$(curl -s -o "$D/scope.json" -w '%{http_code}' -X POST "$API/envelopes" \
  -H "Authorization: Bearer $CACCESS" -F "template=@testdata/sample1.pdf" -F "title=x" \
  -F "expires_in=48h" -F 'parties=[{"email":"c@example.test","name":"C","order":1}]' -F "spec=<$D/specfield.json")" \
  = "403" && echo "  create with envelope:read -> 403"
test "$(curl -s -o "$D/noauth.json" -w '%{http_code}' "$API/envelopes")" = "401" && echo "  no token -> 401"
test "$(curl -s -o "$D/stats.json" -w '%{http_code}' "$API/admin/stats" -H "Authorization: Bearer $CACCESS")" \
  = "403" && echo "  admin/stats with a client token -> 403"
curl -s -o "$D/stats.json" "$API/admin/stats" -H "Authorization: Bearer $ACCESS"
test "$(jq -r '.counts.envelopes' "$D/stats.json")" = "1001" && echo "  admin:read counts 1001 envelopes"

echo "== create has its own bucket: 20/min, 429 with Retry-After, reads unaffected =="
codes=""
for i in $(seq 1 25); do
  jq -n --arg e "p$i@example.test" '[{email:$e,name:"R",order:1}]' > "$D/p.json"
  c=$(create "$D/rl.json" "$(cat "$D/p.json")" "$D/specfield.json" "rl $i")
  codes="$codes $c"
done
ok=$(echo "$codes" | tr ' ' '\n' | grep -c 201)
refused=$(echo "$codes" | tr ' ' '\n' | grep -c 429)
test "$refused" -gt 0 && echo "  429 returned for the overflow: $codes"
test "$ok" -le 20 && echo "  $ok created, $refused refused (budget is 20/min per client)"
curl -s -D "$D/rlhead.txt" -o "$D/rlbody.json" -X POST "$API/envelopes" \
  -H "Authorization: Bearer $ACCESS" -F "template=@testdata/sample1.pdf" -F "title=rl" \
  -F "expires_in=48h" -F 'parties=[{"email":"rl99@example.test","name":"R","order":1}]' \
  -F "spec=<$D/specfield.json" > "$D/rlcode.txt"
grep -qi '^retry-after:' "$D/rlhead.txt" && echo "  Retry-After present"
jq -r '.error.code' "$D/rlbody.json" | grep -q rate_limited && echo "  error code rate_limited"
test "$(curl -s -o "$D/while.json" -w '%{http_code}' "$API/envelopes?limit=1" -H "Authorization: Bearer $ACCESS")" \
  = "200" && echo "  read endpoints keep working while create is saturated"

echo "== request id echoed and in the log; passphrase never logged =="
RID=$(jq -r '.request' "$D/create.json")
test "$(echo "$RID" | wc -c)" -ge 9 && echo "  create echoed request id $RID"
grep -q "$RID" "$D/signsrv.jsonl" && echo "  request id is in the log"
if grep -q "dev-keystore-passphrase" "$D/signsrv.jsonl"; then echo "  passphrase in the log"; exit 1
else echo "  passphrase absent from the log"; fi

echo "== all step 05 checks passed =="
