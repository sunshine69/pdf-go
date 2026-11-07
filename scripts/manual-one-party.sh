#!/bin/sh
# The new way, by hand. Steps 1-7: build, configure, start, log in, mint the
# client key, create a ONE-party request, send it. Every step prints the
# command shape and the service's real answer.
set -e
cd .
B=/tmp/manual
rm -rf $B && mkdir -p $B/log $B/keystore $B/storage $B/outbox $B/audit $B/out
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
ADMIN_PASS=manual-admin-password-long-9
ADMIN=ana@manual.test

echo "== 1. build (three binaries: service, CLI, TSA mock)"
go build -o $B/signsrv ./cmd/signsrv
go build -o $B/pdf-go ./cmd/pdf-go
go build -o $B/mocktsa ./cmd/mock-tsa
ls -1 $B/signsrv $B/pdf-go $B/mocktsa | sed 's/^/   /'

echo
echo "== 2. config: one env file, mode 0600, loopback only, dev = true"
cat > $B/signsrv.env <<EOF
listen = 127.0.0.1:$PORT
public_url = http://127.0.0.1:$PORT
dev = true
db = $B/manual.db
storage_dir = $B/storage
keystore_dir = $B/keystore
outbox_dir = $B/outbox
audit_dir = $B/audit
log_path = $B/log/signsrv.jsonl
log_level = info
jwt_secret_file = $B/jwt.ed25519.key
keystore_pass = manual-keystore-passphrase
link_ttl = 72h
mail_from = signsrv@manual.test
tsa_url = http://127.0.0.1:5193/tsr
EOF
chmod 600 $B/signsrv.env
echo "   $B/signsrv.env is mode $(stat -c %a $B/signsrv.env)"
grep -E '^(listen|public_url|dev|tsa_url|link_ttl) ' $B/signsrv.env | sed 's/^/   /'
echo "   note: admin_password is NOT in the file — the admin's password is set"
echo "   by the operator's own command, below."

echo
echo "== 3. migrate + checkconfig, then start the TSA mock and the service"
$B/signsrv checkconfig -config $B/signsrv.env | sed 's/^/   /'
$B/signsrv migrate -config $B/signsrv.env | tail -3 | sed 's/^/   /'
nohup $B/mocktsa -listen 127.0.0.1:5193 >$B/log/mocktsa.log 2>&1 &
sleep 0.3
nohup $B/signsrv serve -config $B/signsrv.env >$B/log/stdout.log 2>&1 &
echo $! > $B/pid
for i in $(seq 1 60); do
  curl -fsS http://127.0.0.1:$PORT/healthz >/dev/null 2>&1 && break
  sleep 0.25
done
echo "   mock-tsa: $(sed -n 's/^.*mock-tsa/mock-tsa/p' $B/log/mocktsa.log)"
echo "   signsrv serve: pid $(cat $B/pid)"
echo "   GET /healthz -> $(curl -fsS http://127.0.0.1:$PORT/healthz)"

echo
echo "== 4. the admin account, created by the operator; password in the env"
SIGNSRV_ADMIN_PASSWORD=$ADMIN_PASS $B/signsrv admin add $ADMIN -config $B/signsrv.env \
  | sed 's/^/   /'

echo
echo "== 5. login (the only login: POST /api/v1/auth/login, JSON only)"
code=$(curl -sS -o $B/out/login.json -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$ADMIN\",\"password\":\"$ADMIN_PASS\"}" \
  http://127.0.0.1:$PORT/api/v1/auth/login)
jq -r '.access' $B/out/login.json > $B/admin.token
echo "   POST /api/v1/auth/login -> HTTP $code"
jq -c 'with_entries(select(.key != "access"))' $B/out/login.json | sed 's/^/   answer (access elided): /'
echo "   the access token: $(cut -c1-24 $B/admin.token)... ($(wc -c < $B/admin.token) bytes, 3 dot-separated parts)"
echo "   admin token: $(wc -c < $B/admin.token) bytes of JWT, three parts: $(awk -F. '{print NF}' $B/admin.token)"

echo
echo "== 6. a client API key for the CLI (envelope:write, envelope:read)"
$B/signsrv client add manual-cli envelope:write envelope:read -config $B/signsrv.env \
  > $B/out/client-add.txt
sed -n 's/^key: //p' $B/out/client-add.txt > $B/client.key
chmod 600 $B/client.key
echo "   signsrv client add -> $(head -2 $B/out/client-add.txt | tr '\n' ' ')"
echo "   the key: $(wc -c < $B/client.key) bytes, printed once; the store keeps its digest"
cat > $B/parties.json <<'EOF'
[{"email":"ana@manual.test","name":"Ana Renderer","order":1,"reason":"I agree to the terms"}]
EOF
chmod 600 $B/parties.json
cat > $B/fill.json <<'EOF'
{"values":{"Text1":"Acme Ltd","Text2":"2026-11-08","Text3":"USD 12,400",
"Text4":"Twelve widgets, net 30 days.","Text5":"Acme / Beta supply agreement",
"Text6":"manual run, one party"}}
EOF

echo
echo "== 7. prepare the ONE-party request with the CLI"
echo "   fill spec: 6 field values; parties: $(jq -c '.[0] | {email, name, order}' $B/parties.json)"
E2E_CLIENT_KEY=$(cat $B/client.key) $B/pdf-go envelope create \
  -server http://127.0.0.1:$PORT -token-env E2E_CLIENT_KEY -insecure \
  -title "Acme supply agreement" -expires 72h \
  -spec $B/fill.json -parties $B/parties.json \
  -links-out $B/links.json testdata/sample2.pdf > $B/out/create.json
sed 's/^/   /' $B/out/create.json
ENV=$(jq -r '.envelope.id' $B/out/create.json)
echo "   status: $(jq -r '.envelope.status' $B/out/create.json)  fields applied: $(jq '.fill.applied|length' $B/out/create.json)  missing: $(jq '.fill.missing|length' $B/out/create.json)"
echo "   envelope id: $ENV"

echo
echo "== 8. send it"
E2E_CLIENT_KEY=$(cat $B/client.key) $B/pdf-go envelope send \
  -server http://127.0.0.1:$PORT -token-env E2E_CLIENT_KEY -insecure \
  -links-out $B/links.json $ENV > $B/out/send.json
jq -c '{status: .envelope.status, links: [.links[] | {email, url}]}' $B/out/send.json \
  | jq . | sed 's/^/   /'
echo "   links file: $B/links.json mode $(stat -c %a $B/links.json)"
# The key is the credential; the token is what rides on a call. Exchange once,
# then read the request back as the client, the way any API caller would.
curl -sS -X POST -H 'Content-Type: application/json' \
  -d "{\"key\":\"$(cat $B/client.key)\"}" \
  http://127.0.0.1:$PORT/api/v1/auth/token > $B/out/token.json
jq -r '.access // empty' $B/out/token.json > $B/client.token
echo "   POST auth/token -> $(jq -c 'with_entries(select(.key != "access" and .key != "refresh"))' $B/out/token.json)"
curl -sS -H "Authorization: Bearer $(cat $B/client.token)" \
  http://127.0.0.1:$PORT/api/v1/envelopes/$ENV > $B/out/envelope.json
jq -c '{id, status, title, document_sha, expires_at,
        parties: [.parties[] | {email, status}]}' $B/out/envelope.json \
  | jq . | sed 's/^/   /'

echo
echo "== 9. the invitation, as the party receives it"
for i in $(seq 1 40); do
  [ "$(ls -1 $B/outbox/*.eml 2>/dev/null | wc -l)" -ge 1 ] && break
  sleep 0.25
done
ls -1 $B/outbox/*.eml | sed 's/^/   /'
grep -m1 -E '^(To|Subject):' $B/outbox/*.eml | sed 's/^/   /'
sed -n 's/.*\(http:\/\/127.0.0.1:[0-9]*\/s\/[A-Za-z0-9]*\).*/   signing link: \1/p' $B/outbox/*.eml | head -1
echo
echo "PREPARED. Envelope $ENV is sent with ONE party; the signing link is in"
echo "$B/links.json and in the .eml under $B/outbox. Server pid $(cat $B/pid) on 127.0.0.1:$PORT."
echo
echo "== 10. is the request ready for the party to sign?"
L=$(jq -r ".links[0].token" $B/links.json)
curl -sS http://127.0.0.1:$PORT/api/v1/sign/$L/envelope > $B/out/party-view.json
jq -c "{title, status, document_sha: (.document_sha[0:16]), expires_at, parties: [.parties[] | {email, name, status}]}" $B/out/party-view.json | sed "s/^/   /"
code=$(curl -sS -o $B/out/party-claim.json -w "%{http_code}" -X POST -H "Content-Type: application/json" -d "{\"email\":\"ana@manual.test\"}" http://127.0.0.1:$PORT/api/v1/sign/$L/claim)
echo "   POST sign/<token>/claim -> HTTP $code (the session cookie is set; the signing page is armed)"
echo "   open in a browser: http://127.0.0.1:$PORT/s/$L"
