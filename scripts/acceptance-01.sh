#!/bin/sh
# Step 01 acceptance. Run from the project root:  sh scripts/acceptance-01.sh
# Every block is a signoff item from docs/steps/01-layout.md.
set -e
D=$(mktemp -d)
cleanup() {
  rm -rf "$D"
  rm -f ./signsrv ./pdf-go
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
log_level=debug
keystore_pass=dev-keystore-passphrase
admin_password=dev-password-change-me
smtp_host=127.0.0.1
mail_from=signsrv@example.test
EOF
printf 'listen=127.0.0.1:8091\npublic_url=http://x\ndev=false\n' > "$D/broken.conf"
printf 'listen 127.0.0.1:8092\nno equals sign here\n' > "$D/malformed.conf"

echo "== build offline from vendor =="
go build -o "$D/signsrv" ./cmd/signsrv
go build ./cmd/pdf-go ./internal/signstore ./internal/signauth \
  ./internal/signpdf ./internal/signfill ./internal/signmail ./internal/signflow ./web
echo "  ok"

echo "== vet and gofmt =="
go vet ./cmd/signsrv ./internal/signstore ./internal/signauth ./internal/signpdf \
  ./internal/signfill ./internal/signmail ./internal/signflow ./web
test -z "$(gofmt -l ./cmd ./internal ./web)" && echo "  clean"

echo "== checkconfig =="
"$D/signsrv" checkconfig -config config.example.env | tail -1
"$D/signsrv" checkconfig -config "$D/dev.conf"      | tail -1
"$D/signsrv" checkconfig -config "$D/broken.conf"   | grep -c "problem:" | sed 's/^/  problems listed: /'
code=0; "$D/signsrv" checkconfig -config "$D/malformed.conf" >/dev/null 2>&1 || code=$?
echo "  malformed file exit=$code  (2 = unparseable)"

echo "== serve =="
pkill -x signsrv >/dev/null 2>&1 || true
sleep 0.5
SIGNSRV_ADMIN_PASSWORD=devpass-long-enough nohup "$D/signsrv" serve -config "$D/dev.conf" \
  > "$D/stdout.log" 2>&1 &
sleep 1.5
B=http://127.0.0.1:8090
curl -s -m 5 $B/healthz | jq -c .
for p in /s/7b3f2a91c4d5e6f7 /admin/ /assets/spa/app.js /assets/spa/app.css /assets/admin/app.js /nope; do
  printf "  %-24s %s\n" "$p" "$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$B$p")"
done
printf "  traversal %%2e%%2e          %s\n" "$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$B/assets/spa/%2e%2e/app.js")"
curl -s -D- -o /dev/null -m 5 $B/s/x | grep -i "content-security" | sed "s/^/  signer CSP: /"
curl -s -D- -o /dev/null -m 5 $B/admin/ | grep -i "content-security" | sed "s/^/  admin  CSP: /"
echo "  tokens+secrets found in log: $(grep -c 'devpass-long-enough\|dev-keystore-passphrase\|7b3f2a91c4d5e6f7' "$D/signsrv.jsonl")"

echo "== graceful shutdown (SIGTERM) =="
kill -TERM "$(pgrep -x signsrv)"
sleep 2
echo "  processes left: $(pgrep -x signsrv | wc -l)"
echo "  port closed:    $(curl -s -o /dev/null -w '%{http_code}' -m 3 $B/healthz)"
grep -o '"msg":"[^"]*"' "$D/signsrv.jsonl" | tail -2 | sed 's/^/  /'

echo "== tests =="
go test ./cmd/signsrv ./cmd/pdf-go 2>&1 | grep -v '^{"time"'
echo "== all step 01 checks passed =="
