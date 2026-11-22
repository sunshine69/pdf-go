#!/bin/sh
# release-gate-dev.sh — run scripts/verify-release.sh against a throwaway
# instance, from an empty directory to a verdict.
#
#   sh scripts/release-gate-dev.sh          # ALL GREEN -> exit 0
#
# verify-release.sh drives the endpoints but creates nothing: it logs in as an
# operator and exchanges a client key, both of which must exist first. This
# script starts an instance with a fresh database, seeds exactly those two
# rows, runs the gate, and tears the instance down. It is the difference
# between "the gate failed" and "the gate could not start".
#
# dev=true, so mail is written to the outbox instead of reaching a relay, and
# the listener is loopback. Nothing here touches tmp/real or the instance on
# :8090. The gate signs a throwaway document; it is not a request anyone cares
# about.

set -eu

D=tmp/rel-gate
PORT=${GATE_PORT:-18099}
BASE=http://127.0.0.1:$PORT

# The gate logs in with these; they are the gate's own defaults.
ADMIN_EMAIL=${ADMIN_EMAIL:-rel@test.dev}
ADMIN_PW=${ADMIN_PW:-rel-admin-pass}

say() { printf '%s\n' "$*"; }
die() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }

# Build from the tree you are standing in, so the verdict describes this code.
mkdir -p "$D"

say "== build"
go build -trimpath -ldflags "-s -w" -o "$D/signsrv" ./cmd/signsrv
go build -trimpath -ldflags "-s -w" -o "$D/pdf-go"  ./cmd/pdf-go
say "   $("$D/signsrv" version)  $("$D/pdf-go" version)"

# An instance left over from a previous run answers on the port from a database
# this script is about to delete: the flow still passes (SQLite writes through
# the deleted inode) but the log check reads a file nobody is writing, and the
# verdict describes the wrong process. Kill by pid, then refuse to start if the
# port is still taken.
if [ -f "$D/serve.pid" ]; then
    kill "$(cat "$D/serve.pid")" 2>/dev/null || true
    sleep 1
fi
if curl -s --max-time 2 -o "$D/pre.probe" "$BASE/healthz"; then
    die "$BASE is already answering. Find it (pgrep -a signsrv) and stop it;
     this script cannot tell whose database the gate would then have driven."
fi

say "== fresh instance"
rm -f "$D/signsrv.db" "$D/signsrv.db-wal" "$D/signsrv.db-shm" "$D/signsrv.jsonl"
rm -rf "$D/storage" "$D/keystore" "$D/outbox" "$D/audit"
mkdir -p "$D/storage" "$D/keystore" "$D/outbox" "$D/audit"

cat > "$D/dev.conf" <<EOF
listen=127.0.0.1:$PORT
public_url=http://127.0.0.1:$PORT
dev=true
db=$D/signsrv.db
storage_dir=$D/storage
keystore_dir=$D/keystore
outbox_dir=$D/outbox
audit_dir=$D/audit
log_path=$D/signsrv.jsonl
jwt_secret_file=$D/jwt.ed25519.key
link_ttl=168h
max_pdf_mb=25
log_level=info
worker_interval=5s
EOF

nohup "$D/signsrv" serve -config "$D/dev.conf" > "$D/serve.out" 2>&1 &
SRV=$!
echo "$SRV" > "$D/serve.pid"

cleanup() {
    kill "$SRV" 2>/dev/null || true
    wait "$SRV" 2>/dev/null || true
    rm -f "$D/serve.pid"
}
trap cleanup EXIT INT TERM

# Fail on a refusal to start rather than on a timeout: a listener that is
# somebody else's answers the health check perfectly.
i=0
until [ -s "$D/signsrv.jsonl" ] && curl -s --max-time 2 -o "$D/health.json" "$BASE/healthz"; do
    if ! kill -0 "$SRV" 2>/dev/null; then
        die "the instance exited. Last lines of its output: $(tail -3 "$D/serve.out")"
    fi
    i=$((i + 1))
    [ "$i" -ge 30 ] && die "the instance never answered on $BASE"
    sleep 1
done
grep -q "address already in use" "$D/serve.out" \
    && die "port $PORT was taken after all: the gate would have driven the wrong process"
say "   listening: $(tr -d '\n ' < "$D/health.json")"

say "== seed (the gate needs an operator and a machine client)"
ADMIN_PASSWORD="$ADMIN_PW" "$D/signsrv" admin add "$ADMIN_EMAIL" \
    -config "$D/dev.conf" > "$D/admin.out" 2>&1 || die "admin add: $(cat "$D/admin.out")"
say "   $(tail -1 "$D/admin.out")"

"$D/signsrv" client add relgate envelope:write envelope:read envelope:cancel \
    -config "$D/dev.conf" > "$D/client.out" 2>&1 || die "client add: $(cat "$D/client.out")"
KEY=$(sed -n 's/^key: \(key_[0-9a-f]*\)$/\1/p' "$D/client.out" | head -1)
# Checking the shape, not just emptiness: a broken extraction produces a key the
# server correctly rejects, and the 401 reads like a server bug. A length check
# names the real culprit. (A replacement of "1" for "\1" here passed an emptiness
# test and wasted a run.)
# Print the shape of the output, never its content: the file holds a live key.
[ ${#KEY} -eq 68 ] || { echo "key extraction gave ${#KEY} chars, want 68 (client.out has $(wc -l < "$D/client.out") lines)"; exit 1; }
say "   client relgate (key read once, not echoed)"

say "== the gate"
# The gate's exit code is the verdict. Two traps here: `set -e` would end this
# script the moment the gate fails, before the code is captured, and piping the
# gate through tail would measure tail's status instead of the gate's. Both are
# ways a gate becomes a gate that cannot fail.
RC=0
sh scripts/verify-release.sh "$D" "$BASE" "$KEY" "$D/dev.conf" > "$D/gate.out" 2>&1 || RC=$?
tail -30 "$D/gate.out"
printf '   full output: %s/gate.out (exit %d)\n' "$D" "$RC"

cleanup
trap - EXIT INT TERM

# The port must be closed by now. If it is not, this script did not stop the
# process it started, and the next run cannot be trusted to drive a fresh one.
if curl -s --max-time 2 -o "$D/post.probe" "$BASE/healthz"; then
    say "   !! something still answers $BASE - find it with pgrep -a signsrv"
    [ "$RC" -eq 0 ] && RC=1
fi

exit $RC
