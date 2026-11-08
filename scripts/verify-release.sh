#!/bin/sh
# verify-release.sh — the release gate, as one runnable script.
#
# It drives a throwaway instance end to end (upload, fill, create, send, claim,
# consent, sign, deliver), probes the party-facing endpoints, and reads the
# instance's LOG looking for credentials. Every line it prints is a fact about
# the binary it just ran.
#
# Usage:
#   sh scripts/verify-release.sh <bin-dir> <base-url> <client-key>
#
#   bin-dir    the directory holding signsrv and pdf-go
#   base-url   the instance under test, e.g. http://127.0.0.1:47099
#   client-key a client key from `signsrv client add name envelope:write envelope:read`
#
# The last section SIGNS. Run it against a request nobody cares about.
#
# The instance must be configured with a log_path; the script reads that file
# and fails if any credential appears in it.

set -eu
BIN=${1:?bin-dir holding signsrv and pdf-go}
BASE=${2:?base URL}
KEY=${3:?client key}
OUT=$(mktemp -d)
INSECURE=""
case $BASE in http://*) INSECURE=-insecure ;; esac
FAILS=0
say() { printf '%s\n' "$*"; }
ok()  { say "  PASS  $*"; }
bad() { say "  FAIL  $*"; FAILS=$((FAILS + 1)); }
need() { [ "$1" = "$2" ] && ok "$3 -> $1" || bad "$3 -> $1, want $2"; }
# mask <text> <secret>: redact before anything is printed. The secret travels
# in the child's environment, not its argv, so it does not appear in `ps`.
mask() { M="$2" awk '{gsub(ENVIRON["M"], "[token]")}1' <<TEXT
$1
TEXT
}

say "== the binaries"
for b in signsrv pdf-go; do
    [ -x "$BIN/$b" ] && ok "$b: $("$BIN/$b" version)" || bad "$b missing in $BIN"
done
[ "$FAILS" -eq 0 ] || { say "build the binaries first"; exit 1; }

say "== health"
need "$(curl -sS -o "$OUT/health.json" -w '%{http_code}' "$BASE/healthz")" 200 "GET /healthz"

say "== the client key exchanges for a scoped token (it is not itself a bearer token)"
curl -sS -o "$OUT/tok.json" -H 'Content-Type: application/json' \
    -X POST -d "{\"key\":\"$KEY\"}" "$BASE/api/v1/auth/token"
ACCESS=$(jq -r '.access // empty' "$OUT/tok.json")
[ -n "$ACCESS" ] && ok "auth/token -> access token of ${#ACCESS} chars" || \
    bad "auth/token returned no access token: $(head -c 140 "$OUT/tok.json")"
need "$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $KEY" "$BASE/api/v1/envelopes")" \
    401 "the raw client key replayed as a bearer token"
AUTH="Authorization: Bearer $ACCESS"

say "== the CLI's transport guard: a client token over plain HTTP travels in the clear"
guard=$(env NOP=deadbeef "$BIN/pdf-go" envelope get --server "$BASE" --token-env NOP x 2>&1 || true)
case "$BASE" in
  http://*) printf '%s' "$guard" | grep -qi 'plain HTTP' && \
      ok "pdf-go refuses plain HTTP without -insecure" || \
      bad "pdf-go accepted plain HTTP: $guard" ;;
  *) ok "https: the guard is scheme-only, not exercised here" ;;
esac

say "== create --send, one party (the document rides in the create body)"
cd "$(dirname "$0")/.."
cat > "$OUT/parties.json" <<'JSON'
[{"email":"release@verify.test","name":"Release Verifier","order":1,"reason":"I agree to the terms"}]
JSON
# A fill spec with values: the service rejects an empty fill, so the script
# carries its own rather than depending on a previous run's files. The field
# names are those of testdata/sample2.pdf (see: pdf-go extract).
cat > "$OUT/fill.json" <<'JSON'
{"values":{"Text1":"Release Verifier","Text2":"2026-11-08","Text3":"USD 1",
 "Text4":"Release verification run","Text5":"Release verification","Text6":"signed by Release Verifier"}}
JSON
env NOP=$ACCESS "$BIN/pdf-go" envelope create \
    --server "$BASE" --token-env NOP $INSECURE \
    --title "Release verification" --expires 72h \
    --spec "$OUT/fill.json" --parties "$OUT/parties.json" --links-out "$OUT/links.json" \
    --send testdata/sample2.pdf > "$OUT/create.json" 2>"$OUT/create.err" || \
    { bad "create: $(head -c 200 "$OUT/create.err")"; exit 1; }
# `--send` prints the create response and then the send response into the same
# file: two JSON documents. The envelope's settled state and the DELIVERED link
# are in the LAST one — the create response's links are the never-delivered
# tokens, which the send invalidates. Reading the first document would test the
# wrong credential, which is exactly the mistake the old negatives made.
ENVID=$(jq -s -r '.[-1].envelope.id' "$OUT/create.json")
need "$(jq -s -r '.[-1].envelope.status' "$OUT/create.json")" sent "create --send leaves the request"
TOKEN=$(jq -s -r '.[-1].links[0].token // empty' "$OUT/create.json")
[ -n "$TOKEN" ] && ok "the send response carries the live link (printed elided: $(printf '%s' "$TOKEN" | cut -c1-8)…)" || \
    { bad "no link in the create response"; exit 1; }

say "== the party-facing refusals, in the order the page runs them"
r() { m=$1; p=$2; want=$3; wcode=$4; shift 4
    code=$(curl -sS -o "$OUT/r.json" -w '%{http_code}' -X "$m" "$BASE$p" "$@" 2>/dev/null || echo 000)
    rc=$(jq -r '.error.code // empty' "$OUT/r.json" 2>/dev/null || echo '')
    pp=$(mask "$p" "$TOKEN")
    if [ "$code" = "$want" ] && { [ -z "$wcode" ] || [ "$rc" = "$wcode" ]; }; then
        ok "$m $pp -> $code $rc"
    else
        bad "$m $pp -> $code $rc, want $want $wcode"
    fi; }
postj() { # postj <path> <json> <want status> <want error code>
    printf '%s' "$2" > "$OUT/b.json"
    code=$(curl -sS -o "$OUT/r.json" -w '%{http_code}' -X POST \
        -H 'Content-Type: application/json' --data-binary "@$OUT/b.json" \
        "$BASE/api/v1/sign/$TOKEN/$1" 2>/dev/null || echo 000)
    rc=$(jq -r '.error.code // empty' "$OUT/r.json" 2>/dev/null || echo '')
    if [ "$code" = "$3" ] && { [ -z "$4" ] || [ "$rc" = "$4" ]; }; then
        ok "POST $1 -> $code $rc"
    else
        bad "POST $1 -> $code $rc, want $3 $4"
    fi; }
postjs() { # postjs <path> <json> <want status> <want error code>  (sends the session cookie)
    printf '%s' "$2" > "$OUT/b.json"
    code=$(curl -sS -b "$OUT/jar" -o "$OUT/r.json" -w '%{http_code}' -X POST \
        -H 'Content-Type: application/json' --data-binary "@$OUT/b.json" \
        "$BASE/api/v1/sign/$TOKEN/$1" 2>/dev/null || echo 000)
    rc=$(jq -r '.error.code // empty' "$OUT/r.json" 2>/dev/null || echo '')
    if [ "$code" = "$3" ] && { [ -z "$4" ] || [ "$rc" = "$4" ]; }; then
        ok "POST $1 (with the session) -> $code $rc"
    else
        bad "POST $1 (with the session) -> $code $rc, want $3 $4"
    fi; }
r GET /api/v1/sign/nosuchtoken/envelope 404 not_found
postj consent '{}' 401 ''
postj decline '{}' 401 ''
postj consent '{"signature_text":"X","consent":true,"document_sha":"deadbeef"}' 401 ''
say "        (the body is not read before the session: 401 on all three)"
r PUT "/api/v1/sign/$TOKEN/consent" 404 not_found
r GET "/api/v1/sign/$TOKEN/status" 404 not_found
dd if=/dev/zero bs=1048576 count=2 status=none | tr '\0' 'a' > "$OUT/big.txt"
{ printf '{"signature_text":"'; cat "$OUT/big.txt"; printf '","consent":true,"document_sha":"x"}'; } > "$OUT/big.json"
code=$(curl -sS -o "$OUT/r.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
    --data-binary "@$OUT/big.json" "$BASE/api/v1/sign/$TOKEN/consent")
if [ "$code" = 400 ] || [ "$code" = 413 ] || [ "$code" = 401 ]; then
    ok "a 2 MiB consent body -> $code (the cap is 204800, ledger item 39)"
else
    bad "a 2 MiB consent body -> $code, want 400/413/401"
fi

say "== claim, then the session"
printf '{"email":"release@verify.test"}' > "$OUT/claim.json"
need "$(curl -sS -c "$OUT/jar" -o "$OUT/r.json" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' --data-binary @"$OUT/claim.json" \
    "$BASE/api/v1/sign/$TOKEN/claim")" 200 "claim with the invited address"
need "$(curl -sS -b "$OUT/jar" -o "$OUT/view.json" -w '%{http_code}' \
    "$BASE/api/v1/sign/$TOKEN/envelope")" 200 "the view, with the session"
DSHA=$(jq -r '.document_sha // empty' "$OUT/view.json")
[ -n "$DSHA" ] && ok "the view names the document digest" || bad "the view carries no document digest"
jq -e '.parties' "$OUT/view.json" >/dev/null 2>&1 && \
    ok "the post-claim view carries the signing order (by design: a party sees who else signs)" || \
    bad "the post-claim view has no party list"
# With a session established, the same body cap is enforced BEFORE the body is
# decoded: 400/413, not 200. The pre-session answer was 401, which proves the
# ordering; this proves the cap itself.
code=$(curl -sS -b "$OUT/jar" -o "$OUT/r.json" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' --data-binary "@$OUT/big.json" \
    "$BASE/api/v1/sign/$TOKEN/consent")
if [ "$code" = 400 ] || [ "$code" = 413 ]; then
    ok "a 2 MiB body WITH a session -> $code (cap 204800; docs/api.md says 3 KiB, ledger item 39)"
else
    bad "a 2 MiB body with a session -> $code, want 400/413"
fi
jq -e '.my.email' "$OUT/view.json" >/dev/null 2>&1 && \
    bad "the view echoes the invited address" || ok "the view never echoes the address"

say "== consent, and the signed bytes"
{ printf '{"signature_text":"Release Verifier","consent":true,"document_sha":"%s"}' "$DSHA"; } > "$OUT/consent.json"
need "$(curl -sS -b "$OUT/jar" -o "$OUT/r.json" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' --data-binary @"$OUT/consent.json" \
    "$BASE/api/v1/sign/$TOKEN/consent")" 200 "consent naming the digest the view gave"
postjs decline '{"reason":"too late"}' 409 state_conflict
postjs consent '{"signature_text":"Late","consent":true,"document_sha":"x"}' 409 state_conflict
postjs claim '{"email":"release@verify.test"}' 409 state_conflict
say "        (once signed, every party verb answers 409 state_conflict: the link is spent"
say "        (and the envelope is terminal, so there is no other honest answer)"
WATCHRC=0
env NOP=$ACCESS "$BIN/pdf-go" envelope get --server "$BASE" --token-env NOP $INSECURE --watch "$ENVID" > "$OUT/watch.out" 2>"$OUT/watch.err" || WATCHRC=$?
need "$WATCHRC" 0 "envelope get --watch: signed and delivered (exit 0)"
SIGNED=$(jq -s -r '.[-1].document_sha // empty' "$OUT/watch.out")
[ -n "$SIGNED" ] && ok "the signed revision has its own digest: $SIGNED" || bad "no signed digest"

say "== the admin reads (an admin session, not a client token)"
ADMINJAR="$OUT/admin.jar"
code=$(curl -sS -c "$ADMINJAR" -o "$OUT/alogin.json" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"${ADMIN_EMAIL:-rel@test.dev}\",\"password\":\"${ADMIN_PW:-rel-admin-pass}\"}" \
    "$BASE/api/v1/auth/login")
need "$code" 200 "POST auth/login as an operator"
AAUTH="Authorization: Bearer $(jq -r '.access // empty' "$OUT/alogin.json")"
# The login response is a bearer token (admin:read scope). The cookie jar is
# empty by design: the operator's own session cookie belongs to the admin SPA,
# and the login endpoint hands out the token for it.
need "$(printf %s "$AAUTH" | grep -q 'Bearer ..' && echo ok)" ok "the login response carries a bearer token"
for a in admin/stats admin/dbstatus admin/schema admin/configcheck admin/users admin/clients; do
    need "$(curl -sS -o /dev/null -w '%{http_code}' -H "$AAUTH" "$BASE/api/v1/$a")" 200 "GET $a"
done
need "$(curl -sS -o "$OUT/ev.json" -w '%{http_code}' -H "$AAUTH" \
    "$BASE/api/v1/admin/events?envelope=$ENVID")" 200 "GET admin/events?envelope=... (paged, newest first)"
jq -s -e '.[-1].events | length > 0' "$OUT/ev.json" >/dev/null 2>&1 && \
    ok "the envelope's audit log has rows" || bad "the envelope's audit log is empty"
# An envelope id that matches nothing answers an EMPTY log, not 404: a typo in
# an id is not a bad request, and the empty answer plus the total tells the
# operator which it was. (This is the documented behaviour; the probe keeps it
# documented.)
curl -sS -o "$OUT/evnone.json" -H "$AAUTH" "$BASE/api/v1/admin/events?envelope=nosuchenvelope"
jq -s -e '.[-1].events | length == 0' "$OUT/evnone.json" >/dev/null 2>&1 && \
    ok "GET admin/events for an unknown envelope -> an empty log, not an error" || \
    bad "GET admin/events for an unknown envelope is not an empty log"
need "$(curl -sS -o /dev/null -w '%{http_code}' -H "$AAUTH" \
    "$BASE/api/v1/admin/events?limit=-5")" 400 "GET admin/events?limit=-5"
need "$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/api/v1/admin/stats")" 401 "GET admin/stats with no credential"
need "$(curl -sS -o "$OUT/audit.zip" -w '%{http_code}' -H "$AUTH" \
    "$BASE/api/v1/envelopes/$ENVID/audit.zip")" 200 "GET audit.zip with a client token"
unzip -l "$OUT/audit.zip" >/dev/null 2>&1 && \
    ok "the bundle opens: $(unzip -l "$OUT/audit.zip" | tail -1 | awk '{print $2}') entries" || \
    bad "the bundle is not a readable zip"
need "$(curl -sS -o /dev/null -w '%{http_code}' -H "$AUTH" \
    "$BASE/api/v1/admin/stats")" 403 "GET admin/stats with a client token (the scope check)"

say "== the log holds no credential, and the catch-all record is redacted"
LP=""
if [ -n "${4:-}" ] && [ -f "$4" ]; then
    LP=$(sed -n 's/^[[:space:]]*log_path[[:space:]]*=[[:space:]]*//p' "$4" | tr -d '"')
fi
if [ -n "$LP" ] && [ -f "$LP" ]; then
    say "  INFO  log under test: $LP ($(wc -l < "$LP") records)"
    for secret in "$TOKEN" "$ACCESS" "$KEY"; do
        [ -n "$secret" ] || continue
        if grep -q "$secret" "$LP"; then
            bad "a credential appears in the log in the clear ($(grep -c "$secret" "$LP") lines)"
        else
            ok "no trace of a credential in $(wc -l < "$LP") records"
        fi
    done
    grep -q '/api/v1/sign/\[token\]/consent' "$LP" && \
        ok "the unrouted signing probe is in the log, REDACTED" || \
        say "  INFO  no redacted catch-all record found (the PUT probe above should have written one)"
else
    bad "log_path not resolvable: the release gate requires the log check (unit twin: TestAccessLogNeverCarriesASecret)"
fi

say "== result"
if [ "$FAILS" -eq 0 ]; then say "  ALL GREEN   workspace: $OUT"; exit 0; fi
say "  $FAILS FAILURE(S)   workspace: $OUT"; exit 1
