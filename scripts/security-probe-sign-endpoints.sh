#!/bin/sh
# security-probe-sign-endpoints.sh — the party-facing endpoints, without a session.
#
# Every line printed is a request that was sent and the answer the service
# gave. These are the probes behind docs/security-endpoint-audit.md. They
# check the ORDER of the refusals, because the order is the part a signing page
# cannot fake: a page that holds a link must learn nothing about a request
# until it has claimed it, and the claim is what is rate limited and logged.
#
# Nothing here consumes the link and nothing signs, so the probe is safe to run
# against a request that matters. The probes that change state are in
# security-probe-sign-endpoints2.sh.
#
# Usage:  sh scripts/security-probe-sign-endpoints.sh <base-url> <link-token>
#         sh scripts/security-probe-sign-endpoints.sh <base-url> <signing-link>
#
# Run it against a request nobody cares about. The link token is a bearer
# credential: it is printed elided here, and the service must never log it.

BASE=${1:?base URL, e.g. http://127.0.0.1:8090}
TOK=${2:?link token, or the whole signing link}
case $TOK in */s/*) TOK=${TOK##*/s/} ;; esac
W=$(mktemp -d)
FAILS=0
ELID=$(printf '%s' "$TOK" | cut -c1-12)

# r <method> <path> <want status> <want error code> [curl args...]
r() {
    m=$1; p=$2; want=$3; wcode=$4; shift 4
    case $m in
      HEAD) code=$(curl -sS -I -o "$W/h.txt" -w '%{http_code}' "$BASE$p" "$@" 2>/dev/null || echo 000) ;;
      GET)  code=$(curl -sS -o "$W/r.json" -w '%{http_code}' "$BASE$p" "$@" 2>/dev/null || echo 000) ;;
      *)    code=$(curl -sS -o "$W/r.json" -w '%{http_code}' -X "$m" "$BASE$p" "$@" 2>/dev/null || echo 000) ;;
    esac
    pp=$(printf %s "$p" | sed "s#$TOK#[token]#g")
    rc=$(jq -r '.error.code // empty' "$W/r.json" 2>/dev/null || echo '')
    if [ "$code" = "$want" ] && { [ -z "$wcode" ] || [ "$rc" = "$wcode" ]; }; then
        printf '  PASS  %-6s %-30s -> %s %s\n' "$m" "$pp" "$code" "$rc"
    else
        printf '  FAIL  %-6s %-30s -> %s %s, want %s %s\n' "$m" "$pp" "$code" "$rc" "$want" "$wcode"
        FAILS=$((FAILS + 1))
    fi
}
j() { # j <json> <path> <want> <label>
    printf '%s' "$1" > "$W/b.json"
    code=$(curl -sS -o "$W/r.json" -w '%{http_code}' -X POST \
        -H 'Content-Type: application/json' --data-binary "@$W/b.json" \
        "$BASE/api/v1/sign/$TOK/$2" 2>/dev/null || echo 000)
    rc=$(jq -r '.error.code // empty' "$W/r.json" 2>/dev/null || echo '')
    if [ "$code" = "$3" ] && { [ -z "$4" ] || [ "$rc" = "$4" ]; }; then
        printf '  PASS  POST %-27s -> %s %s\n' "$2" "$code" "$rc"
    else
        printf '  FAIL  POST %-27s -> %s %s, want %s %s\n' "$2" "$code" "$rc" "$3" "$4"
        FAILS=$((FAILS + 1))
    fi
}
note() { printf '        %s\n' "$*"; }

printf 'base %s   token %s... (elided)\n\n' "$BASE" "$ELID"

echo "== 1. a token that is not in the store"
r GET /api/v1/sign/nosuchtoken/envelope 404 not_found
note "no party, so no status. The answer for an unknown token is the answer for"
note "a stale one, so a probe cannot tell a link that never existed from a spent one."

echo
echo "== 2. the token in the path is not the session, and the body is not read first"
j '{}' consent 401 ''
note "401 BEFORE the body is parsed: the shape of a request's body is not"
note "information a link holder may collect."
j '{}' decline 401 ''
j '{"signature_text":"X","consent":true,"document_sha":"deadbeef"}' consent 401 ''
note "a well-formed body is refused for the same reason: the missing credential"
note "is the session, not the JSON shape. That is why the page must claim first."

echo
echo "== 3. a verb the mux does not route: the catch-all, and the log"
for v in DELETE PUT PATCH OPTIONS; do
    code=$(curl -sS -o "$W/r.json" -w '%{http_code}' -X "$v" \
        "$BASE/api/v1/sign/$TOK/consent" 2>/dev/null || echo 000)
    printf '  INFO  %-6s /api/v1/sign/<token>/consent -> %s\n' "$v" "$code"
done
r HEAD "/api/v1/sign/$TOK/envelope" 200 ''
note "HEAD on a GET route is served, headers and no body: that is the mux's"
note "method rule, and the answer carries no bytes, so nothing is revealed."
note "The catch-all records the path in the log. It must record it REDACTED, or"
note "one such request writes a live signing link into the log, the shipper, the"
note "12-week logrotate history and the support bundle. Proved by"
note "TestUnroutedSigningVerbDoesNotLogTheToken, which fails if the token"
note "appears anywhere in the log and fails if the redacted record is absent."

echo
echo "== 4. the body cap, on the real limit (204800 bytes)"
dd if=/dev/zero bs=1048576 count=2 status=none | tr '\0' 'a' > "$W/big.txt"
{ printf '{"signature_text":"'; cat "$W/big.txt"; printf '","consent":true,"document_sha":"x"}'; } > "$W/big.json"
code=$(curl -sS -o "$W/r.json" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' --data-binary "@$W/big.json" \
    "$BASE/api/v1/sign/$TOK/consent" 2>/dev/null || echo 000)
if [ "$code" = 400 ] || [ "$code" = 401 ]; then
    printf '  PASS  a 2 MiB consent body -> %s\n' "$code"
    note "refused before any decode. docs/api.md says 3 KiB; the service caps at"
    note "204800 (ledger item 39). The consent image has its own 1 MiB limit."
else
    printf '  FAIL  a 2 MiB consent body -> %s, want 400 or 401\n' "$code"
    FAILS=$((FAILS + 1))
fi

echo
echo "== 5. the claim is recorded, and a long name is refused"
printf '{"email":"probe@nowhere.test"}' > "$W/c1.json"
code=$(curl -sS -o "$W/r.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
    --data-binary "@$W/c1.json" "$BASE/api/v1/sign/$TOK/claim" 2>/dev/null || echo 000)
rc=$(jq -r '.error.code // empty' "$W/r.json" 2>/dev/null || echo '')
printf '  INFO  claim with an address nobody was invited -> %s %s\n' "$code" "$rc"
note "The address in the body is never compared with the invited address. The"
note "claim is what the signer says, and the ledger records it. The invited"
note "address is the credential's addressee, not a check at claim time."
long=$(printf 'x%.0s' $(seq 1 2000))
printf '{"email":"probe@nowhere.test","name":"%s"}' "$long" > "$W/c2.json"
code=$(curl -sS -o "$W/r.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
    --data-binary "@$W/c2.json" "$BASE/api/v1/sign/$TOK/claim" 2>/dev/null || echo 000)
printf '  INFO  claim with a 2000-rune name -> %s (claim fields are capped)\n' "$code"

echo
echo "== 6. the shell page, and the headers of the party's page"
curl -sS -D "$W/h2.txt" -o "$W/shell.html" "$BASE/s/$TOK" 2>/dev/null
for want in 'cache-control: no-store' 'x-content-type-options: nosniff' \
            'referrer-policy: no-referrer' 'content-security-policy'; do
    if grep -qi "^$want" "$W/h2.txt"; then
        printf '  PASS  the signing shell sends %s\n' "$want"
    else
        printf '  FAIL  the signing shell is missing %s\n' "$want"
        FAILS=$((FAILS + 1))
    fi
done
if grep -qi "$ELID" "$W/shell.html"; then
    printf '  FAIL  the shell page embedded the token in markup\n'
    FAILS=$((FAILS + 1))
else
    echo '  PASS  the shell page is static: no token, no envelope data'
    note "The page is served before the token is validated, so it can carry"
    note "nothing about the request. All the data comes from the API, after claim."
fi

echo
echo "== 7. endpoints that must not exist"
r GET "/api/v1/sign/$TOK/status" 404 not_found
r GET /api/v1/envelopes 401 ''
note "the admin surface needs a bearer token; a link is never an admin credential"

echo
if [ "$FAILS" -eq 0 ]; then
    echo "ALL PROBES PASSED. The state-changing probes are in probe 2."
    rm -rf "$W"; exit 0
fi
echo "$FAILS probe(s) failed. Workspace: $W"
exit 1
