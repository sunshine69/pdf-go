#!/bin/sh
# scripts/prod-sign-run.sh — the production regression, over the API only.
#
#   scripts/prod-sign-run.sh                             run it (any number of times)
#   WAIT=1 scripts/prod-sign-run.sh                       run, then wait and verify
#   scripts/prod-sign-run.sh report <envelope-id>         re-verify a past run
#   scripts/prod-sign-run.sh cancel  <envelope-id>        close an open test link
#
#   BASE=... DOC=... PARTY=... PARTY_NAME=... TITLE=...   overrides (all optional)
#   FORCE_NEW=1                                           dispatch another envelope
#                                                         instead of reusing this one
#
# WHAT THE RUN DOES. The example form is read and filled locally with the pdf-go built
# from this source tree; one party (PARTY_NAME / PARTY) is invited; the server applies
# the fill spec, certifies the bytes, and the party signs in a browser from the link the
# run prints. Then the signature is verified over the API.
#
# HOW IT TALKS TO THE SERVER — the rule this script does not break
#
#     the HTTPS API endpoint (BASE, default https://test-pdfsign.kaykraft.org), and
#     the pdf-go CLI, built from ./cmd/pdf-go in this tree.
#
# There is no docker in this script: no `docker compose`, no `docker exec`, no
# `docker cp`, no volume paths, no shell on the server. Every question the run asks —
# credentials, the API credential, whether the mail left, whether the audit chain is
# intact, whether the archived bytes are the bytes that were signed — is asked over
# HTTPS. That is what makes the run worth running: it proves what a real client can
# prove, from where a real client stands. The only local file reads are the example PDF
# (testdata/sample2.pdf) and the two config files that already hold the admin login;
# the only local writes are under tmp/prod-run.
#
# THE STAGES, IN ORDER
#
#   preflight   curl, jq, openssl, base64 exist; $BASE/healthz answers 200
#   build       rebuild pdf-go with -trimpath from ./cmd/pdf-go, every run (the CLI is
#               half of what is under test, and a run driven by a stale binary cannot be
#               attributed to this tree)
#   credentials the admin address comes from deploy/docker-compose.test.yml
#               (DEFAULT_ADMIN_EMAIL) and the password from deploy/.env.test
#               (ADMIN_PASSWORD). Both files are already 0600; neither is ever printed.
#               POST /api/v1/auth/login turns that pair into a bearer token, cached in
#               tmp/prod-run/admin.token and reused until it is within a minute of the
#               exp claim in the JWT itself.
#   client key  tmp/prod-run/client.key is checked against POST /api/v1/auth/token and,
#               if the service does not accept it, a new one is minted with
#               POST /api/v1/admin/clients (envelope:write envelope:read). That answer
#               shows the key once; it is kept at 0600. The key is then exchanged ONCE
#               per run for a bearer token (tmp/prod-run/client.bearer) and handed to
#               pdf-go, which recognises an access token by its three parts and does not
#               exchange it again. Without that, every pdf-go verb would spend another
#               hit on the token endpoint, which is limited to 5 requests per minute per
#               address — and every request of this run arrives from one address,
#               because the proxy is the client.
#   document    pdf-go extract the form, write the fill spec (the party's name and the
#               date), fill it, re-read it and prove the values landed
#   dispatch    pdf-go envelope create (title, expiry, spec, one party), then
#               pdf-go envelope send. The links go to a 0600 file, printed once.
#   queue       GET /api/v1/admin/dbstatus: how many invitations are still waiting for
#               the worker (DEV=1 in deploy/.env.test, so on this instance the mail is
#               written to the outbox inside the container rather than pushed at a relay)
#   prompt      print the signing link to this terminal once, and the two commands to
#               come back with. The run does not block unless WAIT=1.
#   verify      WAIT=1 (and `report`): poll the status, pdf-go envelope report, the byte
#               identity of the archived bytes, the audit chain, and the addresses the
#               service recorded for the party.
#
# IDEMPOTENT — run it as often as you like
#
#   * nothing on the server is deleted or reset. The run reuses the existing client key
#     and adds an envelope rather than wiping the instance, so documents signed by
#     earlier runs keep verifying;
#   * both credentials are validated before use and re-minted only when the service
#     rejects them, so the script works after the instance is rebuilt under it;
#   * the envelope this run created is remembered in tmp/prod-run/envelope.id. On a
#     re-run, if that envelope is still waiting for a signature (draft/ready/sent/
#     collecting) the script does not create another one and does not mail the party
#     twice — it reads and verifies that envelope instead, and prints the commands.
#     Once it is delivered (signed), the next run dispatches a fresh envelope.
#     FORCE_NEW=1, or deleting that file, asks for a new envelope;
#   * `send` on an envelope that is already sent is refused by the server's state
#     machine, so a second mail cannot happen by accident even with FORCE_NEW=0 and a
#     hand-edited envelope.id;
#   * an early exit (endpoint down, bad password, form changed) leaves no half-written
#     key, token or envelope id behind, and never writes to deploy/.env.test.
#
#     scripts/prod-sign-run.sh                 1st run -> creates + sends envelope A
#     scripts/prod-sign-run.sh                 2nd run -> A still waiting: reuses A,
#                                                        mails nobody a second time
#     FORCE_NEW=1 scripts/prod-sign-run.sh     -> creates + sends envelope B
#     scripts/prod-sign-run.sh report A        -> read-only, any time after
#
# SECRETS. The admin password and the client key are read from and written to 0600
# files and never printed; the bearer tokens are printed nowhere. The signing link IS
# the party's credential, so it is shown once, to this terminal, and into no log file.
#
# ONE LIMIT, STATED BEFORE ANYONE READS A RESULT AS PROOF. Requests issued from this
# box reach the domain through its public address and hairpin back through nginx on the
# same machine, so the address the service records is this box's address, not a remote
# client's. The published container port makes that worse in a useful way: the socket
# peer is the docker bridge gateway, so the client address can arrive ONLY through
# X-Forwarded-For — a header that is not working shows up as 172.18.0.1 on the
# signature instead of hiding. To put a true remote address on a signature, open the
# printed link on a phone off this network: the link is the credential, the phone
# supplies the address. The addresses actually recorded are read back over the API from
# the envelope's "claimed" and "consent" events (see consent_ips).

set -eu
cd "$(dirname "$0")/.."   # the repo root, whatever directory this was started from

BASE=${BASE:-https://test-pdfsign.kaykraft.org}
ENVF=${ENVF:-deploy/.env.test}                     # the admin password lives here
COMPOSE=${COMPOSE:-deploy/docker-compose.test.yml} # the admin address lives here
DOC=${DOC:-testdata/sample2.pdf}
WORK=${WORK:-tmp/prod-run}
BIN=${BIN_DIR:-tmp/bin}
PDFGO=$BIN/pdf-go

# The admin login the instance seeded on its first start. Overridable either way;
# nothing here writes to the server's configuration.
ADMIN_EMAIL=${ADMIN_EMAIL:-}
ADMIN_PASSWORD=${ADMIN_PASSWORD:-}

# The one party.
PARTY=${PARTY:-msh.computing@gmail.com}
PARTY_NAME=${PARTY_NAME:-Steve Kieu}
TITLE=${TITLE:-Production regression - one real signature}
EXPIRES=${EXPIRES:-72h}
CONSENT_REASON=${CONSENT_REASON:-I have read this document and agree to its terms}
CANCEL_REASON=${CANCEL_REASON:-test run closed by scripts/prod-sign-run.sh}
WAIT=${WAIT:-0}
WATCH_SECONDS=${WATCH_SECONDS:-900}
FORCE_NEW=${FORCE_NEW:-0}

KEYFILE=$WORK/client.key
ADMIN_TOKEN_F=$WORK/admin.token
BEARER_F=$WORK/client.bearer
ENVIDFILE=$WORK/envelope.id
API_OUT=$WORK/api.out

# The verification report wraps the checks in .report:
#   {status, sha256, report:{valid, signers[], errors[], pages}, signed_parties,
#    required_parties, complete}
# Reading .valid at the top level gives null, which jq treats as falsy, so a run would
# "pass" on a value that was never there.
report_jq='{status, sha256, complete, signed: .signed_parties, required: .required_parties,
           valid: .report.valid, pages: .report.pages,
           signers: [.report.signers[] | {name, valid, trusted, revoked, timestamped}],
           errors: .report.errors}'

say()  { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }

umask 077
mkdir -p "$WORK" "$BIN"
cleanup() { rm -f "$WORK/jwt.p"; }
trap cleanup EXIT INT TERM

# ------------------------------------------------------------- preflight ----
case "$BASE" in
    https://*) ;;
    *) fail "BASE=$BASE is not https:// - the bearer token and the signing link would travel in the clear" ;;
esac
for t in curl jq openssl base64; do
    command -v "$t" > /dev/null 2>&1 || fail "$t is not on PATH - this run needs it"
done
[ -f "$DOC" ]     || fail "no document at $DOC (DOC=/path/contract.pdf scripts/prod-sign-run.sh for a different form)"
[ -f "$ENVF" ]    || fail "no $ENVF - the admin password comes from that file"
[ -f "$COMPOSE" ] || fail "no $COMPOSE - the admin login address comes from that file"

# ------------------------------------------------------- read the login ----
# .env.test writes ADMIN_PASSWORD='...' and compose writes DEFAULT_ADMIN_EMAIL: both
# spellings are handled, comment lines are skipped, and neither value is ever echoed.
# These files are not generated and not modified here: the keystore passphrase in
# .env.test belongs to the CA on the server's volume, so a run that invented its own
# credentials would be testing an instance nobody uses.
# The two files spell the same idea differently, and both spellings are handled:
#   .env.test        KEY='value'            (it is an env_file, so dotenv syntax)
#   compose YAML     KEY: value             (and "KEY": "value", and KEY = value)
# Comment lines are dropped, because this file talks about DEFAULT_ADMIN_EMAIL in prose
# more often than it sets it. Quoted values keep any '#' or space inside them. Nothing
# printed here is a secret.
env_value() { # <file> <KEY>
    sed -n -E "/^[[:space:]]*[#]/!s/^[[:space:]]*\"?$2\"?[[:space:]]*[:=][[:space:]]*(.*)$/\1/p" "$1" 2>/dev/null \
        | head -1 | sed -E "s/^[\"']//; s/[\"'][[:space:]]*\$//; s/[[:space:]]+\$//"
}
[ -n "$ADMIN_EMAIL" ]    || ADMIN_EMAIL=$(env_value "$COMPOSE" DEFAULT_ADMIN_EMAIL)
[ -n "$ADMIN_PASSWORD" ] || ADMIN_PASSWORD=$(env_value "$ENVF" ADMIN_PASSWORD)
[ -n "$ADMIN_EMAIL" ]    || fail "no admin address: DEFAULT_ADMIN_EMAIL is not in $COMPOSE and ADMIN_EMAIL is not set"
[ -n "$ADMIN_PASSWORD" ] || fail "no password: ADMIN_PASSWORD is not in $ENVF and ADMIN_PASSWORD is not set"

# ------------------------------------------------ the token helpers ----
# The expiry of a bearer token is read out of the token rather than assumed: the JWT
# carries exp, so the cache can be honest about the window it is reusing instead of
# guessing a lifetime that would eventually send a stale token and read as a service
# fault. base64 is fed a file, not a pipe, because a bare `base64 -d` on some systems
# reads the whole token as a file name.
jwt_field() { # <token-file> <claim> — empty when the token cannot be decoded
    cut -d. -f2 "$1" | tr -d '\n' > "$WORK/jwt.p"
    case $(( $(wc -c < "$WORK/jwt.p") % 4 )) in
        2) printf '==' >> "$WORK/jwt.p" ;;
        3) printf '='  >> "$WORK/jwt.p" ;;
    esac
    base64 -d "$WORK/jwt.p" 2>/dev/null | jq -r ".$2 // empty" 2>/dev/null || true
}

# Still valid means valid by more than a minute: a run that waits for a signature out
# lives longer than the 15-minute token it started with, and re-exchanging a little
# early costs one request instead of a 401 in the middle of the verification.
token_live() { # <token-file>
    [ -s "$1" ] || return 1
    exp=$(jwt_field "$1" exp)
    [ -n "$exp" ] || return 1
    [ "$exp" -gt $(( $(date +%s) + 60 )) ]
}

# The admin bearer token, exchanged from the email/password pair. Nothing else in the
# run carries the password, and the pair is never sent on an ordinary API call.
admin_token() {
    token_live "$ADMIN_TOKEN_F" && { printf '%s' "$(cat "$ADMIN_TOKEN_F")"; return 0; }
    rm -f "$ADMIN_TOKEN_F"
    body=$(jq -cn --arg email "$ADMIN_EMAIL" --arg password "$ADMIN_PASSWORD" \
        '{email:$email, password:$password}')
    code=$(curl -sS --max-time 20 -o "$WORK/login.json" -w '%{http_code}' -X POST \
        -H 'Content-Type: application/json' -d "$body" "$BASE/api/v1/auth/login" \
        2>"$WORK/login.err" || echo 000)
    if [ "$code" != 200 ]; then
        note "POST /api/v1/auth/login -> HTTP $code"
        jq -c '.error // .' "$WORK/login.json" 2>/dev/null | sed 's/^/   /' || true
        [ "$code" = 429 ] && note "the login bucket is 5/min per address - wait a minute and re-run"
        fail "the login over the API failed (address $ADMIN_EMAIL)"
    fi
    jq -r '.access // empty' "$WORK/login.json" > "$ADMIN_TOKEN_F"
    : > "$WORK/login.json"          # that answer also held the refresh token
    [ -s "$ADMIN_TOKEN_F" ] || fail "the login answered with no access token"
    printf '%s' "$(cat "$ADMIN_TOKEN_F")"
}

# The API credential for the envelope verbs. pdf-go takes the value in TOKEN and works
# out what it is: a "key_..." string is exchanged at the token endpoint, a three-part
# token is sent as it is. Handing it the second kind is what keeps one run to a single
# exchange.
client_bearer() {
    token_live "$BEARER_F" && { printf '%s' "$(cat "$BEARER_F")"; return 0; }
    rm -f "$BEARER_F"
    body=$(jq -cn --arg key "$(cat "$KEYFILE")" '{key:$key}')
    curl -sS --max-time 20 -o "$WORK/exchange.json" -X POST \
        -H 'Content-Type: application/json' -d "$body" "$BASE/api/v1/auth/token" \
        2>"$WORK/exchange.err" || { rm -f "$WORK/exchange.json"; return 1; }
    jq -r '.access // empty' "$WORK/exchange.json" > "$BEARER_F"
    : > "$WORK/exchange.json"
    [ -s "$BEARER_F" ] || { rm -f "$BEARER_F"; return 1; }
    printf '%s' "$(cat "$BEARER_F")"
}

# api <METHOD> <path> [json-body] — one admin-scoped call. Prints the HTTP status; the
# answer is in $API_OUT. A 401 re-exchanges once: a run that waits outgrows its token,
# and blaming that on the service would send someone to read a healthy log.
api() {
    m=$1; p=$2; b=${3:-}
    tok=$(admin_token)
    # A POSIX shell has no arrays, so a body-bearing call and a bodyless one are
    # spelled out separately rather than assembled from a variable.
    if [ -n "$b" ]; then
        code=$(curl -sS --max-time 30 -o "$API_OUT" -w '%{http_code}' -X "$m" \
            -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
            -d "$b" "${BASE}${p}" || echo 000)
        if [ "$code" = 401 ]; then
            rm -f "$ADMIN_TOKEN_F"
            code=$(curl -sS --max-time 30 -o "$API_OUT" -w '%{http_code}' -X "$m" \
                -H "Authorization: Bearer $(admin_token)" -H 'Content-Type: application/json' \
                -d "$b" "${BASE}${p}" || echo 000)
        fi
    else
        code=$(curl -sS --max-time 30 -o "$API_OUT" -w '%{http_code}' -X "$m" \
            -H "Authorization: Bearer $tok" "${BASE}${p}" || echo 000)
        if [ "$code" = 401 ]; then
            rm -f "$ADMIN_TOKEN_F"
            code=$(curl -sS --max-time 30 -o "$API_OUT" -w '%{http_code}' -X "$m" \
                -H "Authorization: Bearer $(admin_token)" "${BASE}${p}" || echo 000)
        fi
    fi
    printf '%s' "$code"
}

api_problem() { # the service's own reason for the call sitting in $API_OUT
    jq -c '.error // {unexpected: .}' "$API_OUT" 2>/dev/null | sed 's/^/   /' \
        || sed -E 's/(key|token|secret|pass)[^ ]*=.*/\1...=<redacted>/' "$API_OUT" 2>/dev/null \
        | sed 's/^/   /'
}

# envelope <verb> [flags...] [the positional] — a pdf-go envelope verb, with the
# credential in the environment and never in argv (a token in argv sits in the process
# list, which anyone on the box can read). Callers put every flag BEFORE the positional:
# Go's flag parser stops at the first non-flag word, so "get <id> -server ..." reads the
# id, treats the flags as further arguments, and answers "needs --server".
envelope() {
    v=$1; shift
    TOKEN=$(client_bearer) || fail "the client key was refused at /api/v1/auth/token"
    export TOKEN
    # -server goes right after the verb: the CLI parses the subcommand first, and its
    # flag set stops at the first non-flag word, so the id has to stay last.
    case "$*" in
        *-server*) "$PDFGO" envelope "$v" "$@" ;;
        *)         "$PDFGO" envelope "$v" -server "$BASE" "$@" ;;
    esac
}

env_party() { # <envelope-id> — "Name <email>" of the first party, over the API.
    # Printed instead of the PARTY/PARTY_NAME defaults: on a re-run that reuses an
    # envelope made under other names, the defaults would show the wrong person.
    code=$(api GET "/api/v1/envelopes/$1")
    [ "$code" = 200 ] || { printf ''; return 0; }
    jq -r '(.parties // [])[0] | select(.email != null)
           | "\(.name // "unnamed") <\(.email)>"' "$API_OUT" 2>/dev/null | head -1
}

env_status() { # <envelope-id> — the status over the API, empty when it is not there
    code=$(api GET "/api/v1/envelopes/$1")
    [ "$code" = 200 ] || { printf ''; return 0; }
    jq -r '.status // empty' "$API_OUT" 2>/dev/null || true
}

# ------------------------------------------------------- what to check ----
# These four read the outcome of a run. They are defined before the subcommand dispatch
# below, because `report` reaches them immediately and a POSIX shell resolves a function
# name only when it is called — one defined further down has, at that point, no
# definition yet, and the run dies on "not found" instead of reporting anything.

# Byte identity of the copy the party downloads. The report names the sha256 of the
# bytes it verified; the document endpoint serves the archived bytes for exactly one
# envelope. If those two disagree, the file someone filed is not the file the CA
# certified, and no amount of green on the signature checks says otherwise.
byte_identity() { # <indent> <envelope-id> <sha from the report, may be empty>
    ind=$1; env=$2; want=$3
    tok=$(client_bearer) || { note "${ind}no API token - cannot fetch the document"; return 0; }
    code=$(curl -sS --max-time 60 -o "$WORK/download.pdf" -w '%{http_code}' \
        -H "Authorization: Bearer $tok" "${BASE}/api/v1/envelopes/${env}/document" \
        2>"$WORK/download.err" || echo 000)
    if [ "$code" != 200 ]; then
        note "${ind}GET /envelopes/$env/document -> HTTP $code (nothing archived yet?)"
        return 0
    fi
    got=$(openssl dgst -sha256 "$WORK/download.pdf" | awk '{print $NF}')
    case "$want" in
        "")   note "${ind}the document downloads; sha256 $got" ;;
        "$got") note "${ind}the downloaded document hashes to the report's sha256 - byte-identical to what was certified" ;;
        *)    note "${ind}!! downloaded document hashes to $got but the report names $want"
              note "${ind}   the bytes someone can download are not the bytes the report verified" ;;
    esac
    head -c 5 "$WORK/download.pdf" | grep -q '%PDF' \
        || note "${ind}!! what downloaded is not a PDF"
}

# The audit chain is the claim the archive rests on, and the API answers it in two
# calls. The write is not optional: the hash log is appended only on an explicit call,
# so verifying first reports "events up to id N exist, the log ends at 0 (events
# missing)" on a perfectly healthy instance — which reads exactly like tampering.
# Re-running the write for a day already written adds nothing, so this is idempotent.
audit_chain() { # <indent>
    ind=$1
    TOKEN=$(admin_token); export TOKEN
    "$PDFGO" admin audit-write -server "$BASE" -token-env TOKEN \
        > "$WORK/audit-write.json" 2>"$WORK/audit.err" \
        || { sed -E 's/(key|token|secret|pass)[^ ]*=.*/\1...=<redacted>/' "$WORK/audit.err" | sed "s/^/$ind/"; return 0; }
    "$PDFGO" admin audit-verify -server "$BASE" -token-env TOKEN \
        > "$WORK/audit-verify.json" 2>>"$WORK/audit.err" \
        || note "${ind}audit-verify exited non-zero - read the reason below"
    jq -c '{day, lines, path}' "$WORK/audit-write.json" 2>/dev/null | sed "s/^/$ind/"
    jq -c '{ok, lines_verified, reason: (.reason // "")}' "$WORK/audit-verify.json" 2>/dev/null | sed "s/^/$ind/"
    jq -e '.ok == true' "$WORK/audit-verify.json" > /dev/null 2>&1 \
        && note "${ind}chain valid" \
        || note "${ind}!! the hash log does not match the events table"
}

# The address the service recorded for each of the party's requests. No database access
# is needed: GET /api/v1/envelopes/{id} returns the audit events, and "claimed",
# "consent" and "declined" carry the caller's address in their payload.
#
# events[].payload is a STRING holding JSON, not a nested object, so it has to be
# decoded before it can be queried — `.payload.ip` on a string is always null, and a
# null silently filters every row out.
consent_ips() { # <indent> <envelope-id>
    ind=$1; env=$2
    tok=$(client_bearer) || { note "${ind}no API token - cannot read the envelope"; return 0; }
    curl -sS --max-time 20 -o "$WORK/ips.json" -H "Authorization: Bearer $tok" \
        "${BASE}/api/v1/envelopes/${env}" 2>"$WORK/ips.err" || {
            note "${ind}the read failed: $(head -c 140 "$WORK/ips.err" 2>/dev/null)"; return 0; }
    jq -r '(.events // [])[]
           | (.payload | if type == "string" then (fromjson? // {}) else . end) as $p
           | select(($p.ip // "") != "")
           | "  \(.kind)\t\($p.ip)\t\(.created_at)"' "$WORK/ips.json" 2>/dev/null | sed "s/^/$ind/"
    n=$(jq -r '[(.events // [])[]
               | (.payload | if type == "string" then (fromjson? // {}) else . end)
               | select((.ip // "") != "")] | length' "$WORK/ips.json" 2>/dev/null || echo 0)
    [ "${n:-0}" = 0 ] && { note "${ind}no event carries an address yet - nobody has opened the link"; return 0; }
    note "${ind}^ the address the service recorded, read over HTTPS"
    if jq -e '[(.events // [])[]
              | (.payload | if type == "string" then (fromjson? // {}) else . end)
              | select(.ip == "172.18.0.1")] | length > 0' "$WORK/ips.json" >/dev/null 2>&1; then
        note "${ind}!! 172.18.0.1 is the docker bridge gateway, not a client address:"
        note "${ind}   for that request X-Forwarded-For never reached the service"
    fi
    if jq -e '[(.events // [])[]
              | (.payload | if type == "string" then (fromjson? // {}) else . end)
              | select(.ip == "127.0.0.1" or .ip == "::1")] | length > 0' "$WORK/ips.json" >/dev/null 2>&1; then
        note "${ind}!! a loopback address: that request did not arrive through the proxy"
    fi
}

# The two read-only subcommands. They need the pdf-go binary and the machine client key
# from a previous run, and nothing else — no admin login, no create, no writes to the
# instance other than the audit-day file, which is what the nightly job writes anyway.
if [ "${1:-}" = report ] || [ "${1:-}" = cancel ]; then
    [ $# -eq 2 ] || fail "usage: $0 $1 <envelope-id>"
    [ -s "$KEYFILE" ] || fail "no client key at $KEYFILE - run $0 (no arguments) once first"
    go build -trimpath -o "$PDFGO" ./cmd/pdf-go || fail "pdf-go did not build"
fi

if [ "${1:-}" = "report" ]; then
    say "report $2  (read-only)"
    envelope report "$2" > "$WORK/report.json" 2>"$WORK/report.err" \
        || { cat "$WORK/report.err"; fail "report failed" ; }
    jq -c "$report_jq" "$WORK/report.json" | sed 's/^/   /'
    jq -e '.complete and .report.valid and
           (([.report.signers[].valid] | length) > 0) and ([.report.signers[].valid] | all)' \
        "$WORK/report.json" >/dev/null 2>&1 \
        && note "PASS - every party signed and every signature verifies against the CA" \
        || note "not a PASS - read the fields above (.report.errors says why)"
    byte_identity '   ' "$2" "$(jq -r '.sha256 // empty' "$WORK/report.json" 2>/dev/null)"
    audit_chain '   '
    consent_ips '   ' "$2"
    exit 0
fi

if [ "${1:-}" = "cancel" ]; then
    say "cancel $2"
    # There is no `pdf-go envelope cancel`, so this is the route directly: POST
    # /api/v1/envelopes/{id}/cancel, with the body the endpoint requires (an empty
    # reason is a 422, not a default). The answer is
    # {envelope: "<id>", status: "cancelled", notified: [...]} where `envelope` is a
    # STRING, so .envelope.status would error and print nothing.
    tok=$(client_bearer) || fail "the client key was refused at /api/v1/auth/token"
    body=$(jq -cn --arg reason "$CANCEL_REASON" '{reason:$reason}')
    code=$(curl -sS --max-time 30 -o "$WORK/cancel.json" -w '%{http_code}' -X POST \
        -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
        -d "$body" "${BASE}/api/v1/envelopes/${2}/cancel" || echo 000)
    printf '   POST /envelopes/%s/cancel -> HTTP %s\n' "$2" "$code"
    if [ -s "$WORK/cancel.json" ]; then
        jq -c '{envelope, status, notified}' "$WORK/cancel.json" 2>/dev/null | sed 's/^/   /' \
            || api_problem
    fi
    [ "$code" = 200 ] || note "a delivered envelope cannot be cancelled (state_conflict) - and that is correct"
    exit 0
fi

note "credentials read from $ENVF and $COMPOSE (neither printed)"

# ------------------------------------------------------------- health ----
say "preflight: $BASE"
CODE=$(curl -sS --max-time 20 -o "$WORK/health.json" -w '%{http_code}' "$BASE/healthz" \
    2>"$WORK/health.err" || echo 000)
[ "$CODE" = 200 ] || { printf '%s\n' "$(head -c 200 "$WORK/health.err" 2>/dev/null)"
                       fail "GET $BASE/healthz -> HTTP $CODE"; }
note "GET /healthz -> 200   $(jq -c '{status, version}' "$WORK/health.json" 2>/dev/null)"
admin_token > /dev/null
note "login over the API ok (token not printed)"

# ------------------------------------------------------------------ build ----
say "build pdf-go (-trimpath, from ./cmd/pdf-go)"
go build -trimpath -o "$PDFGO" ./cmd/pdf-go || fail "pdf-go did not build"
note "$("$PDFGO" version)   $PDFGO"

# ------------------------------------------------------------ client key ----
# A key file is not a key the service still accepts: the instance can be rebuilt while
# tmp/prod-run survives. So the file is asked about before it is trusted, at the same
# endpoint the next call would use. Minting also happens over the API — the key is shown
# once by POST /api/v1/admin/clients and stored as a hash, so a lost file means the
# client is revoked from the console, not guessed at.
say "client key (over the API)"
key_check() { # HTTP status of the token exchange for the key on disk
    [ -s "$KEYFILE" ] || { printf 'none'; return 0; }
    body=$(jq -cn --arg key "$(cat "$KEYFILE")" '{key:$key}')
    curl -sS --max-time 20 -o "$WORK/keycheck.json" -w '%{http_code}' -X POST \
        -H 'Content-Type: application/json' -d "$body" "$BASE/api/v1/auth/token" \
        2>/dev/null || printf '000'
    : > "$WORK/keycheck.json"
}
KC=$(key_check)
if [ "$KC" = 200 ]; then
    note "reusing $KEYFILE (the token endpoint accepts it)"
else
    [ "$KC" = none ] && note "no key on disk yet" \
        || note "the stored key is not accepted (HTTP $KC) - issuing a new one"
    # The name is unique on the instance and the key is unrecoverable (hashed, shown
    # once), so a client left by an earlier run whose key file is gone cannot be reused
    # and cannot be re-keyed: mint a second one. The service answers that collision with
    # a 500 on the insert, not a 409, so a plain name is tried first and a numbered one
    # only after it is refused. Revoke the old ones from the console when it matters.
    CNAME=prod-regression
    body=$(jq -cn --arg n "$CNAME" '{name:$n, scopes:["envelope:write","envelope:read"]}')
    code=$(api POST /api/v1/admin/clients "$body")
    case "$code" in
        200|201) : ;;
        *) CNAME="prod-regression-$(date +%s)"
           note "'prod-regression' is already taken on this instance (an earlier run that"
           note "lost its key file). Minting as $CNAME instead; revoke the old one in the console."
           body=$(jq -cn --arg n "$CNAME" '{name:$n, scopes:["envelope:write","envelope:read"]}')
           code=$(api POST /api/v1/admin/clients "$body") ;;
    esac
    case "$code" in
        200|201) : ;;
        *) printf '   POST /api/v1/admin/clients -> HTTP %s\n' "$code"; api_problem
           fail "could not mint the client key over the API" ;;
    esac
    # The key is in this answer and in no later one. It goes file to file: never argv,
    # never the terminal, never the log.
    jq -r '.key' "$API_OUT" > "$KEYFILE"
    [ -s "$KEYFILE" ] || { api_problem; fail "the create answer held no key"; }
    KC=$(key_check)
    [ "$KC" = 200 ] || { note "the new key was refused too (HTTP $KC)"; fail "the client key does not work"; }
    note "issued client id $(jq -r '.client.id' "$API_OUT") (revoke: DELETE /api/v1/admin/clients/<id> or ${BASE}/admin/)"
fi
rm -f "$BEARER_F"      # any cached bearer belongs to the key that was just checked
client_bearer > /dev/null || fail "the client key was refused at /api/v1/auth/token"
note "API credential ready (one exchange for the whole run)"

# --------------------------------------------------------------- document ----
# Read the form before naming a field. A name that is not in the document is a 400 at
# create; a name that is in the document but wrong is a document that says the wrong
# thing and gets certified anyway.
say "document: $DOC"
"$PDFGO" extract "$DOC" -o "$WORK/schema.json" > "$WORK/extract.out" 2>&1 \
    || { cat "$WORK/extract.out"; fail "extract failed (a scanned PDF with no form?)"; }
jq -r '.fields[] | select(.type=="text") | .name' "$WORK/schema.json" > "$WORK/fields.txt"
note "fillable text fields: $(tr '\n' ' ' < "$WORK/fields.txt")"

# The party's name, the date, and a line naming the run. The rest of the form is left
# alone deliberately: a regression run should change the least the signature has to
# cover, so a failure points at the protocol rather than at the artwork.
FILL_DATE=$(date +%F)
FILL_REF="regression $(date +%Y-%m-%dT%H:%M) $(printf '%s' "${BASE#https://}")"
jq -n --arg n "$PARTY_NAME" --arg d "$FILL_DATE" --arg r "$FILL_REF" \
    '{values: {Text1: $n, Text2: $d, Text5: $n, Text6: $r}}' > "$WORK/fill.json"
# Field names are read one line at a time rather than word-split: a form written by
# Word names its fields "Full name" and company, and a `for` loop would test "Full" and
# "name" separately and call that a match.
jq -r '.values | keys[]' "$WORK/fill.json" > "$WORK/fill-keys.txt"
while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -Fxq -- "$f" "$WORK/fields.txt" \
        || fail "the fill spec sets '$f', which is not a text field in $DOC"
done < "$WORK/fill-keys.txt"
note "the fill spec sets: $(jq -r '.values | keys | join(", ")' "$WORK/fill.json")"

"$PDFGO" fill "$WORK/fill.json" "$DOC" -o "$WORK/filled.pdf" > "$WORK/fill.out" 2>&1 \
    || { cat "$WORK/fill.out"; fail "fill failed"; }
grep -i 'warn' "$WORK/fill.out" | sed 's/^/     /' || true
"$PDFGO" fields "$WORK/filled.pdf" > "$WORK/filled-fields.txt" 2>&1 \
    || { cat "$WORK/filled-fields.txt"; fail "the filled document cannot be re-read"; }
# One value per line, same reason as the field names above: the party's name is two
# words, and a word-split check would pass on either half of it.
jq -r '.values[]' "$WORK/fill.json" > "$WORK/fill-values.txt"
while IFS= read -r v; do
    [ -n "$v" ] || continue
    grep -Fq -- "$v" "$WORK/filled-fields.txt" || note "!! '$v' did not read back from the PDF"
done < "$WORK/fill-values.txt"
note "filled document re-reads with the values in it"
note "local sha256 of those bytes: $(openssl dgst -sha256 "$WORK/filled.pdf" | awk '{print $NF}')"

# --------------------------------------------------------------- dispatch ----
say "dispatch"
jq -n --arg e "$PARTY" --arg n "$PARTY_NAME" --arg r "$CONSENT_REASON" \
    '[{email: $e, name: $n, order: 1, reason: $r}]' > "$WORK/parties.json"

# Reuse, do not repeat. The envelope this run made is remembered, and while it is still
# waiting there is nothing to create and nothing to mail.
ENVID=""
if [ -s "$ENVIDFILE" ]; then
    CAND=$(tr -d ' \t\n' < "$ENVIDFILE")
    case "$CAND" in
        [0-9a-f][0-9a-f]*)
            st=$(env_status "$CAND")
            if [ "$FORCE_NEW" = 1 ]; then
                note "envelope $CAND (${st:-gone}) exists; FORCE_NEW=1 asks for another"
            elif [ -z "$st" ]; then
                note "envelope $CAND is no longer on the instance - creating one"
            else
                case "$st" in
                    draft|ready|sent|collecting)
                        # Waiting for a signature in every one of these. draft and ready
                        # still need their send (the send below only fires from ready);
                        # sent and collecting are already mailed, so this run reads and
                        # verifies only.
                        ENVID=$CAND
                        note "envelope $CAND is waiting for a signature (status $st):"
                        note "not creating another, and not mailing the party twice. FORCE_NEW=1 for a new one."
                        ;;
                    *)
                        note "envelope $CAND is $st - this run dispatches a fresh one"
                        ;;
                esac
            fi ;;
        *) note "ignoring a malformed $ENVIDFILE"; rm -f "$ENVIDFILE" ;;
    esac
fi

if [ -z "$ENVID" ]; then
    # The document is the LAST argument on purpose (Go's flag parser stops at the first
    # non-flag word, so a path first makes every flag after it positional and the CLI
    # answers "needs --server"). No -send here: send is the next stage, so a run that
    # stops in between leaves a ready envelope that can be sent by hand.
    envelope create \
        -server "$BASE" -token-env TOKEN -title "$TITLE" -expires "$EXPIRES" \
        -subject "One document is waiting for your signature" \
        -message "Please review and sign. The link expires in $EXPIRES." \
        -spec "$WORK/fill.json" -parties "$WORK/parties.json" \
        -links-out "$WORK/links.json" "$DOC" \
        > "$WORK/create.json" 2>"$WORK/create.err" \
        || { cat "$WORK/create.err"; fail "create failed"; }
    ENVID=$(jq -r '.envelope.id // empty' "$WORK/create.json")
    case "$ENVID" in ""|null) cat "$WORK/create.err"; fail "the service answered with no envelope id" ;; esac
    printf '%s\n' "$ENVID" > "$ENVIDFILE"
    note "created envelope $ENVID   status $(jq -r '.envelope.status' "$WORK/create.json")"
    # The bytes that get certified are the server's fill of the spec, not the local file.
    # A field the server could not set is the one thing that would put a different
    # document in front of the party than the one filled here, so it is named here.
    if [ -n "$(jq -r '.fill.missing // [] | .[]' "$WORK/create.json" 2>/dev/null)" ]; then
        note "!! the server did not set: $(jq -r '.fill.missing | join(", ")' "$WORK/create.json")"
    fi
    note "server set: $(jq -r '.fill.applied // [] | join(", ")' "$WORK/create.json")"
    note "form locked on the server: $(jq -r '.fill.lockedForm // "not reported"' "$WORK/create.json")"
fi

# Send, once. A ready envelope is the only state the machine sends from, so this cannot
# mail the same party twice by accident; a refusal is the service's own problem document.
st=$(env_status "$ENVID")
if [ "$st" = ready ]; then
    envelope send -server "$BASE" -token-env TOKEN -links-out "$WORK/links.json" "$ENVID" \
        > "$WORK/send.json" 2>"$WORK/send.err" \
        || { cat "$WORK/send.err"; fail "send failed"; }
    note "sent. envelope status now $(env_status "$ENVID")"
    jq -c '[.links[]? | {order, email, expires_at}]' "$WORK/send.json" 2>/dev/null | sed 's/^/     /'
elif [ -n "$st" ]; then
    note "envelope is '$st' - not sending again; the party was already invited"
else
    note "!! could not read envelope $ENVID over the API - not sending"
fi

# Whether the invitation actually left. A send whose mail fails does not fail the call:
# the queue row keeps its next_at and is retried, so the envelope status cannot tell you
# the party has a mail. dbstatus counts the queue. On this instance DEV=1 (deploy/.env.test)
# writes the invitation to the outbox inside the container instead of pushing it at a
# relay, so "queue empty" here means the worker ran and wrote it. The count is for the
# whole instance, not for this envelope — on a shared instance, read the envelope's
# events instead.
i=0; LEFT=""; code=000
while [ "$i" -lt 15 ]; do
    code=$(api GET /api/v1/admin/dbstatus)
    [ "$code" = 200 ] && LEFT=$(jq -r '.mail_queued // empty' "$API_OUT" 2>/dev/null) && break
    i=$((i + 1)); sleep 2
done
case "$LEFT" in
    0)  note "mail queue drained   $(jq -c '{envelopes, parties_pending, mail_queued}' "$API_OUT" 2>/dev/null)" ;;
    '') note "dbstatus did not answer (HTTP $code) - the invitation may still be queued" ;;
    *)  note "!! $LEFT mail(s) still queued after 30s - the worker is not draining it" ;;
esac

# The link. It is the party's credential, and the service never returns it twice, so the
# file that holds it is checked for belonging to THIS envelope before it is printed: a
# stale file from an earlier run would otherwise show someone a live link for a document
# that is not this one.
LINK=""
if [ -s "$WORK/links.json" ] && [ "$(jq -r '.envelope // empty' "$WORK/links.json" 2>/dev/null)" = "$ENVID" ]; then
    LINK=$(jq -r '.links[0].url // empty' "$WORK/links.json" 2>/dev/null)
else
    [ -s "$WORK/links.json" ] && { rm -f "$WORK/links.json"; note "removed a stale $WORK/links.json (a different envelope)"; }
    LINK=$(jq -r '.links[0].url // empty' "$WORK/send.json" 2>/dev/null)
fi
if [ -n "$LINK" ]; then
    printf '\n   >>> THE SIGNING LINK - ONCE, TO THIS TERMINAL ONLY <<<\n\n'
    printf '       %s\n\n' "$LINK"
else
    note "no link in hand (it is in the invitation, and `pdf-go envelope links` can reprint"
    note "it from $WORK/links.json while that file exists)"
fi

# ---------------------------------------------------------------- prompt ----
printf '   To sign: open the link on a phone or a laptop, tick the box, draw or type the\n'
printf '   signature, submit. The worker then certifies, signs, timestamps and archives.\n\n'
printf '   To verify afterwards:\n'
printf '       WAIT=1 scripts/prod-sign-run.sh          # poll + verify in one go\n'
printf '       scripts/prod-sign-run.sh report  %s\n' "$ENVID"
printf '   To close the link without signing (do this if you walk away):\n'
printf '       scripts/prod-sign-run.sh cancel  %s\n' "$ENVID"
# Whoever is actually on the envelope, read back over the API — not the defaults this
# invocation was started with, which are wrong when a re-run reuses an earlier envelope.
WHO=$(env_party "$ENVID")
[ -n "$WHO" ] || WHO="$PARTY_NAME <$PARTY>"
printf '   Party: %s\n' "$WHO"
printf '   (override the party on a NEW envelope with PARTY=a@b.com PARTY_NAME="Someone")\n'
printf '   Envelope remembered in %s - re-running reuses it until it is signed.\n' "$ENVIDFILE"

if [ "$WAIT" != 1 ]; then
    printf '\nNot waiting. Run with WAIT=1 once you have signed, or use the report command.\n'
    exit 0
fi

# ---------------------------------------------------------------- verify ----
say "verify (up to ${WATCH_SECONDS}s; Ctrl-C is safe - the envelope keeps waiting)"
deadline=$(( $(date +%s) + WATCH_SECONDS ))
STATUS=""
while :; do
    STATUS=$(env_status "$ENVID")
    case "$STATUS" in
        delivered|completed|signed|expired|cancelled|failed) break ;;
    esac
    [ "$(date +%s)" -ge "$deadline" ] && { note "out of patience at status '${STATUS:-unknown}'"; break; }
    printf '   status %-11s %ss left\n' "${STATUS:-unknown}" $((deadline - $(date +%s)))
    sleep 10
done
note "settled at status '${STATUS:-unknown}'"

say "report (re-opens the archived bytes; verifies every signature against the CA)"
envelope report "$ENVID" > "$WORK/report.json" 2>"$WORK/report.err" \
    || { cat "$WORK/report.err"; note "report failed; only the status line above stands"; }
if [ -s "$WORK/report.json" ]; then
    jq -c "$report_jq" "$WORK/report.json" | sed 's/^/     /'
    # .complete means the parties reached the required count; .report.valid means every
    # cryptographic check passed. Neither one alone is the gate.
    jq -e '.complete and .report.valid and
           (([.report.signers[].valid] | length) > 0) and ([.report.signers[].valid] | all)' \
        "$WORK/report.json" >/dev/null 2>&1 \
        && note "PASS - all parties signed, every signature verifies, timestamps present" \
        || note "FAIL - read the fields above"
fi

byte_identity '     ' "$ENVID" "$(jq -r '.sha256 // empty' "$WORK/report.json" 2>/dev/null)"
audit_chain '     '
consent_ips '     ' "$ENVID"

say "done. artifacts in $WORK (0600, no passwords)"
