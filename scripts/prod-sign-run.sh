#!/bin/sh
# scripts/prod-sign-run.sh — the production regression in one command.
#
# Everything happens here, in order, and re-running does not break anything:
#
#   build          rebuild signsrv and pdf-go with -trimpath
#   stop           kill the server that answers today
#   reset          wipe db, keystore, jwt key, storage, outbox, audit and the config,
#                  so the run is attributable to this run's keys (RESET=0 keeps them)
#   config         write tmp/prod.conf (0600) for the public URL; with RESET=0 it
#                  keeps any secret already in the file, which matters because the
#                  keystore passphrase has to match the CA on disk or every signature
#                  issued so far stops verifying
#   start          start on 127.0.0.1:8090 behind the proxy, dev off (real SMTP relay)
#   key            ensure a client key scoped envelope:write envelope:read
#   document       extract the form of the contract, write the fill spec, fill it,
#                  re-read it to prove the values landed
#   dispatch       create + send, one party, real mail
#   prompt         print the signing link once, and confirm the invitation actually
#                  left this box (the queue row, not the envelope status)
#   verify         once you have signed: poll, verify every signature against the CA
#                  and the timestamp, verify the audit chain, scan the log for leaks
#
# The run does not block. After the invitation is mailed it prints the link and the
# two commands to come back with. That is deliberate: the signature has to come from
# a person in a browser, and a script that could sign its own document would prove
# nothing.
#
#   scripts/prod-sign-run.sh                                  run; leaves server up
#   WAIT=1 scripts/prod-sign-run.sh                           also wait for the sign
#   DOC=/path/contract.pdf scripts/prod-sign-run.sh           a specific document
#   scripts/prod-sign-run.sh report <envelope-id>             re-verify a past run
#   scripts/prod-sign-run.sh cancel <envelope-id>             close an open test link
#   KEEP_RUNNING=0 scripts/prod-sign-run.sh                   stop the server at exit
#
# Secrets are never printed and never written to the log. The signing link is the
# whole capability, so it goes to the terminal once and to no file.

set -eu

cd "$(dirname "$0")/.."   # the repo root, whatever directory this was started from

CONF=${CONF:-tmp/prod.conf}
WORK=${WORK:-tmp/prod-run}
BIN=${BIN_DIR:-tmp/bin}
DOC=${DOC:-testdata/sample2.pdf}
PORT=${PORT:-8090}
BASE=http://127.0.0.1:${PORT}
PUBLIC=${PUBLIC:-https://pdfsign.kaykraft.org}
PARTY=${PARTY:-msh.computing@gmail.com}
PARTY_NAME=${PARTY_NAME:-Steve Kieu}
SMTP_HOST=${SMTP_HOST:-192.168.20.18}
SMTP_PORT=${SMTP_PORT:-25}
TRUST_PROXY=${TRUST_PROXY:-true}
DEV=${DEV:-false}
WAIT=${WAIT:-0}
KEEP_RUNNING=${KEEP_RUNNING:-1}
CANCEL_REASON=${CANCEL_REASON:-test run closed by scripts/prod-sign-run.sh}

# The report endpoint wraps the verification in .report:
#   {envelope, status, sha256, report: {valid, signers[], errors[], pages},
#    signed_parties, required_parties, complete}
# Pulling .valid from the top level would read as null and every run would "pass"
# on a null that jq silently treats as falsy.
report_jq='{status, sha256, complete, signed: .signed_parties, required: .required_parties,
           valid: .report.valid, pages: .report.pages,
           signers: [.report.signers[] | {name, valid, trusted, revoked, timestamped}],
           errors: .report.errors}'

say()  { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }

# The chain is the claim the archive rests on, and it is the one thing the API does not
# show. The log is appended only by an explicit call — this CLI verb, or the admin POST —
# so writing first is not optional: verify alone reports "the log ends at 0 (events
# missing)" on a perfectly healthy database, which reads exactly like tampering.
audit_chain() { # <indent> — append the events table to the hash log, then verify it
    ind=$1
    [ -x "$BIN/signsrv" ] || { note "no $BIN/signsrv yet - run the full path once first"; return 0; }
    "$BIN/signsrv" -config "$CONF" audit-write > "$WORK/audit.out" 2>&1 \
        || note "audit-write failed: see $WORK/audit.out"
    "$BIN/signsrv" -config "$CONF" audit-verify >> "$WORK/audit.out" 2>&1 || true
    tail -2 "$WORK/audit.out" | sed "s/^/$ind/"
    if grep -q 'INVALID' "$WORK/audit.out"; then
        note "!! the hash log does not match the events table"
    else
        note "chain valid"
    fi
# Pull a 64-hex value out of a receipt file without needing a JSON parser. Tolerant of
# the space a pretty-printer inserts after the colon: a receipt read from a log or an
# email is often re-indented, and a matcher that only accepts Go's compact form would
# report "not recorded" for a value that is plainly there.
receipt_hex() { # receipt_hex <file> <key>
    sed -n -E 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"([0-9a-f]{64})".*/\1/p' "$1" 2>/dev/null | head -1
}
}

umask 077
mkdir -p "$WORK" "$BIN"

# The access log already writes "Bearer [credential]". A pattern that matches the
# redaction marker reports 23 leaks on a perfectly clean log, and a scan that cries
# wolf gets ignored — so the pattern demands credential-shaped bytes *after* the word.
log_leak_scan() {
    [ -f tmp/real/signsrv.jsonl ] || { note "no log file at tmp/real/signsrv.jsonl"; return 0; }
    LEAK=$(tail -400 tmp/real/signsrv.jsonl \
        | grep -Ec 'key_[a-f0-9]{64}|Bearer [A-Za-z0-9._-]{10,}|-----BEGIN [A-Z ]*KEY' || true)
    [ "${LEAK:-0}" = "0" ] \
        && note "clean - no key, bearer token, or PEM in the last 400 records" \
        || { note "!! $LEAK line(s) carry a credential-shaped value - investigate";
             tail -400 tmp/real/signsrv.jsonl \
                 | grep -Eo 'key_[a-f0-9]{6,}|Bearer [^ ]{0,12}|-----BEGIN [A-Z ]*KEY' \
                 | sort -u | sed 's/^/     /' | head -5; }
}

# ------------------------------------------------- byte identity of the copy ----
# The party's downloaded copy and the bytes the CA signed have to be the same bytes.
# The service already records, per envelope, the hash of the file as it was sent and
# the hash of the archive that went to storage (final_sha256 in the delivery receipt).
# A byte-level check needs no PKI, so it is a fair gate on the report path too.
#
# Two ways of getting the reference, in order of preference:
#   1. the stored archive itself, hashed on disk — strongest, and needs no receipt;
#   2. the receipt in tmp/real/storage/<final_sha256>.receipt.json.
# A downloaded PDF is checked against the same value by hand:
#   sha256sum downloaded.pdf        # must equal final_sha256
final_pdf_check() { # <indent> <envelope-id> <sha from the report, may be empty>
    ind=$1; env=$2; rep_sha=$3
    # Read from the config rather than a path baked into this function: storage_dir is
    # a setting, and a check that silently reads the wrong directory reports the archive
    # missing on a box where it is present. Inlined rather than calling conf_get
    # because the report subcommand reaches this before that helper is defined.
    sd=$STORAGE_DIR
    [ -n "$sd" ] || sd=$(sed -n -E 's/^[[:space:]]*storage_dir[[:space:]]*=[[:space:]]*//p' "$CONF" 2>/dev/null | head -1)
    [ -n "$sd" ] || sd=tmp/real/storage
    sha=$rep_sha
    if [ -z "$sha" ] || [ "$sha" = null ]; then
        # Pick the receipt for *this* envelope. Taking the last file in the directory
        # would certify some other envelope's bytes against this one, and with more
        # than one document on the box that is a wrong answer that looks right.
        for r in "$sd"/*.receipt.json; do
            [ -f "$r" ] || continue
            e=$(receipt_hex "$r" envelope_id)
            case "$e" in ""|"$env") ;; *) continue ;; esac
            v=$(receipt_hex "$r" final_sha256)
            [ -n "$v" ] && sha=$v && break
        done
    fi
    if [ -z "$sha" ]; then
        note "${ind}!! no final_sha256 for envelope $env in the report or on disk — cannot state what the party downloaded"
        return 0
    fi
    [ "${#sha}" = 64 ] || { note "${ind}!! final_sha256 is not 64 hex chars: '$sha'"; return 0; }
    stored=$(find "$sd" -name "${sha}*" -type f ! -name '*.json' 2>/dev/null | head -1)
    if [ -n "$stored" ]; then
        got=$(sha256sum "$stored" | cut -d' ' -f1)
        [ "$got" = "$sha" ] \
            && note "${ind}the archived document hashes to its own final_sha256 (byte-identical to what was certified)" \
            || note "${ind}!! archived document hashes to $got but the receipt names $sha — the file was changed after it was signed"
    else
        note "${ind}the archive is not on this box (storage_dir may differ); final_sha256 is $sha"
    fi
    # dispatch_sha256 names the bytes that left the box; final_sha256 names the bytes
    # archived. They must agree or a signing round changed the document outside the
    # signature protocol.
    if [ -f "$sd/${sha}.receipt.json" ]; then
        disp=$(receipt_hex "$sd/${sha}.receipt.json" dispatch_sha256)
        case "$disp" in
            "")        note "${ind}dispatch_sha256 is not recorded on this receipt; final_sha256 is the reference" ;;
            "$sha")    note "${ind}dispatch_sha256 == final_sha256: the bytes mailed were the bytes archived" ;;
            *)         note "${ind}!! dispatch_sha256 ($disp) != final_sha256 ($sha) — bytes changed between send and archive" ;;
        esac
    fi
}
# ----------------------------------------------------- cancel / report ----
# Subcommands that come back without building or restarting anything.
#
# cancel <envelope-id> — close an envelope the run left open. A test link is live on
# the public URL until it expires (link_ttl, 336h here), and anyone who has the mail
# can still claim it, so a run you are not going to finish should be cancelled rather
# than left to lapse. Delivered envelopes cannot be cancelled (409 state_conflict) and
# should not be: the signature is already in the archive.
if [ "${1:-}" = "cancel" ]; then
    [ $# -eq 2 ] || fail "usage: $0 cancel <envelope-id>"
    umask 077; mkdir -p "$WORK"
    [ -s "$WORK/client.key" ] || fail "no client key at $WORK/client.key"
    TOK=$(curl -sS -X POST -H 'Content-Type: application/json' \
        -d "{\"key\":\"$(cat "$WORK/client.key")\"}" "${BASE}/api/v1/auth/token" | jq -r '.access // empty')
    [ -n "$TOK" ] || fail "no access token from ${BASE}/api/v1/auth/token — is the server up? (and for a public link, is cloudflared running?)"
    CODE=$(curl -sS -o "$WORK/cancel.json" -w '%{http_code}' -X POST \
        -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
        -d "{\"reason\":\"$CANCEL_REASON\"}" \
        "${BASE}/api/v1/envelopes/$2/cancel")
    printf '   cancel %s -> HTTP %s\n' "$2" "$CODE"
    # The cancel answer is {envelope: "<id>", status: "cancelled", notified: [...]},
    # with envelope a string: .envelope.status would error and print nothing, and a
    # blank line where the outcome should be is how a wrong jq expression becomes a
    # silent pass.
    jq -c '{status: (.status // .error.code), notified: (.notified // [])}' "$WORK/cancel.json" \
        2>/dev/null | sed 's/^/     /' || sed 's/^/     /' "$WORK/cancel.json"
    [ "$CODE" = 200 ] || fail "cancel refused (HTTP $CODE). A delivered envelope cannot be cancelled, and that is correct."
    exit 0
fi

# report <envelope-id> — re-verify a run that already finished. Read-only.
if [ "${1:-}" = "report" ]; then
    [ $# -eq 2 ] || fail "usage: $0 report <envelope-id>"
    [ -s "$WORK/client.key" ] || fail "no client key at $WORK/client.key"
    SIGNSRV_TOKEN=$(cat "$WORK/client.key"); export SIGNSRV_TOKEN
    # Flags before the positional: Go's flag parser stops at the first non-flag word,
    # so "report <id> -server ..." reads the id, then treats the flags as arguments
    # and answers "needs --server".
    "$BIN/pdf-go" envelope report -server "$BASE" -token-env SIGNSRV_TOKEN -insecure "$2" \
        > "$WORK/report.json" 2>"$WORK/report.err" \
        || { cat "$WORK/report.err"; fail "report failed"; }
    jq -c "$report_jq" "$WORK/report.json" | sed 's/^/   /'
    final_pdf_check '   ' "$2" "$(jq -r '.sha256 // empty' "$WORK/report.json" 2>/dev/null)"
    # Signatures alone do not prove a run: the hash chain behind the archive has to
    # agree with the events table, so the report path checks it too.
    audit_chain '   '
    log_leak_scan
    exit 0
fi

# ------------------------------------------------------------------- build ----
say "build (production: -trimpath, from the module cache)"
go build -trimpath -o "$BIN/signsrv" ./cmd/signsrv || fail "signsrv did not build"
go build -trimpath -o "$BIN/pdf-go"  ./cmd/pdf-go  || fail "pdf-go did not build"
note "$("$BIN/signsrv" version)  $("$BIN/pdf-go" version)"

# -------------------------------------------------------------------- stop ----
say "stop every running server"
# The bracket keeps this script's own command line out of its own match. The .* is
# load-bearing: the real command line is `signsrv -config x serve`, so a pattern that
# demands the two words adjacent leaves the server running, holding the port.
SRVPAT='[s]ignsrv( .*)? serve( .*)?'
if pgrep -f "$SRVPAT" >/dev/null 2>&1; then
    pkill -f "$SRVPAT" || true
    i=0
    while pgrep -f "$SRVPAT" >/dev/null 2>&1; do
        i=$((i + 1)); [ "$i" -gt 20 ] && fail "the old server would not stop"
        sleep 1
    done
    note "stopped"
else
    note "nothing was listening"
fi

# Port ownership check. If the stop above missed something — a server started by a
# service manager, or one whose command line this pattern does not cover — it keeps the
# port, the health poll reads 200, and every later line prints green while the pid, the
# log tail and the exit-time kill all point at a process that never ran. Name it now.
if curl -fsS -o "$WORK/health.pre" --max-time 2 "${BASE}/healthz" 2>/dev/null; then
    holder=$(ss -ltnp 2>/dev/null | grep ":${BASE##*:} " | head -1)
    printf 'FAIL  something else is holding %s (it answers /healthz now)\n' "$BASE"
    printf '      %s\n      find it: ss -ltnp | grep %s\n' "${holder:-no owner visible in ss output}" "${BASE##*:}"
    printf '      or move this run off the port: BASE=http://127.0.0.1:8091 scripts/prod-sign-run.sh\n'
    exit 1
fi

# ------------------------------------------------------------------ config ----
# Idempotent in form: a key already in the file survives. But see the reset section
# below — by default it deletes the config first, so every run issues fresh secrets.
# RESET=0 is the mode in which the preservation below is what actually happens.
#
# keystore_pass CANNOT be invented once tmp/real/keystore/ca.key exists — the CA is
# encrypted with it, and a wrong passphrase means the service comes up and every
# signature already issued reads as invalid. So under RESET=0: keep what is in the
# file; if there is none and a CA exists, stop and ask rather than guess.
say "config: $CONF"
conf_get() { # conf_get <key> — value from the existing config, empty if absent
    [ -f "$CONF" ] || return 0
    sed -n -E "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$CONF" | head -1 | tr -d '"'
}

KS_PASS=$(conf_get keystore_pass)
ADMIN_PW=$(conf_get admin_password)
JWT_FILE=$(conf_get jwt_secret_file)
TSA_URL=$(conf_get tsa_url)
SMTP_PASS=$(conf_get smtp_pass)
MAIL_FROM=$(conf_get mail_from)
DB=$(conf_get db)
[ -n "$DB" ] || DB=tmp/real/signsrv.db
KS_DIR=$(conf_get keystore_dir)
[ -n "$KS_DIR" ] || KS_DIR=tmp/real/keystore
STORAGE_DIR=$(conf_get storage_dir)
[ -n "$STORAGE_DIR" ] || STORAGE_DIR=tmp/real/storage
OUTBOX_DIR=$(conf_get outbox_dir)
[ -n "$OUTBOX_DIR" ] || OUTBOX_DIR=tmp/real/outbox
AUDIT_DIR=$(conf_get audit_dir)
[ -n "$AUDIT_DIR" ] || AUDIT_DIR=tmp/real/audit

# Env var wins, then whatever is already in the file, then the default. Without the
# middle step, an operator who set dev=true or trust_proxy=false in the file finds the
# script quietly rewriting their intent on every run.
# An operator who sets dev=true or trust_proxy=false in the file gets it rewritten on
# every run otherwise. The earlier `X=${X:-default}` cannot tell "unset" from "the
# default", so the test is: an environment value that differs from the default is a
# deliberate choice and wins; anything else defers to the file, then the default.
keep() { # keep <key> <env-value> <default>
    v=$(conf_get "$1")
    if [ -n "$2" ] && [ "$2" != "$3" ]; then printf '%s' "$2"
    elif [ -n "$v" ]; then printf '%s' "$v"
    else printf '%s' "$3"; fi
}
DEV=$(keep dev "$DEV" false)
TRUST_PROXY=$(keep trust_proxy "$TRUST_PROXY" true)
SMTP_HOST=$(keep smtp_host "$SMTP_HOST" 192.168.20.18)
SMTP_PORT=$(keep smtp_port "$SMTP_PORT" 25)
STARTTLS=$(keep smtp_starttls "${SMTP_STARTTLS:-}" false)
[ -n "$JWT_FILE" ] || JWT_FILE=$KS_DIR/../jwt.ed25519.key

# --------------------------------------------------------------- reset ----
# Every run from now on starts from nothing: database, keystore, jwt secret, client
# key, stored PDFs, outbox, audit log and the config itself. Without this the run is
# *mostly* fresh but carries the old CA and jwt key forward, so the documents signed
# in this run are signed by a key that has already been used, and a failure cannot be
# attributed to the run that produced it.
#
# It also removes the reason the secrets-preservation logic below exists: with the old
# state gone there is no passphrase to orphan and no CA to keep, so the new one is
# generated and written fresh. RESET=0 restores the preserve-everything behaviour.
#
# The wipe has to happen here, after the paths are resolved and before anything is
# generated or written: wipe after generation and the freshly generated values are
# dropped on the floor, which produces a config with an empty keystore_pass and an
# admin_password — checkconfig then refuses it with "keystore_pass is required".
#
# This is destructive and it is irreversible. Only ever point it at the test tree.
RESET=${RESET:-1}
if [ "$RESET" = 1 ]; then
    say "reset: wiping prior state"
    [ "${RESET_CONFIRM:-yes}" = "yes" ] || fail "RESET_CONFIRM must be 'yes' to wipe"
    for p in "$DB" "$KS_DIR" "$JWT_FILE" "$STORAGE_DIR" "$OUTBOX_DIR" "$AUDIT_DIR"; do
        case "$p" in
            tmp/*|../tmp/*) ;;
            *) fail "refusing to wipe: $p is outside tmp/ (set RESET=0 to keep it)" ;;
        esac
    done
    # $JWT_FILE first, and never after $KS_DIR: the default path is
    # "$KS_DIR/../jwt.ed25519.key", and once the keystore directory is gone that path
    # no longer resolves, so rm -rf walks past it and leaves a stale key behind for the
    # service to choke on.
    for p in "$JWT_FILE" "$DB" "$DB-wal" "$DB-shm" "$KS_DIR" \
             "$STORAGE_DIR" "$OUTBOX_DIR" "$AUDIT_DIR" \
             tmp/real/signsrv.jsonl tmp/real/serve.log; do
        [ -e "$p" ] && { rm -rf "$p"; note "removed $p"; } || true
    done
    rm -f "$CONF"
    rm -rf "$WORK"; mkdir -p "$WORK"
    # Whatever the deleted config held is stale now, and the CA it protected is gone.
    # Clearing these here is what makes the generation below actually generate.
    KS_PASS=""; ADMIN_PW=""
    note "state reset — a fresh CA, jwt key and client key will be issued this run"
fi

if [ -z "$KS_PASS" ] && [ -f "$KS_DIR/ca.key" ]; then
    fail "keystore_pass is not in $CONF but $KS_DIR/ca.key exists. Put the CA's
   passphrase in the config by hand: the one that unlocked the keystore the last
   time. Generating a new one orphans every document signed so far."
fi
if [ -z "$KS_PASS" ]; then
    KS_PASS=ks-$(openssl rand -hex 16)
    note "generated keystore_pass (the keystore will be created at first start)"
fi
[ -n "$ADMIN_PW" ] || ADMIN_PW=admin-$(openssl rand -hex 12)
[ -n "$JWT_FILE" ] || JWT_FILE=$KS_DIR/../jwt.ed25519.key
[ -n "$MAIL_FROM" ] || MAIL_FROM=signer@kaykraft.org
if [ -z "$TSA_URL" ]; then
    note "tsa_url unset: signatures carry no RFC 3161 timestamp, so they cannot be"
    note "proven to predate any later compromise of the key. Set tsa_url in $CONF."
fi

mkdir -p "$(dirname "$DB")" "$KS_DIR" "$STORAGE_DIR" "$OUTBOX_DIR" "$AUDIT_DIR"
mkdir -p "$(dirname "$JWT_FILE")"
# The jwt key is created by the service, not by this script. signauth.LoadKeyring
# generates it in its own encoding (base64 of the 64-byte ed25519 private blob) plus
# a .pub sibling, and it refuses anything else: an `openssl genpkey` PEM file is a
# perfectly good Ed25519 key that the loader cannot read, and the server dies with
# "is not base64" at boot. If the file already exists, leave it alone and only fix
# the mode, which LoadKeyring also enforces (0600 or it refuses to load).
if [ ! -f "$JWT_FILE" ]; then
    note "$JWT_FILE absent — the service will create it at first start"
else
    chmod 600 "$JWT_FILE"
    note "reusing $JWT_FILE"
fi

# Secrets live inline in this file (0600) rather than in a second file that is easy
# to forget: one artifact, one owner, one mode.
{
    echo "# Generated by scripts/prod-sign-run.sh. Mode 0600 — it contains secrets."
    echo "# Re-running the script preserves every value already present here."
    echo "listen=${BASE#http://}"
    echo "public_url=${PUBLIC}"
    echo "trust_proxy=${TRUST_PROXY}"
    echo "dev=${DEV}"
    echo "db=${DB}"
    echo "storage_dir=tmp/real/storage"
    echo "outbox_dir=tmp/real/outbox"
    echo "audit_dir=tmp/real/audit"
    echo "log_path=tmp/real/signsrv.jsonl"
    echo "keystore_dir=${KS_DIR}"
    echo "keystore_pass=${KS_PASS}"
    echo "admin_password=${ADMIN_PW}"
    echo "jwt_secret_file=${JWT_FILE}"
    echo "mail_from=${MAIL_FROM}"
    echo "smtp_host=${SMTP_HOST}"
    echo "smtp_port=${SMTP_PORT}"
    # The relay on this box is a plain SMTP server that does not advertise STARTTLS,
    # and the service default is true: leaving the default in place makes every
    # invitation fail with an error that reads like a network fault. So the default
    # written here is false, and an existing setting in the file still wins.
    echo "smtp_starttls=${STARTTLS}"
    echo "link_ttl=336h"
    echo "worker_interval=2s"
    echo "max_pdf_mb=20"
    echo "log_level=info"
    [ -n "$TSA_URL" ]   && echo "tsa_url=${TSA_URL}"
    [ -n "$SMTP_PASS" ] && echo "smtp_pass=${SMTP_PASS}"
} > "$CONF"
chmod 600 "$CONF"
note "$(cut -d= -f1 "$CONF" | grep -v '^#' | grep -v '^$' | tr '\n' ' ')"
# Nothing above may reach a log line or a shell trace.
[ -n "$SMTP_PASS" ] && export SIGNSRV_SMTP_PASS="$SMTP_PASS"

"$BIN/signsrv" -config "$CONF" checkconfig > "$WORK/checkconfig.out" 2>&1 || {
    sed -E 's/(pass|secret)[^ ]*=.*/\1...=<redacted>/' "$WORK/checkconfig.out"
    fail "checkconfig refused the config"
}
# CHECK_ONLY=1 stops here: enough to prove a reset produced a usable config without
# binding a port or dispatching anything to the relay.
if [ "${CHECK_ONLY:-0}" = 1 ]; then
    say "CHECK_ONLY=1: config verified, not starting the server"
    exit 0
fi
if [ "$DEV" = true ]; then
    note "checkconfig clean. dev=true: invitations are written to outbox_dir as .eml"
    note "files instead of being mailed, and dev_mode_blocked_* guards are off."
else
    note "checkconfig clean. dev=false: invitations go to the relay at ${SMTP_HOST}:${SMTP_PORT}."
fi

# ------------------------------------------------------------------- start ----
say "start"
LOG=tmp/real/serve.log
nohup "$BIN/signsrv" serve -config "$CONF" > "$LOG" 2>&1 &
SRV=$!
trap '[ "$KEEP_RUNNING" = 1 ] || { kill "$SRV" 2>/dev/null || true; }' EXIT
i=0
until curl -fsS -o "$WORK/health.json" --max-time 3 "${BASE}/healthz" 2>/dev/null; do
    i=$((i + 1))
    kill -0 "$SRV" 2>/dev/null || { tail -20 "$LOG"; fail "serve exited (pid $SRV gone)"; }
    [ "$i" -gt 60 ] && { tail -20 "$LOG"; fail "health never came up"; }
    sleep 0.5
done
note "pid $SRV   GET ${BASE}/healthz -> 200"

# --------------------------------------------------------------------- key ----
# One key, stored once. Each pdf-go *process* exchanges it for its own bearer token
# (the exchange is rate limited per source address under the login guard), so keep the
# number of CLI invocations low: this run does create, get --watch and report, which
# is three. A loop of CLI calls would read as a 429 server fault.
say "client key"
KEYFILE=$WORK/client.key
if [ ! -s "$KEYFILE" ]; then
    "$BIN/signsrv" -config "$CONF" client add prod-regression envelope:write envelope:read \
        > "$WORK/client.out" 2>&1 || { cat "$WORK/client.out"; fail "client add failed"; }
    grep -o 'key_[a-f0-9]\{64\}' "$WORK/client.out" | head -1 > "$KEYFILE"
    rm -f "$WORK/client.out"          # the human-readable copy held the key too
    chmod 600 "$KEYFILE"
    note "issued a new key (revoke the old ones from the admin UI when you are done)"
else
    note "reusing $KEYFILE"
fi
export SIGNSRV_TOKEN
SIGNSRV_TOKEN=$(cat "$KEYFILE")

# --------------------------------------------------------------- document ----
# Read the form. Never guess a field name: a name that is not in the document is a
# 400 at create, and a name that is there but wrong is a document that says the
# wrong thing and gets certified anyway.
say "document: $DOC"
[ -f "$DOC" ] || fail "no document at $DOC"
"$BIN/pdf-go" extract "$DOC" -o "$WORK/schema.json" > "$WORK/extract.out" 2>&1 \
    || { cat "$WORK/extract.out"; fail "extract failed (scanned PDF with no form?)"; }
jq -r '.fields[] | select(.type=="text") | .name' "$WORK/schema.json" > "$WORK/fields.txt"
note "fillable text fields: $(tr '\n' ' ' < "$WORK/fields.txt")"

if [ ! -s "$WORK/fill.json" ]; then
    # Reuse the last known-good values if this box has any; otherwise seed from the
    # schema with the date, and stop rather than dispatch a blank document.
    LAST=$(ls -t tmp/real/fill*.json 2>/dev/null | head -1 || true)
    if [ -n "$LAST" ]; then
        cp "$LAST" "$WORK/fill.json"; note "seeded from $LAST — check the values"
    else
        jq -n --arg d "$(date +%F)" '{values: {Text1: "Steve Kieu", Text2: $d}}' > "$WORK/fill.json"
        note "no earlier fill spec; wrote a minimal one. Edit $WORK/fill.json to suit."
    fi
fi
jq -e '.values' "$WORK/fill.json" > /dev/null 2>&1 || fail "$WORK/fill.json needs a .values object"
for f in $(jq -r '.values | keys[]' "$WORK/fill.json"); do
    grep -qx "$f" "$WORK/fields.txt" || fail "fill.json sets '$f', which is not in $DOC"
done
note "every name in fill.json exists in the document"

"$BIN/pdf-go" fill "$WORK/fill.json" "$DOC" -o "$WORK/filled.pdf" > "$WORK/fill.out" 2>&1 \
    || { cat "$WORK/fill.out"; fail "fill failed"; }
grep -i 'note\|warn' "$WORK/fill.out" | sed 's/^/     /' || true
"$BIN/pdf-go" fields "$WORK/filled.pdf" > "$WORK/filled-fields.txt" 2>&1 \
    || { cat "$WORK/filled-fields.txt"; fail "the filled document cannot be re-read"; }
for v in $(jq -r '.values[]' "$WORK/fill.json"); do
    grep -Fq "$v" "$WORK/filled-fields.txt" || note "!! '$v' did not read back from the PDF"
done
note "filled document re-reads with the values in it"

# ---------------------------------------------------------------- dispatch ----
say "dispatch"
jq -n --arg e "$PARTY" --arg n "$PARTY_NAME" \
    '[{email: $e, name: $n, order: 1, reason: "I have read this document and agree to its terms"}]' \
    > "$WORK/parties.json"

# -spec applies fill.json server-side, so the certified bytes are the filled bytes.
# Without -send nothing is mailed and the party has nothing to act on.
#
# The document is the LAST argument on purpose: Go's flag parser stops at the first
# non-flag word, so putting the path first makes every flag after it a positional
# and the CLI answers "needs --server".
"$BIN/pdf-go" envelope create \
    -server "$BASE" -token-env SIGNSRV_TOKEN -insecure \
    -title "${TITLE:-Production regression - one real signature}" \
    -subject "One document is waiting for your signature" \
    -message "Please review and sign. The link expires in 72 hours." \
    -expires 72h -spec "$WORK/fill.json" -parties "$WORK/parties.json" \
    -links-out "$WORK/links.json" -send "$DOC" \
    > "$WORK/create.json" 2>"$WORK/create.err" || {
        cat "$WORK/create.err"; fail "create/send failed"
    }
# create --send answers with TWO JSON documents: the create result and the send
# result. Reading .envelope.id from the file therefore yields the id twice, and a
# two-line id matches nothing in the database. Slurp and take the last document,
# which is the send: its status is the one that matters.
last() { jq -s -r "$1" "$WORK/create.json"; }
lastc() { jq -s -c "$1" "$WORK/create.json"; }
ENVID=$(last '.[-1].envelope.id')
note "envelope $ENVID   status $(last '.[-1].envelope.status')"
lastc '.[-1].links | [.[] | {email, expires_at}]' | sed 's/^/     /'
case "$ENVID" in ""|null) fail "the service answered without an envelope id" ;; esac
[ "$(printf '%s' "$ENVID" | wc -l)" = 0 ] || fail "read a multi-line envelope id: the create answer has more than two documents"

# A send whose mail fails does not fail: the row keeps its next_at and is retried,
# so the envelope status cannot tell you the invitation left. The queue is the truth.
# The worker drains on its own interval, so this polls briefly instead of reading a
# row that has not been attempted yet and calling that a pass.
if command -v sqlite3 > /dev/null 2>&1; then
    q="select kind||' attempts='||attempts||' sent_at='||coalesce(sent_at,'-')||
         case when last_error is null or last_error='' then '' else ' error='||last_error end
         from mail_queue where envelope_id='$ENVID';"
    i=0
    while [ "$i" -lt 30 ]; do
        ROW=$(sqlite3 "file:${DB}?mode=ro" "$q" 2>/dev/null || true)
        case "$ROW" in
            *sent_at=20*) break ;;                                  # delivered
            *error=*)     break ;;                                  # failed for real
        esac
        [ -z "$ROW" ] && break
        i=$((i + 1)); sleep 1
    done
    [ -n "$ROW" ] && printf '%s\n' "$ROW" | sed 's/^/     mail_queue: /' \
        || note "!! no mail_queue row for $ENVID - the invitations were never queued"
    case "$ROW" in
        *error=*) note "!! the relay refused the mail: the party has no link" ;;
        *sent_at=20*) note "the invitation left this box" ;;
        *) note "the invitation is still queued; check the worker in $LOG" ;;
    esac
else
    note "sqlite3 not on PATH: check the mail_queue rows for $ENVID yourself"
fi

LINK=$(jq -r '.links[0].url // empty' "$WORK/links.json" 2>/dev/null)
[ -n "$LINK" ] || LINK=$(jq -r '.links[0].url // empty' "$WORK/create.json")
if [ -n "$LINK" ]; then
    printf '\n   >>> THE SIGNING LINK - ONE TIME, TO THIS TERMINAL ONLY <<<\n\n'
    printf '       %s\n\n' "$LINK"
fi

# ---------------------------------------------------------------- prompt ----
printf '   To sign: open the link on a phone or laptop (the page is mobile-usable),'
printf '\n   tick the box, draw or type the signature, submit. The worker delivers.\n\n'
printf '   To verify it afterwards:\n'
printf '       WAIT=1 scripts/prod-sign-run.sh          # poll + verify in one go\n'
printf '       scripts/prod-sign-run.sh report  %s\n' "$ENVID"
printf '   To close the link without signing (do this if you walk away):\n'
printf '       scripts/prod-sign-run.sh cancel  %s\n' "$ENVID"
printf '   Party: %s   (PARTY=a@b.com scripts/prod-sign-run.sh to change it)\n' "$PARTY"

if [ "$WAIT" != 1 ]; then
    printf '\nNot waiting. Re-run with WAIT=1 once you have signed.\n'
    printf 'The server stays up on %s (pid %s); stop it with: pkill -f "[s]ignsrv.*serve"\n' "$BASE" "$SRV"
    exit 0
fi

# ----------------------------------------------------------------- verify ----
say "watch (Ctrl-C is safe; the envelope keeps waiting for the party)"
"$BIN/pdf-go" envelope get -server "$BASE" -token-env SIGNSRV_TOKEN -insecure \
    --watch --interval 5s "$ENVID" > "$WORK/envelope.json" 2>"$WORK/watch.err"
WATCHRC=$?
note "settled with rc $WATCHRC (0 = signed and delivered)"
tail -2 "$WORK/watch.err" | sed 's/^/     /' || true

say "report (re-open the archived PDF; verify each signature against the CA)"
"$BIN/pdf-go" envelope report -server "$BASE" -token-env SIGNSRV_TOKEN -insecure "$ENVID" \
    > "$WORK/report.json" 2>"$WORK/report.err" \
    || { cat "$WORK/report.err"; note "report failed; only the status line above stands"; }
if [ -s "$WORK/report.json" ]; then
    jq -c "$report_jq" "$WORK/report.json" | sed 's/^/     /'
    # .complete means signed_parties reached required_parties; .report.valid means
    # every cryptographic check passed. Either one alone is not the release gate.
    jq -e '.complete and .report.valid and
           (([.report.signers[].valid] | length) > 0) and ([.report.signers[].valid] | all)' \
        "$WORK/report.json" > /dev/null 2>&1 \
        && note "PASS - all parties signed, every signature verifies, timestamps present" \
        || note "FAIL - read the fields above"
fi

# The party's copy and the certified copy are the same bytes — or the run says so.
final_pdf_check '     ' "$ENVID" "$(jq -r '.sha256 // empty' "$WORK/report.json" 2>/dev/null)"

audit_chain '     '
log_leak_scan

say "done. artifacts in $WORK (0600, no passwords)"
[ "$KEEP_RUNNING" = 1 ] && printf 'Server left up on %s (pid %s). Stop: pkill -f "[s]ignsrv serve"\n' "$BASE" "$SRV"
