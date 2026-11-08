#!/bin/sh
# drafter-notify-live.sh — the drafter's notices against the running instance.
#
# The unit tests cover the rules; this proves them on the real binary with the
# real database and the real relay: create with notify_email, claim the party's
# link, decline, and check that the notice reached the queue addressed to the
# drafter and then left the box.
#
# Nothing here is new to the service. Every step is a call the SPA or the CLI
# already makes.
#
# Usage: sh scripts/drafter-notify-live.sh
set -eu
cd "$(dirname "$0")/.."

BIN=${BIN_DIR:-tmp/bin}
BASE=${BASE:-http://127.0.0.1:8090}
WORK=${WORK:-tmp/prod-run}
DOC=${DOC:-testdata/sample2.pdf}
KEYFILE=$WORK/client.key
CONF=${CONF:-tmp/prod.conf}
NOTIFY=${NOTIFY:-msh.computing@gmail.com}
PARTY=${PARTY:-msh.computing@gmail.com}
DB=$(grep '^db=' "$CONF" | cut -d= -f2)
FAILS=0
say() { printf '%s\n' "$*"; }
ok()  { say "  PASS  $*"; }
bad() { say "  FAIL  $*"; FAILS=$((FAILS + 1)); }
KEY=$(cat "$KEYFILE")

say "== 1. create an envelope that names a drafter address"
"$BIN/pdf-go" envelope create \
    -server "$BASE" -key "$KEY" \
    -title "Drafter-notify live test" \
    -expires 1h -spec "$WORK/fill.json" -parties "$WORK/parties.json" \
    -notify "$NOTIFY" \
    -links-out "$WORK/notify-links.json" -send "$DOC" \
    >"$WORK/notify-create.out" 2>&1 || { cat "$WORK/notify-create.out"; bad "create failed"; exit 1; }

ENV=$(jq -r '.envelope.id' "$WORK/notify-links.json")
TOK=$(jq -r '.links[0].token' "$WORK/notify-links.json")
say "  envelope $ENV"

# The stored column, not the request we just sent: a value that round-trips is
# the only proof the write path and the read path agree.
STORED=$(sqlite3 "$DB" "select notify_email from envelopes where id='$ENV';")
[ "$STORED" = "$NOTIFY" ] && ok "envelope stores notify_email=$STORED" \
    || bad "notify_email = '$STORED', want $NOTIFY"

say "== 2. the envelope view carries it back to the caller"
VIEW=$(curl -s -H "Authorization: Bearer $KEY" "$BASE/api/v1/envelopes/$ENV")
echo "$VIEW" | grep -q "\"notify_email\":\"$NOTIFY\"" \
    && ok "GET /envelope names the drafter address" \
    || bad "envelope view omits notify_email: $(echo "$VIEW" | head -c 200)"

say "== 3. the party claims the link, then declines"
JAR=$(mktemp)
CODE=$(curl -s -o "$WORK/claim.out" -w '%{http_code}' -c "$JAR" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$PARTY\"}" "$BASE/api/v1/sign/$TOK/claim")
[ "$CODE" = 200 ] && ok "claim -> 200" || bad "claim -> $CODE: $(cat "$WORK/claim.out")"

CODE=$(curl -s -o "$WORK/decline.out" -w '%{http_code}' -b "$JAR" \
    -H 'content-type: application/json' \
    -d '{"reason":"the term sheet attached is not the one we agreed"}' \
    "$BASE/api/v1/sign/$TOK/decline")
[ "$CODE" = 200 ] && ok "decline -> 200" || bad "decline -> $CODE: $(cat "$WORK/decline.out")"

say "== 4. the notice is queued to the drafter, not to the party"
sleep 3
sqlite3 "$DB" "select kind || ' to=' || coalesce(recipient,'-') || ' about=' ||
    substr(party_id,1,8) || ' detail=' || coalesce(substr(detail,1,40),'-')
    from mail_queue where envelope_id='$ENV' order by id;" | sed 's/^/     /'

ROWS=$(sqlite3 "$DB" "select count(*) from mail_queue where envelope_id='$ENV' and kind='declined';")
[ "$ROWS" = 1 ] && ok "one declined row" || bad "$ROWS declined rows, want 1"

TO=$(sqlite3 "$DB" "select recipient from mail_queue where envelope_id='$ENV' and kind='declined';")
[ "$TO" = "$NOTIFY" ] && ok "notice addressed to the drafter $TO" \
    || bad "notice addressed to '$TO', want $NOTIFY"

STATUS=$(sqlite3 "$DB" "select status from envelopes where id='$ENV';")
[ "$STATUS" = failed ] && ok "envelope is failed after the decline" \
    || bad "envelope status = $STATUS, want failed"

say "== 5. the notice left the box, and quotes the reason"
for i in 1 2 3 4 5 6 7 8 9 10; do
    SENT=$(sqlite3 "$DB" "select coalesce(sent_at,'') from mail_queue where envelope_id='$ENV' and kind='declined';")
    [ -n "$SENT" ] && break
    sleep 2
done
[ -n "$SENT" ] && ok "notice sent at $SENT" || bad "notice still unsent after 20s"

OUT=$(ls -t "$(grep '^outbox_dir=' "$CONF" | cut -d= -f2)" 2>/dev/null | head -1)
# dev=false, so the message went to the relay and never touched outbox_dir. The
# queue row is the fact that it left; this only proves the body when the
# instance happens to be in dev mode.
if [ -n "$OUT" ] && [ -f "$(grep '^outbox_dir=' "$CONF" | cut -d= -f2)/$OUT" ]; then
    F=$(grep '^outbox_dir=' "$CONF" | cut -d= -f2)/$OUT
    grep -q "the term sheet attached is not the one we agreed" "$F" \
        && ok "the outbox copy carries the party's reason" \
        || say "  n/a   newest outbox file is not this notice"
else
    say "  n/a   dev=false: the body is at the relay, not in outbox_dir"
fi

say "== 6. a notice does not breed a notice, and the old behaviour is intact"
N=$(sqlite3 "$DB" "select count(*) from mail_queue where envelope_id='$ENV';")
[ "$N" = 2 ] && ok "queue holds exactly the invite and the notice ($N rows)" \
    || bad "$N rows on this envelope, want 2"

EV=$(sqlite3 "$DB" "select count(*) from events where envelope_id='$ENV' and kind='declined';")
[ "$EV" = 1 ] && ok "the decline is still in the audit trail" || bad "$EV decline events, want 1"

say ""
say "envelope $ENV — close it with:"
say "  scripts/prod-sign-run.sh cancel $ENV"
[ "$FAILS" = 0 ] || say "$FAILS check(s) failed"
exit "$FAILS"
