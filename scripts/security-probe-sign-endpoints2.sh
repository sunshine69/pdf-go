#!/bin/sh
# Part 2 of the endpoint audit: the probes that need a CLAIMED session.
# Nothing here signs anything: every consent body is one the service must
# refuse, so the envelope stays unsigned and the party can still sign it. It
# does CONSUME the link (a claim spends it), so run it against a request nobody
# cares about.
#
# Usage:  sh scripts/security-probe-sign-endpoints2.sh <base-url> <links.json> [log-path]
#   links.json  the file `pdf-go envelope create --send --links-out` wrote
#   log-path    the service's log_path; without it section 18 is skipped
B=${1:?base-url, e.g. http://127.0.0.1:47085}
LINKS=${2:?links.json written by envelope create --send}
S=$(mktemp -d); echo "workspace: $S"
TOK=$(jq -r '.links[0].token // (.links[0].url | sub(".*/s/"; ""))' "$LINKS")
EMAIL=$(jq -r '.links[0].email' "$LINKS")
JAR=$S/jar.txt
LOG=${3:-}
printf 'party %s   token %s... (elided)\n' "$EMAIL" "$(echo "$TOK" | cut -c1-10)"

echo
echo "== 11. claim with the invited address (the honest path)"
code=$(curl -sS -c $JAR -o $S/claim.json -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' -d "{\"email\":\"$EMAIL\"}" \
  "$B/api/v1/sign/$TOK/claim")
echo "   POST claim <invited address>              -> $code"; head -c 160 $S/claim.json; echo
grep -i 'signsrv_session\|Set-Cookie' $JAR | sed 's/\t.*value/\t<value elided>/' | sed 's/^/   cookie: /' | cut -c1-110

echo
echo "== 12. the document, with the session"
curl -sS -b $JAR -D $S/hdr.txt -o $S/doc.pdf -w '   GET document -> %{http_code}  %{size_download} bytes\n' \
  "$B/api/v1/sign/$TOK/document"
grep -i 'content-type\|content-disposition\|cache-control\|x-content-sha256\|x-frame\|content-security' \
  $S/hdr.txt | tr -d '\r' | sed 's/^/   /'
file $S/doc.pdf | sed 's/^/   /'

echo
echo "== 13. the view, with the session (what state is released, and to whom)"
curl -sS -b $JAR -o $S/view.json "$B/api/v1/sign/$TOK/envelope"
jq -c 'keys' $S/view.json | sed 's/^/   keys: /'
jq -c '{status, document_sha: (.document_sha[0:12]), my, parties}' $S/view.json | sed 's/^/   /'

SHA=$(jq -r '.document_sha' $S/view.json)

echo
echo "== 14. consent body rules, behind the session"
c() { printf '   %-42s -> ' "$1"; shift; curl -sS -b $JAR -o $S/b.json -w '%{http_code}' \
        -X POST "$@" "$B/api/v1/sign/$TOK/consent"; echo "  $(head -c 60 $S/b.json | tr -d '\n')"; }
c "no consent flag"            -H 'Content-Type: application/json' \
  -d "{\"signature_text\":\"Steve Kieu\",\"document_sha\":\"$SHA\"}"
c "consent:false"              -H 'Content-Type: application/json' \
  -d "{\"consent\":false,\"signature_text\":\"Steve Kieu\",\"document_sha\":\"$SHA\"}"
c "a JSON array, not an object" -H 'Content-Type: application/json' -d '[1,2,3]'
c "text/plain body"            -H 'Content-Type: text/plain' -d 'consent=true'
c "empty signature text"       -H 'Content-Type: application/json' \
  -d "{\"consent\":true,\"signature_text\":\"\",\"document_sha\":\"$SHA\"}"
c "signature text of 500 runes" -H 'Content-Type: application/json' \
  -d "{\"consent\":true,\"signature_text\":\"$(head -c 500 $S/view.json)\",\"document_sha\":\"$SHA\"}"
c "digest of a different document" -H 'Content-Type: application/json' \
  -d "{\"consent\":true,\"signature_text\":\"Steve Kieu\",\"document_sha\":\"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"}"
head -c 2097152 /dev/zero | tr '\0' 'a' > $S/big.json
c "2 MB body"                  -H 'Content-Type: application/json' --data-binary "@$S/big.json"
c "CRLF in the signature text" -H 'Content-Type: application/json' \
  -d "{\"consent\":true,\"signature_text\":\"Steve\\r\\nKieu\",\"document_sha\":\"$SHA\"}"

echo
echo "== 15. an oversized consent image (canvas output is base64 in the body)"
head -c 700000 /dev/zero | tr '\0' 'a' > $S/img.b64
c "image larger than the cap"  -H 'Content-Type: application/json' \
  -d "{\"consent\":true,\"signature_text\":\"Steve Kieu\",\"document_sha\":\"$SHA\",\"image\":\"data:image/png;base64,$(cat $S/img.b64)\"}"
c "GIF body under a jpeg label" -H 'Content-Type: application/json' \
  -d "{\"consent\":true,\"signature_text\":\"Steve Kieu\",\"document_sha\":\"$SHA\",\"image\":\"data:image/jpeg;base64,$(printf 'GIF89a' | base64)\"}"

echo
echo "== 16. the consent bucket (keyed on the link, 10/min)"
: > $S/cc; n=1
while [ $n -le 14 ]; do
  curl -sS -b $JAR -o $S/b.json -w '%{http_code}\n' -X POST \
    -H 'Content-Type: application/json' -d '{"consent":false}' \
    "$B/api/v1/sign/$TOK/consent" >> $S/cc
  n=$((n+1))
done
tr '\n' ' ' < $S/cc | sed 's/^/   codes: /'; echo
echo "   400s: $(grep -c 400 $S/cc)   429s: $(grep -c 429 $S/cc)"

echo
echo "== 17. state after every probe: nothing was signed"
curl -sS -b $JAR -o $S/view2.json "$B/api/v1/sign/$TOK/envelope"
jq -c '{status, all_consented, my: {status: .my.status, consent_at: .my.consent_at}}' \
  $S/view2.json | sed 's/^/   /'

echo
echo "== 18. the log: the token never in the clear"
if [ -f "$LOG" ]; then
  echo "   live token occurrences in the log: $(grep -c "$TOK" "$LOG")"
  tail -500 "$LOG" | jq -r '.path // empty' 2>/dev/null | grep -c 'sign/[a-z0-9]\{20,\}' \
    | sed 's/^/   log lines with an unredacted token: /'
  tail -500 "$LOG" | jq -r '.path // empty' 2>/dev/null | grep 'sign/' | sort -u | head -3 | sed 's/^/   /'
  tail -500 "$LOG" | jq -r '.cookie // empty' 2>/dev/null | grep -c '=' | sed 's/^/   cookie values logged: /'
  jq -r 'select(.authorization != null) | .authorization' "$LOG" 2>/dev/null | sort -u | \
    sed 's/^/   authorization field values logged: /'
  jq -r 'select(.token != null) | .token' "$LOG" 2>/dev/null | sort -u | head -3 | \
    sed 's/^/   token field values logged: /'
else
  echo "   no log file at $LOG"
fi
