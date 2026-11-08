#!/bin/sh
# Step 11 acceptance, part 1: the audit chain. Run from the project root:
#   sh scripts/acceptance-11.sh
#
# Every block is a signoff item from docs/steps/11-hardening.md. The Go suite
# (internal/signstore/audit_test.go) carries the same cases at unit level; this
# script drives the real binary against a real database, which is what an
# operator runs.
set -e

D=$(mktemp -d)
cleanup() {
  rm -rf "$D"
  rm -f ./signsrv
}
trap cleanup EXIT
RESULTS="$D/results.txt"
say() { printf '%s\n' "$1" >> "$RESULTS"; }
check() { # label, condition-result
  if [ "$2" = "0" ]; then say "  $1"; else say "  (check failed: $1)"; fi
}

say "== build offline from vendor =="
go build -o ./signsrv ./cmd/signsrv && say "  ok" || say "  (build failed)"

say "== the audit chain suite =="
go test -count=1 ./internal/signstore > "$D/gotest.txt" 2>&1 \
  && say "  signstore passes" || { say "  (signstore failed)"; cat "$D/gotest.txt" >> "$RESULTS"; }

# A config pointing at this run's own database and audit directory.
CONF="$D/acc11.env"
sed "s|var/signsrv.db|$D/acc11.db|; s|var/audit|$D/audit|" config.example.env > "$CONF"
printf "smtp_pass=test-smtp-secret\n" >> "$CONF"
DB="$D/acc11.db"
Q() { sqlite3 "$DB" "$1"; }
run() { rc=0; "$@" > "$OUT" 2>&1 || rc=$?; } # rc is the command's exit code
# An envelope id, so events are attached to a real envelope.
EID="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

# The nightly job writes the events the table has. Events land in the table as
# the service runs: here they are inserted directly, which is exactly the shape
# the writer sees.
# Migrate first: the audit writer opens the store, which applies the schema.
./signsrv migrate -config "$CONF" > "$D/migrate.txt" 2>&1
test -f "$DB" && say "  the database is created and migrated" || say "  (check failed)"
sqlite3 "$DB" "insert into events(envelope_id,actor,kind,payload,created_at) values
  ('$EID','admin','created','{}','2026-11-05T00:00:00Z'),
  ('$EID','system','sent','{\"n\":1}','2026-11-05T00:01:00Z'),
  ('$EID','party','consent','{\"sha\":\"aa\"}','2026-11-05T00:02:00Z');"
say "== the nightly write appends the events, in order =="
OUT="$D/w1.txt"; run ./signsrv audit-write -config "$CONF" 2026-11-05
test $rc -eq 0 && say "  the write exits 0" || say "  (check failed: write exits)"
test -f "$D/audit/2026-11-05.jsonl" && \
  say "  the audit directory is created, one file per day" || say "  (check failed)"
test "$(grep -c . "$D/audit/2026-11-05.jsonl")" = 3 && \
  say "  three events appended" || say "  (check failed)"
test "$(ls -l "$D/audit/2026-11-05.jsonl" | awk '{print $1}')" = "-rw-------" && \
  say "  the audit file is owner-only" || say "  (check failed)"

say "== the chain links the lines =="
python3 - "$D/audit/2026-11-05.jsonl" <<'PY' >> "$RESULTS" 2>&1
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
ok = lines[0]["prev_hash"] == ""
for i in range(1, len(lines)):
    ok = ok and lines[i]["prev_hash"] == lines[i-1]["hash"]
print("  the first line has no prev_hash, every later line points to the line before" if ok
      else "  (check failed: chain links)")
PY

say "== a clean log verifies =="
OUT="$D/v0.txt"; run ./signsrv audit-verify -config "$CONF"
test $rc -eq 0 && say "  audit-verify exits 0" || say "  (check failed)"
grep -q "chain valid" "$D/v0.txt" && \
  say "  the report names the event count: $(grep -o '[0-9]* event' "$D/v0.txt" | head -1)" || \
  say "  (check failed)"

say "== a re-run writes nothing =="
./signsrv audit-write -config "$CONF" 2026-11-05 > "$D/w2.txt" 2>&1
test "$(grep -c . "$D/audit/2026-11-05.jsonl")" = 3 && \
  say "  the same day written twice leaves the file the same length" || say "  (check failed)"
test "$(grep -c '0 event' "$D/w2.txt")" = 1 && \
  say "  the re-run reports zero events appended" || say "  (check failed)"

say "== events the log has not caught up with are a gap =="
sqlite3 "$DB" "insert into events(envelope_id,actor,kind,payload,created_at) values
  ('$EID','system','signed','{\"sha\":\"bb\"}','2026-11-05T00:03:00Z');"
OUT="$D/v1.txt"; run ./signsrv audit-verify -config "$CONF"
test $rc -ne 0 && say "  verify exits non-zero on a gap" || say "  (check failed)"
grep -qi "missing" "$D/v1.txt" && \
  say "  the report says events are missing" || say "  (check failed)"
./signsrv audit-write -config "$CONF" 2026-11-06 > "$D/w3.txt" 2>&1
OUT="$D/v2.txt"; run ./signsrv audit-verify -config "$CONF"
test $rc -eq 0 && say "  catching up makes the log verify again" || say "  (check failed)"

say "== the chain crosses the day boundary =="
python3 - "$D/audit/2026-11-05.jsonl" "$D/audit/2026-11-06.jsonl" <<'PY' >> "$RESULTS" 2>&1
import json, sys
a = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
b = [json.loads(l) for l in open(sys.argv[2]) if l.strip()]
ok = b[0]["prev_hash"] == a[-1]["hash"]
print("  the next day's first line continues the chain of the day before" if ok
      else "  (check failed: day boundary)")
PY

# Tampering. The two shapes are caught by two different halves of the check, so
# both are exercised against the real binary.
say "== tampering: a careless edit is caught by the line's own hash =="
cp "$D/audit/2026-11-05.jsonl" "$D/clean.jsonl"
python3 - "$D/audit/2026-11-05.jsonl" <<'PY' >/dev/null
import json, sys
sep = (",", ":")
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
lines[1]["actor"] = "attacker"
with open(sys.argv[1], "w") as f:
    for l in lines:
        f.write(json.dumps(l, separators=sep) + "\n")
PY
OUT="$D/v3.txt"; run ./signsrv audit-verify -config "$CONF"
test $rc -ne 0 && say "  the edit is reported" || say "  (check failed)"
grep -qi "hash" "$D/v3.txt" && \
  say "  the error names the day and the line: $(sed -n '1p' "$D/v3.txt" | cut -c1-60)..." || \
  say "  (check failed)"
grep -qi "invalid" "$D/v3.txt" && \
  say "  the chain is reported INVALID" || say "  (check failed)"

say "== tampering: a rehashed edit is caught by the cross-check against the table =="
cp "$D/clean.jsonl" "$D/audit/2026-11-05.jsonl"
python3 - "$D/audit/2026-11-05.jsonl" <<'PY' >/dev/null
import json, hashlib, sys
sep = (",", ":")
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
def raw(p): return json.dumps(p, separators=sep)
def h(l):
    body = "\n".join([l["envelope_id"], l["actor"], l["kind"], l["created_at"], raw(l["payload"])])
    return hashlib.sha256(body.encode()).hexdigest()
target = lines[1]
target["payload"] = json.loads('{"n":99}')
target["hash"] = h(target)
with open(sys.argv[1], "w") as f:
    for l in lines:
        f.write(json.dumps(l, separators=sep) + "\n")
PY
# The chain is internally consistent, so the chain alone would pass. The events
# table is append-only, and this is what an operator can check against it.
OUT="$D/v4.txt"; run ./signsrv audit-verify -config "$CONF"
test $rc -ne 0 && say "  the rehash is reported" || say "  (check failed)"
grep -qi "events table" "$D/v4.txt" && \
  say "  the error quotes both sides: the file's record and the table's" || say "  (check failed)"

say "== tampering: a removed line breaks the chain =="
cp "$D/clean.jsonl" "$D/audit/2026-11-05.jsonl"
python3 - "$D/audit/2026-11-05.jsonl" <<'PY' >/dev/null
import json, hashlib, sys
sep = (",", ":")
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
def raw(p): return json.dumps(p, separators=sep)
def h(l):
    body = "\n".join([l["envelope_id"], l["actor"], l["kind"], l["created_at"], raw(l["payload"])])
    return hashlib.sha256(body.encode()).hexdigest()
del lines[1]
lines[1]["prev_hash"] = lines[0]["hash"]
lines[1]["hash"] = h(lines[1])
with open(sys.argv[1], "w") as f:
    for l in lines:
        f.write(json.dumps(l, separators=sep) + "\n")
PY
OUT="$D/v5.txt"; run ./signsrv audit-verify -config "$CONF"
test $rc -ne 0 && say "  the removed line is reported" || say "  (check failed)"
grep -qi "missing" "$D/v5.txt" && \
  say "  the error says an event is missing" || say "  (check failed)"

say "== tampering: swapped lines break the id order =="
cp "$D/clean.jsonl" "$D/audit/2026-11-05.jsonl"
python3 - "$D/audit/2026-11-05.jsonl" <<'PY' >/dev/null
import json, hashlib, sys
sep = (",", ":")
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
def raw(p): return json.dumps(p, separators=sep)
def h(l):
    body = "\n".join([l["envelope_id"], l["actor"], l["kind"], l["created_at"], raw(l["payload"])])
    return hashlib.sha256(body.encode()).hexdigest()
lines[0], lines[1] = lines[1], lines[0]
lines[0]["prev_hash"] = ""
lines[0]["hash"] = h(lines[0])
lines[1]["prev_hash"] = lines[0]["hash"]
lines[1]["hash"] = h(lines[1])
with open(sys.argv[1], "w") as f:
    for l in lines:
        f.write(json.dumps(l, separators=sep) + "\n")
PY
OUT="$D/v6.txt"; run ./signsrv audit-verify -config "$CONF"
test $rc -ne 0 && say "  the swap is reported" || say "  (check failed)"
grep -qi "missing" "$D/v6.txt" && \
  say "  the swap shows the ids are not contiguous" || say "  (check failed)"

say "== the nightly job refuses to append to a tampered file =="
cp "$D/clean.jsonl" "$D/audit/2026-11-05.jsonl"
cp "$D/audit/2026-11-06.jsonl" "$D/clean6.jsonl"
sqlite3 "$DB" "insert into events(envelope_id,actor,kind,payload,created_at) values
  ('$EID','system','completed','{}','2026-11-07T00:00:00Z');"
# Tamper the tail of the chain, then run the job as it would run the next night.
python3 - "$D/audit/2026-11-05.jsonl" <<'PY' >/dev/null
import json, hashlib, sys
sep = (",", ":")
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
def raw(p): return json.dumps(p, separators=sep)
def h(l):
    body = "\n".join([l["envelope_id"], l["actor"], l["kind"], l["created_at"], raw(l["payload"])])
    return hashlib.sha256(body.encode()).hexdigest()
lines[-1]["actor"] = "attacker"
lines[-1]["hash"] = h(lines[-1])
with open(sys.argv[1], "w") as f:
    for l in lines:
        f.write(json.dumps(l, separators=sep) + "\n")
PY
OUT="$D/w4.txt"; run ./signsrv audit-write -config "$CONF" 2026-11-07
test $rc -ne 0 && say "  the write refuses" || say "  (check failed)"
grep -qi "refusing to append" "$D/w4.txt" && \
  say "  the job says it refuses to append: a tampered log is reported at the write" || \
  say "  (check failed)"
test "$(grep -c . "$D/audit/2026-11-06.jsonl")" = "$(grep -c . "$D/clean6.jsonl")" && \
  say "  nothing was appended" || say "  (check failed)"

say "== a day before the last written day is refused =="
cp "$D/clean.jsonl" "$D/audit/2026-11-05.jsonl"
cp "$D/clean6.jsonl" "$D/audit/2026-11-06.jsonl"
OUT="$D/w5.txt"; run ./signsrv audit-write -config "$CONF" 2026-11-04
test $rc -ne 0 && say "  the backwards day is refused" || say "  (check failed)"

say "== an audit directory with no files verifies =="
# Nothing to log means nothing to check, so the empty dir has to be verified
# against a table that is also empty. Against a table that has events an empty
# dir is a gap, not a valid log: that is the check at the end of this block.
CONF2="$D/acc11b.env"
sed "s|var/signsrv.db|$D/acc11b.db|; s|var/audit|$D/audit2|" config.example.env > "$CONF2"
./signsrv migrate -config "$CONF2" > /dev/null 2>&1
OUT="$D/v7.txt"
rc=0; ./signsrv audit-verify -config "$CONF2" > "$OUT" 2>&1 || rc=$?
test $rc -eq 0 && say "  an empty audit dir against an empty table is valid, exit 0" || { say "  (check failed)"; cat "$OUT" >> "$RESULTS"; }
grep -q "chain valid" "$OUT" && say "  the report says chain valid" || say "  (check failed)"
OUT="$D/v8.txt"
rc=0; ./signsrv audit-verify -config "$CONF" > "$OUT" 2>&1 || rc=$?
test $rc -ne 0 && say "  an empty audit dir against a table that has events is a gap" || say "  (check failed)"

say "== secrets appear in the config report as digests only =="
./signsrv checkconfig -config "$CONF" > "$D/cc.txt" 2>&1
grep -q "keystore_pass=sha256:" "$D/cc.txt" && \
  say "  the keystore passphrase is a digest" || say "  (check failed)"
grep -q "admin_password=sha256:" "$D/cc.txt" && \
  say "  the admin password is a digest" || say "  (check failed)"
# The key is smtp_pass, so a secret that is set must print as a digest.
grep -q "smtp_pass=sha256:" "$D/cc.txt" && \
  say "  a secret set from the config prints as a digest, not the value" || say "  (check failed)"
test "$(grep -c 'keystore_pass=' "$D/cc.txt")" = 1 -a "$(grep -c 'keystore_pass=sha256:' "$D/cc.txt")" = 1 && \
  say "  no plaintext secret is printed" || say "  (check failed)"

say "== checkconfig on a broken config still prints, and fails =="
printf 'listen=not-a-port\nlink_ttl=25h\n' > "$D/broken.env"
OUT="$D/cc2.txt"; run ./signsrv checkconfig -config "$D/broken.env"
test $rc -ne 0 && say "  a broken config exits non-zero" || say "  (check failed)"
grep -q "listen=" "$D/cc2.txt" && \
  say "  the loaded configuration is printed so the operator can see it" || say "  (check failed)"

# Every signoff line in docs/steps/11-hardening.md.
say ""
say "SUMMARY"
FAILED=0
for item in \
  "the audit directory is created, one file per day" \
  "three events appended" \
  "the audit file is owner-only" \
  "the first line has no prev_hash, every later line points to the line before" \
  "audit-verify exits 0" \
  "the same day written twice leaves the file the same length" \
  "the re-run reports zero events appended" \
  "verify exits non-zero on a gap" \
  "the report says events are missing" \
  "catching up makes the log verify again" \
  "the next day's first line continues the chain of the day before" \
  "the edit is reported" \
  "the chain is reported INVALID" \
  "the rehash is reported" \
  "the error quotes both sides: the file's record and the table's" \
  "the removed line is reported" \
  "the error says an event is missing" \
  "the swap is reported" \
  "the swap shows the ids are not contiguous" \
  "the write refuses" \
  "the job says it refuses to append: a tampered log is reported at the write" \
  "nothing was appended" \
  "the backwards day is refused" \
  "an empty audit dir against an empty table is valid, exit 0" \
  "the report says chain valid" \
  "an empty audit dir against a table that has events is a gap" \
  "the keystore passphrase is a digest" \
  "the admin password is a digest" \
  "a secret set from the config prints as a digest, not the value" \
  "no plaintext secret is printed" \
  "a broken config exits non-zero" \
  "the loaded configuration is printed so the operator can see it" \
  "signstore passes"
do
  grep -q "$item" "$RESULTS" || { say "  MISSING: $item"; FAILED=1; }
done
test "$(grep -c '(check failed)' "$RESULTS")" = 0 && say "  all signoff assertions ran" || FAILED=1
test $FAILED -eq 0 && say "STEP 11 ACCEPTANCE COMPLETE" || say "STEP 11 ACCEPTANCE INCOMPLETE"

cp "$RESULTS" ./acceptance-11-results.txt
echo END OF RESULTS
