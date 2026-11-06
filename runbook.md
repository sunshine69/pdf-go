# signsrv runbook

The operational procedures. Each one is a command you run, in order, with the
output you should see.

The service runs as the user `signsrv`, with its state in `/var/lib/signsrv`
(`deploy/signsrv.service`). The commands below use `$STATE` for that directory
and `$CFG` for the config file. Every command reads the config the same way:
`signsrv <cmd> -config $CFG`, with secrets in the environment.

## Daily

`signsrv audit-write` appends the events newer than the last written position
to `var/audit/<date>.jsonl`, with a running SHA-256 chain. Run it at 00:05:

```
systemctl start signsrv-audit-write.service
```

`signsrv audit-verify` walks the audit files in date order and checks the
chain: every line's hash matches its content, every `prev_hash` matches the
line before it, and the event ids strictly increase. It prints the number of
events verified, or the first break, and exits non-zero on a break. Run it
after the write, and after any restore:

```
systemctl start signsrv-audit-verify.service
```

```
events verified: 1204   chain ok, 41 files
```

A break is not a cosmetic problem. It means a line in an audit file does not
match what the database holds. Treat the audit file as the evidence and the
database as the source, and find out which one was changed.

## Hourly backup

SQLite is in WAL mode. Copying `signsrv.db` while the service runs gives you
a file with the committed data missing from the WAL. `sqlite3 .backup` is the
WAL-safe form:

```
sqlite3 /var/lib/signsrv/signsrv.db ".backup '/var/backups/signsrv/signsrv.db'"
```

Retention is 30 days. The backup is the database, which holds the token
hashes, the consent text, the signature text, the IP addresses, and the mail
bodies. It is encrypted at rest on the backup host, and mode 0600.

The document store (`var/storage`) is append-only: a signed document is
written once and never rewritten. `rsync --ignore-existing` is enough, because
there is nothing to update:

```
rsync -a --ignore-existing /var/lib/signsrv/storage/ /var/backups/signsrv/storage/
```

The keystore (`var/keystore`) is the CA private key. It is backed up once, to
a device kept offline, together with the passphrase. There is no second copy
of the passphrase inside the service. See `SECURITY.md`.

## Restore

Restore is a copy, then three checks. The service is stopped for the copy.

```
systemctl stop signsrv.service
cp /var/backups/signsrv/signsrv.db /var/lib/signsrv/signsrv.db
rsync -a /var/backups/signsrv/storage/ /var/lib/signsrv/storage/
```

Then:

```
signsrv migrate      -config $CFG   # applies pending migrations, runs integrity_check
signsrv audit-verify -config $CFG   # the audit chain validates
signsrv sign-selftest -config $CFG   # certify, sign three parties, verify
```

`signsrv migrate` prints the schema version reached and the result of
`integrity_check`. A restore of an older backup followed by `migrate` moves
the schema forward; the migrations are additive and never drop a table.

`signsrv sign-selftest` is the end-to-end check: it produces a document,
signs it with the keystore, and verifies the result. It exits 0 only when the
finished document is valid. If it fails, the keystore is not decrypting with
the passphrase the environment carries — which is the failure that means the
restore is not usable.

`signsrv dbstatus` prints the schema version and the row counts of every
table. Compare against the numbers from before the restore.

If `audit-verify` fails on the restored copy, restore the audit files too:
they are in `var/audit`, and they are the evidence.

## Status checks

```
signsrv checkconfig -config $CFG    # effective config, secrets as digests
signsrv dbstatus     -config $CFG    # schema version and row counts
```

`checkconfig` exits non-zero listing every problem. It prints the redacted
configuration even when the configuration is broken — that is the line to
paste into a ticket. A warning does not stop the service: it names a setting
that works and should not be used.

## The queue

The worker drains the mail queue and the signing queue. In-process, it runs
every `worker_interval` (15s by default). A deployment that runs it as a
second systemd unit (`signsrv worker`) so mail delivery and batch signing
cannot stall the HTTP service:

```
systemctl start signsrv-worker.service
```

Set `worker_interval=0` to disable the in-process drainer.

Batch signing takes a lease on each document. A crash leaves leases behind.
`sweep` releases them:

```
signsrv sweep -config $CFG
```

`sweep` expires the tokens and envelopes whose deadline has passed, deletes
the expired revocations, requeues the batch leases left over from a crash, and
marks the failed batches. It is safe to run at any time, and it is the command
to run after a kill.

## Shutdown

`SIGTERM` cancels the base context, so the in-flight signing requests finish
and then the process exits. Requests that are in flight have a 90s deadline
(the signing path includes the timestamp authority call), so a graceful
shutdown takes up to 90s. systemd's `TimeoutStopSec` is set to 120s for that
reason.

`kill -9` mid-signing leaves a batch lease behind, which `sweep` releases. It
does not corrupt the document store: a document is written once, under a
content-hash name, and a partial write is never read.

## Passwords, keys, rotation

The rotation table is in `SECURITY.md`. The commands:

```
signsrv admin passwd EMAIL   -config $CFG   # revokes the account's sessions
signsrv admin add EMAIL      -config $CFG
signsrv client add NAME SCOPES -config $CFG # prints the key once
signsrv client revoke ID     -config $CFG
signsrv secrets init         -config $CFG   # writes the missing secrets, mode 0600
```

`admin passwd` stamps the credential epoch, so access tokens minted under the
old password stop working and the refresh chain is deleted. This is the action
to take when a token is stolen.

The JWT key (`var/jwt.ed25519.key`, mode 0600) is created on first start.
Replacing it drops every API session; the signing links are unaffected,
because a link is a token and not a JWT. Restart after replacing it.

The CA is `var/keystore/ca.key` and `ca.crt`, created on first start. To
replace it, move both files out of the keystore directory (keep them, offline),
then restart: the service creates a new CA on first start. Signatures made with
the old CA keep verifying — each signature carries its own certificate chain.
New signatures use the new CA. Tell the verifiers the new CA certificate.

## One secret that cannot be recovered

The keystore passphrase. A lost passphrase means the CA is dead. Every
signature made with it still verifies, because the certificate is embedded in
the document. Every future signature needs a new CA. There is no reset: the
key file is encrypted with the passphrase and the service has no copy of it
above the environment.

Keep the passphrase where you keep the key file, offline, and not in the
config file. `signsrv secrets init` will write it into the config file if you
let it; prefer `SIGNSRV_KEYSTORE_PASS` in the environment, or a
`LoadCredential` line in the systemd unit.
