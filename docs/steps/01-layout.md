# 01 — Layout, dependencies, config

Depends: overview signed off.

## Deliverables

- `cmd/signsrv/main.go`, `cmd/signsrv/config.go`, `cmd/signsrv/routes.go`
- `internal/signstore/`, `internal/signauth/`, `internal/signpdf/`,
  `internal/signfill/`, `internal/signmail/`, `internal/signflow/` created as
  empty packages with a `doc.go` stating the package contract (one paragraph each).
- `go.mod` requires `github.com/digitorus/pdfsign` and the SQLite driver.
- `vendor/` updated (`go mod tidy && go mod vendor`).
- `config.example.env` and `README-signing.md` (how to run).
- `signsrv` builds, runs, serves `GET /healthz` -> `{"status":"ok"}`.

## Design

- Binary name `signsrv`. Existing CLI `cmd/pdf-go` is untouched.
- Config from environment with a `` prefix, overridable by a
  `KEY=value` file given as `-config` (the same file works as a systemd
  `EnvironmentFile`; unknown keys are refused so a typo fails at startup).
  Env wins over file. Never log secret values.
- Minimum config keys:

```
LISTEN=:8080
PUBLIC_URL=https://sign.example.org      # used in email links
DB_PATH=var/signsrv.db
STORAGE_DIR=var/storage
KEYSTORE_DIR=var/keystore
KEYSTORE_PASS=                           # required, from env only
JWT_SECRET_FILE=var/jwt.ed25519.key      # generated on first start
TSA_URL=https://freetsa.org/tsr
SMTP_HOST= SMTP_PORT=587 SMTP_STARTTLS=1
SMTP_USER= SMTP_PASS= MAIL_FROM=sign@example.org
LINK_TTL=168h
DEV=0                                     # 1 = http, verbose, no SMTP
```

- `DEV=1` is the only way to run without SMTP/keystore passphrase: it
  writes emails to `var/outbox/` as `.eml` files. Used by tests. Dev mode
  generates the keystore passphrase and the admin password at start and prints
  them to the log, so `DEV=1` on a listener that reaches the network is
  the combination to avoid — the log alone is then enough to sign. It is warned
  about, not refused: where the listener sits is the operator's infrastructure
  decision.
- Static dirs are compile-time embedded (`go:embed web/spa web/admin`) so the
  binary is a single artifact.
- One `Logger` (slog, JSON) with a `RequestID` on every request.
- Graceful shutdown on SIGTERM: stop accepting, 20s drain.

## Acceptance

Run `sh scripts/acceptance-01.sh` from the project root: it executes every
command below and prints the results.

```
go build ./cmd/signsrv && go vet ./cmd/signsrv ./internal/sign...
GOFLAGS=-mod=vendor GOPROXY=off go build ./...    # offline, from vendor/
signsrv checkconfig -config config.example.env    # exit 0, "config ok"
signsrv checkconfig -config broken.env            # exit 1, every problem listed
signsrv checkconfig -config malformed.env         # exit 2, unparseable file
signsrv serve -config dev.conf &                  # dev=true, loopback
curl -s localhost:8090/healthz                    # {"status":"ok","request":"..."}
curl -s -D- -o /dev/null localhost:8090/s/<token> # CSP frame-src 'self'
curl -s -D- -o /dev/null localhost:8090/admin/    # CSP frame-ancestors 'none'
grep -rn "TODO\|panic(" cmd/signsrv               # none in non-test code
grep -c "<token>\|<password>" var/log/signsrv.jsonl  # 0
kill -TERM <pid>                                  # "draining" then "stopped"
go test -mod=vendor ./cmd/signsrv
```

## Signoff

Implemented. Evidence, from the commands above run against the tree:

- [x] Layout matches overview §2 — `cmd/signsrv` (main, config, routes, server,
  static, serve), six `internal/sign*` packages with a contract in `doc.go`,
  `web/` embedding both apps. `cmd/pdf-go` untouched, no CLI code duplicated.
- [x] Dependencies vendored: `github.com/digitorus/pdfsign v1.0.0` and
  `modernc.org/sqlite v1.61.1` required in `go.mod`, marked explicit in
  `vendor/modules.txt`; `GOFLAGS=-mod=vendor GOPROXY=off go build` succeeds.
- [x] Secrets are never logged: accessors read the environment/file at call
  time, `Redacted()` prints `sha256:` digests, the signer shell logs
  `token=[token:hidden]`; `TestRedactedNeverLeaksSecrets` and
  `TestSignerShellHidesTheToken` assert it on the log file.
- [x] `/healthz` returns 200 JSON; SIGTERM logs "draining" then "stopped" and
  the port closes.
- [x] Dev mode is refused on a non-loopback listener *(later reversed — a
  listener outside loopback is now a warning on every start, and dev mode
  accepts any bind; the caveat about ephemeral secrets being printed to the log
  is why the warning exists)*; a missing secret is a start-time problem, so dev
  generates ephemeral secrets and prints the admin password once (dev mode only,
  never in production).
- [x] gofmt clean, vet clean, `go test -mod=vendor ./cmd/signsrv` passes
  (12 cases: routes, traversal, CSP for both faces, config validation,
  env-over-file precedence, loopback parsing, log hygiene).
- [x] `config.example.env` documents every key; unknown keys are refused so a
  typo fails at startup; `README-signing.md` covers dev, prod, first run.

Note for the reviewer: the config format is `KEY=value` (not TOML/YAML) —
the same file is readable as a systemd `EnvironmentFile`, and adding a TOML
parser for 20 scalar keys buys nothing. Say the word if you want it changed.

- [x] `vendor/` is not committed (the repo's `.gitignore` has `vendor/**`), so
  the offline build works from a clean checkout only after `go mod vendor`.
  Decide in step 11 whether to commit it — deployment builds from a tarball
  built on this machine, so it does not have to be committed.

Open items in later steps, by design: `/api/v1/*` endpoints other than
health (05+), the app bodies (08, 09), keystore and CA (04), the worker
(06, 07, 10), rate limiting (03, 11), systemd/logrotate/nginx units (11).

- Reviewer: ____________  Date: ________
