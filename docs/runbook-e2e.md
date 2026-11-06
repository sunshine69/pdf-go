# Acceptance run runbook

How to run the end-to-end test, what it proves, and what to do when it fails.

The run is `e2e/run.sh`. It builds the binaries from the current tree, starts
the real service against a real SQLite database, invites parties, drives the
real signing app in a real browser, signs, delivers, and then checks the
result against the rules the service claims to hold. Nothing is stubbed except
the TSA (a local mock, because a public TSA cannot be a test dependency) and
SMTP (the service writes `.eml` files to an outbox directory).

## Running it

```
e2e/run.sh
```

One command, about 20 seconds. It needs Go, and for the browser phase node
plus a Chrome; `playwright-core` is installed into `/tmp/pw` on first use.

```
== browser signing
   browser transcript:
     ana@e2e.test | claim-ok | Bob Countersign
     ...
   ok
...
failures: 0   duration: 19.5s
acceptance run passed. Evidence: /tmp/signsrv-e2eXXXX/reports
```

The file is behind the build tag `e2e`, so `go test ./...` never compiles it.
The run is a program, not a test: it drives processes, and it needs to keep
going after the first failure so one broken phase does not hide the rest.

### Options

| Variable | Effect |
| --- | --- |
| `E2E_WORK=/tmp/myrun` | Keep the work directory here. By default a fresh `mktemp -d`; a run always starts from an empty tree. |
| `E2E_SKIP_BROWSER=1` | Stop the run after `send + outbox`. The phases past it all need the consents the browser produces, so there is nothing to check without a browser. |
| `CHROME=/path/to/chrome` | Which browser to drive. Defaults to the first of `google-chrome`, `chromium`, `chromium-browser`. |
| `E2E_NODE_MODULES=/tmp/pw/node_modules` | Where `playwright-core` lives. |
| `NODE=...`, `GO=...` | Which binaries to invoke. |

Pass phase names as arguments to run a subset, and `-list` to see them:

```
e2e/run.sh -list
e2e/run.sh "audit chain"
```

## What each phase proves

| Phase | Proves |
| --- | --- |
| build | The tree compiles, and the binaries exist. |
| mock tsa | A RFC 3161 responder is up on a local port, issuing SHA-256 timestamps. |
| config | A config file is written whose `tsa_url` points at the mock. |
| start service | `signsrv serve` answers on its listener, and the SPA is served. |
| admin login | The admin can log in and get a scoped token. |
| client key | An API client is registered, with its keypair. |
| cli create | `pdf-go envelope create` fills the template, certifies the result, and the envelope is `ready`. |
| send + outbox | `pdf-go envelope send` queues the invites; the outbox holds one `.eml` per party, each with a live link. |
| browser signing | Two real browsers claim by email, see the document, type a signature, and consent. The envelope settles. This is the phase that catches anything the SPA and the API disagree about. |
| cli watch | `pdf-go envelope get <id> --watch` reaches `delivered` on its own, which means the batch worker signed it without anyone restarting the service. |
| cli report | `pdf-go envelope report` writes a verification report: every signer present, every signature timestamped. |
| audit chain | `audit-write` writes the events, `audit-verify` accepts them, and a tampered copy is rejected — the verifier fails when it is supposed to. |
| artefacts | Copies every revision into `out/`, and verifies the PDF **attached to the delivery email** offline: its SHA-256 is the one on the envelope, and `checkpdf` accepts it with the TSA root. |
| rate limit | A burst of requests from one address is met with `429`. |
| log redaction | The log never contains a password, an authorization header, a link token, or a key. |
| graceful stop | `SIGTERM` exits `0`, with the queues left consistent. |

## Reading the evidence

Every phase writes what it saw to `$E2E_WORK/reports/<phase>.txt`, and the
transcript of the browser phase is printed to the console line by line.
`$E2E_WORK/out/` holds the document at every revision: template, filled,
certified, each consent stamp, and the signed file.

To look at a signed document by hand:

```
cd $E2E_WORK
./signsrv checkpdf out/signed.pdf -config e2e.env -tsa <tsa-url>
```

## When it fails

The run reports every failure it finds, then exits non-zero. Start with the
console line: it names the phase and the specific rule, e.g.

```
   - the PDF attached to the delivery mail is da858455015a, the envelope says
     the current document is c250e21e2982
```

Then read the phase's evidence file, which holds the command output verbatim.

The failures worth knowing the meaning of:

- **`browser transcript shows an error message`** — the page rendered a
  problem. The text is the server's own problem `detail`, so the message tells
  you which rule the flow broke (`stale document`, `already claimed`, ...).
- **`--watch` never reaches `delivered`** — the batch queue is not being
  drained. The service signs in the background worker; if the queue is empty
  of work, consents did not all land, and the previous phase is the one to
  read.
- **audit chain break** — an audit line does not match the events table. The
  audit file is the evidence, the database is the source. Find which one moved.
- **`checkpdf` fails on the attached PDF** — the document that left the
  service is not the document the service says it signed. Treat this as the
  most serious failure in the run.

A phase that fails leaves the run going, so a single red line does not hide
the phases after it. Fix the earliest phase first: later phases build on it,
and a failure there is usually the only real one.
