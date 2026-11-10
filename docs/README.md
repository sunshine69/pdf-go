# Design documents

Read `00-overview.md` first. It contains the system design and the ordered list of
implementation steps. Each step has its own document in `steps/`, small on purpose,
ending with a **Signoff** block that the reviewer fills before the next step starts.

```
docs/
  00-overview.md         system overview, data model, security, API surface, step list
  01-layout.md           repo layout, dependencies, config
  02-database.md         schema, migrations, store layer
  03-auth.md             admin/machine JWT, middleware
  04-pdfsign.md          pdfsign adapter: certify, sign, verify, appearance
  05-envelopes.md        envelope API (create, send, list, get)
  06-tokens-email.md     signer tokens, expiry, email delivery
  07-consent.md          public consent endpoints, state machine (no PDF touched)
  08-spa.md              signer SPA
  09-admin-ui.md         admin SPA + admin endpoints
  10-batch-sign.md       signing batch, verification gates, delivery, receipt
  11-hardening.md        rate limits, audit, sweeps, TLS, deployment
  12-e2e.md              end-to-end test and runbook
  13-users-one-endpoint.md  users table, caller-minted tokens, chore endpoints
  14-drafter-notify.md   the drafter's notices: decline, undeliverable, notify_email
  build-and-test.md      how to build, and how to test each step by hand
  DEPLOY-DOCKER.md       the Docker image: build, first run, the process, settings,
                         state and backups, upgrade and rollback
  DEB-PACKAGE.md         the Debian package: how to build the .deb, what an install
                         sets up, first-boot modes, upgrade and purge semantics
  security-endpoint-audit.md
                       the endpoint audit: every probe and the answer, the three
                       findings and their fixes, the residual risks accepted
  tsa-roadmap.md         TSA: the policy, the options, the tests to write
  skills/prepare-and-dispatch-signing.md
                       short, runnable recipe: extract -> fill -> verify -> parties.json -> create --send -> report
```

Conventions used by every step doc:

- `Depends` — steps that must be signed off first.
- `Deliverables` — the files/packages that must exist when the step is done.
- `Design` — the decisions the implementer must follow.
- `Acceptance` — the checks that must pass, runnable as written.
- `Signoff` — empty checkboxes. The implementer does not tick them; the reviewer does.

Open decisions are listed in `00-overview.md` under **Open questions** with a
recommended default. Agents implement the default; the reviewer overrides by
annotating the step doc.
