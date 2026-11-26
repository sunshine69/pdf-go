# Documentation

**Start with [`QUICK-START.md`](QUICK-START.md)** — the map of the codebase: what
each package does, how a document flows through the service, the auth model,
where to make a change, and the pitfalls that have already cost someone time. It
is written from the current code.

Below, the reference material. The docs are split into **current** (describes
what the software does today) and **historical** (how it was designed and signed
off, kept for the reasoning, not authoritative on behaviour).

## Current

| Doc | For |
| --- | --- |
| [`QUICK-START.md`](QUICK-START.md) | orientation: architecture, packages, flow, where to change X |
| [`skills/prepare-and-dispatch-signing.md`](skills/prepare-and-dispatch-signing.md) | the fill-and-dispatch procedure, API-first. The runnable recipe an agent should follow. |
| [`external-client-procedures.md`](external-client-procedures.md) | what a client **outside** the server does: the endpoint, a machine key, fill, create, review gate, send, confirm. No shell access to the server assumed. |
| [`CONFIG.md`](CONFIG.md) | every setting: file key, `*` env var, default, and what refuses to start without it |
| [`DEPLOY-DOCKER.md`](DEPLOY-DOCKER.md) | the Docker image: build, first run, process, settings, state and backups, upgrade and rollback |
| [`DEB-PACKAGE.md`](DEB-PACKAGE.md) | the Debian package: building it, what an install sets up, first-boot modes, upgrade and purge semantics |
| [`security-endpoint-audit.md`](security-endpoint-audit.md) | the endpoint audit: every probe and its answer, the findings and fixes, the residual risks accepted |
| [`tsa-roadmap.md`](tsa-roadmap.md) | timestamps: the policy, the options, the tests still to write |

At the repository root:

| Doc | For |
| --- | --- |
| `../README.md` | what `pdf-go` and `signsrv` are |
| `../README-signing.md` | running the service end to end |
| `../runbook.md` | operational procedures, as commands with expected output |
| `../SECURITY.md` | the secrets, ranked by blast radius |
| `../Validation-Guide.md` | recipient-facing: "is this PDF genuine", no account needed |
| `../Validation-Guide-Technician.md` | the same verification, in full technical detail |

The two validation guides are different audiences, not duplicates: the short one
is for someone who just received a document; the technician one covers the
cryptographic detail and `scripts/verify_pdf.py`.

## Historical — build-time design and signoff

These are the original step-by-step design documents. They explain *why the code
is this way*, which is genuinely useful, but they predate several changes and
must not be read as a description of current behaviour. Where they disagree with
the code or with `QUICK-START.md`, the code wins.

| Doc | For |
| --- | --- |
| `00-overview.md` | the original system design, data model and step list |
| `steps/01-layout.md` … `steps/14-drafter-notify.md` | one document per implementation step, each ending in a reviewer's **Signoff** block |
| `build-and-test.md` | how to build, and how each step was tested by hand |
| `runbook-e2e.md` | the acceptance run: how to run the end-to-end test and read a failure |

Conventions used by every step doc:

- `Depends` — steps that must be signed off first.
- `Deliverables` — the files/packages that must exist when the step is done.
- `Design` — the decisions the implementer must follow.
- `Acceptance` — the checks that must pass, runnable as written.
- `Signoff` — empty checkboxes. The implementer does not tick them; the reviewer does.

The `scripts/acceptance-NN.sh` harnesses belong to these docs. Only the steps
whose script still exists are runnable today (01, 04, 05); the rest of the daily
verification is `go test ./...`, `e2e/run.sh`, and the skill document.
