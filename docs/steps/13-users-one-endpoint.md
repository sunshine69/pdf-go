# Step 13 — One account table, one endpoint, CLI-side JWT

Status: **implemented** (migration v5, the HMAC verifier, the chore routes, the CLI
verbs). §4.4 and §5 are the shape that was built; §7 is the acceptance list, and
`acceptance-13-results.txt` is the run of it.

What landed, in one paragraph: the `users` table (v5) carries `username`, an
argon2id `password` and a base64url `jwt_secret`, with `scopes` and `revoked_at`.
The API resolves a bearer token in this order — EdDSA access token, then HS256
against the `users` row named by `sub` — and for the second kind it takes the
scopes and the role from the **row**, re-read per request, and refuses every
`admin:*` route by kind. `signsrv user add|list|rotate|revoke` is the bootstrap
and runs where the database is; `pdf-go admin <verb>` is the same question over
the API, for a machine that has no shell on the server. The CLI mints its own
token from `SIGNSRV_JWT_SECRET` and sends no secret.

## 1. What is being asked (restated so we agree)

- One **users** table. Columns are plain strings: `username`, `password`, `jwt_secret`.
- `jwt_secret` is a **shared, known string**: the CLI is given the same secret and
  **mints its own JWT locally** (`sub` = the username), then sends it as
  `Authorization: Bearer <jwt>`. No login round-trip for machine callers.
- `username` + `password` stay in the table for the **web portal login**, which does
  not exist yet. Future, not this step.
- One consistent API endpoint for everything, so the server can live on one machine
  and the CLI on another.

## 2. What already exists (do not rebuild it)

| Piece | Where |
|---|---|
| 45 routes, one prefix `/api/v1`, `Content-Type: application/problem+json` | `cmd/signsrv/routes.go` |
| Bearer + scope guard, `aud="api"` | `RequireAPI` in `internal/signauth/middleware.go:103` |
| Compact JWS: `{"alg":"EdDSA","kid":…}`, claims `iss sub aud role scopes iat exp jti` | `internal/signauth/jwt.go` |
| Scope vocabulary | `admin:read`, `envelope:read`, `envelope:write` (`middleware.go:175`) |
| Client rows with scopes | `clients(id, name, key_hash, scopes, created_at, revoked_at)`, `schema.sql:16` |
| Admin rows with **argon2id** password | `admins(id, email, password_hash, role, epoch, …)`, `schema.sql:7` |
| Revocation: `revoked_jtis(jti, expires_at)` checked every request | `middleware.go:121` |
| Rate limit, login-denied uniformity, timing-attack dummy hash | `ratelimit.go`, `sessions.go:35` |
| CLI speaks HTTP only — never opens the database | `cmd/pdf-go/envelope.go` (`--server`, `SIGNSRV_TOKEN`) |
| Client create/revoke **already an API** | `POST /api/v1/admin/clients`, `DELETE /api/v1/admin/clients/{id}` (`admin.go:603`) |

So "one consistent endpoint" is already true for documents. The local-only verbs are
chores: `migrate`, `sweep`, `dbstatus`, `audit-verify`, `audit-write`, `client add`,
`admin add`, `checkconfig`, `secrets`, `mail-test`, `sign-selftest`, `checkpdf`, `worker`.

## 3. The honest cost estimate

| Work | New/changed | Effort |
|---|---|---|
| `users` table + store methods + argon2id password | migration v5, ~120 lines | ½ day |
| `POST /api/v1/auth/login` for username (replaces email login) | ~80 lines | ½ day |
| **`alg: HS256` verify path + shared secret in the users row** | ~90 lines + tests | 1 day |
| Chores as routes: dbstatus, sweep, schema, audit/verify, audit/write, config-check, mail-test | 7 handlers, ~250 lines | 1 day |
| `pdf-go admin <chore>` verb group + reuse of the HTTP client | ~150 lines | ½ day |
| Tests for every new route (the repo's acceptance style: runnable as written) | ~350 lines | 1 day |
| **Total** | ~1,000 lines | **≈ 4 days** |

Nothing structural breaks: the envelope/partparty/consent model is untouched.

## 4. Three real problems with `jwt_secret` as a shared string — and the fix that keeps your shape

**4.1 Anyone holding the string is anyone.**
`sub` is a claim the *client* writes. With one shared secret, the dispatch box can put
`"sub": "admin:1"`, `"role": "admin"` in its own token and pass `RequireAdmin`
(`jwt.go:98`: an admin-role token has every scope). The secret is then the whole
system. Today a `clients.key_hash` lookup is what decides scopes; the client cannot
invent them.

**4.2 No revocation, because there is nothing to look up.**
A JWT the server never minted has no row. `signsrv client revoke <id>` stops today's
token because the row is gone. A secret-derived token keeps working until `exp`, and a
leaked secret mints tokens forever. `revoked_jtis` only helps tokens the server issued.

**4.3 Algorithm confusion.**
The verifier today pins `EdDSA` (`jwt.go:23`). Accepting `HS256` for the same routes
means the verifier must decide by `alg` — the classic break where a token signed with
the **public** key passes as HMAC. Any HS256 support must be a **separate verifier,
separate routes, never one `VerifyAccess` that switches on `alg`.**

**4.4 The fix: shared secret, per-user rows, scopes from the row, and no admin role.**

```
users(
  id INTEGER PRIMARY KEY,
  username   TEXT NOT NULL UNIQUE,          -- login name, used as JWT "sub"
  password   TEXT NOT NULL,                 -- argon2id encoded string (see 4.5)
  jwt_secret TEXT NOT NULL,                 -- 256-bit random, base64url. NOT shared between users
  scopes     TEXT NOT NULL DEFAULT 'envelope:read,envelope:write',
  role       TEXT NOT NULL DEFAULT 'user',  -- 'user' cannot reach admin:* routes
  created_at TEXT NOT NULL,
  last_login TEXT,
  revoked_at TEXT
)
```

The CLI holds **one** user's `jwt_secret`, mints `HS256` locally with
`iss=signsrv sub=<username> aud=api role=user scopes=<the ones you granted> exp=+15m jti=<random>`,
and calls one endpoint. That is exactly the convenience you asked for: no login call,
no per-box key ceremony, secret lives in the CLI's environment, server is remote.
What changes from your wording is only **one secret per user instead of one for all** —
so revoking one user is an UPDATE on one row, and one box's secret cannot speak as
another user.

**4.5 Passwords.** "Pure string" is fine for `jwt_secret` (a machine secret, read by
the server to verify). Not for `password`: the column stores the argon2id string
argon2id already used for admins (`password.go`, `m=65536,t=3,p=2`). A plaintext
password column would put every operator's login into every database copy, backup and
`sqlite3` session — the same rule `clients` follows (key hash, never key).

**4.6 `alg` separation.** Add a second verifier: `NewHMACVerifier(secretLookup)` used
only by routes that opt in. `VerifyAccess` (EdDSA) stays as is. Both produce the same
`Claims` struct, so every scope check, log line and handler is unchanged. Admin routes
keep EdDSA-only, so a leaked user secret can never reach them.

## 5. The chore endpoints (all `admin:read`, JSON, same problem+json shape)

```
GET    /api/v1/admin/dbstatus        -> today's dbstatusCmd output as JSON
POST   /api/v1/admin/sweep           -> sweepCmd result: envelopes_expired, mail_requeued…
GET    /api/v1/admin/schema          -> {version: 4, expected: 5}
POST   /api/v1/admin/schema/apply    -> run Migrate (only this one writes schema)
POST   /api/v1/admin/audit/verify    -> {events: N, chain: "valid"} | 409 with day+line
POST   /api/v1/admin/audit/write     -> {day, appended: N}
GET    /api/v1/admin/config-check    -> today's checkconfig problems as a list
POST   /api/v1/admin/mail-test       -> address probe + test send
```

Left local on purpose: `secrets`, `sign-selftest`, `checkpdf` (they generate or probe
keys on the box that holds them), `worker` (it needs the DB file, not an API), and the
**first** `admin add` (nothing is authenticated yet — bootstrap).

## 6. Migration plan (no downtime, nothing breaks mid-flight)

1. **v5 migration** (`migrations.go` has `{version: 1..4}`; add `{version: 5}`):
   create `users`; copy each `admins` row into `users` with `username = email` and the
   same `password` hash; copy each live `clients` row into `users` with
   `username = name`, `password = '!'` (never valid — argon2 strings start `$argon2`),
   `jwt_secret` freshly random, `scopes` copied, `role = 'user'`.
   Keep `admins` and `clients` readable: nothing drops in v5.
2. Ship the **HS256 verifier + `Bearer` resolution order**: try EdDSA (existing
   tokens), then HS256 with `sub -> users.username -> jwt_secret`, and re-check
   `revoked_at IS NULL` and the row's `scopes` on every request. Existing tokens and
   existing CLI runs are unaffected.
3. Ship the chore routes. Update `README-signing.md`, `runbook.md`, `docs/skills/*`
   to call them; keep the local verbs documented as bootstrap.
4. Add `pdf-go admin <verb>` so one `SIGNSRV_URL` + one user's secret drives both
   machines. Add `SIGNSRV_JWT_SECRET` (CLI mints) alongside `SIGNSRV_TOKEN` (server mints).
5. **v6 (later, separate step)** drops `clients` once every caller has a `users` row,
   and `admins` once the portal logs in through `users`. Deletion is its own step so a
   bad migration can be rolled back without touching v5.

## 7. Acceptance (what "done" means, runnable as written)

```sh
# 1. one username works for both doors
SIGNSRV_JWT_SECRET=$SECRET pdf-go admin dbstatus --server https://…   # 200, JSON
# 2. a token minted with user A's secret cannot read user B's client row
# 3. a token whose users row has revoked_at set is refused 401 token_revoked on the next call
# 4. alg=HS256 minted against an EdDSA public key is refused 401
# 5. alg=EdDSA is refused on a route that opted into the HMAC verifier
# 6. sub=admin:1 in a user-minted token does NOT reach any admin:* route
# 7. expired exp (30s skew tolerated) -> 401 token_expired; past that -> 401
# 8. GET /api/v1/admin/dbstatus via API == signsrv dbstatus on the same box (same numbers)
# 9. sweep via API returns the same counts as signsrv sweep on an idle queue
# 10. sqlite3: select password from users -> starts with $argon2id$ (never plaintext)
```

## 8. Recommendation

Adopt the **endpoint-for-chores** part as designed (that part is unambiguously better
and matches the code you already have). Adopt the **CLI-mints-its-own-JWT** part only
in the §4.4 shape: per-user secret, scopes and role read from the row on every request,
separate HS256 verifier, admin routes excluded, argon2 passwords, `users` as the one
table the portal will log into later. That keeps the convenience you want and costs no
security property.

## 9. What shipped, and the operator's one line

The chore verbs run on a desk machine, with one account's secret in an
environment file and nothing else:

```ini
# /etc/systemd/system/signsrv-chores.service
Environment=SIGNSRV_URL=https://srv.example
Environment=SIGNSRV_USERNAME=chores
EnvironmentFile=/etc/signsrv/chores.env     # SIGNSRV_JWT_SECRET=…, mode 0400
ExecStart=/usr/local/bin/pdf-go admin dbstatus
```

The one line that answers "is this deployment healthy", on a machine with no
shell access to the server:

```sh
SIGNSRV_URL=https://srv.example SIGNSRV_USERNAME=chores \
SIGNSRV_JWT_SECRET=$(cat /etc/signsrv/chores.secret) pdf-go admin dbstatus
```

Deliberate properties, each with a test behind it:

- the secret is a **shared string and never travels**: the CLI signs, the service
  verifies against the row. There is no token endpoint to reach at all;
- the scopes and the role come from the **row**, re-read per request. A token
  carrying `admin:read` in its payload gets `insufficient_scope` on every
  `admin:*` route, and `signsrv user add` refuses to write that scope in the
  first place, because a scopes column that cannot be honoured is a lie;
- `user rotate` and `admin revoke-user` take effect at the next request, not at
  token expiry. The row survives, stamped `revoked_at`, so the audit trail of
  what its secret signed stays verifiable and `admin dbstatus` counts it under
  `users_revoked` — "revoked" stays tellable apart from "never existed";
- `SIGNSRV_TOKEN` holds a client key (`key_…`, exchanged at the token endpoint)
  **or** an already-minted access token (`a.b.c`, sent as it is). A script that
  mints once spends one request per verb, which is what keeps a chore run inside
  the token endpoint's rate bucket;
- no credential is read from argv, ever. `SIGNSRV_URL`, `SIGNSRV_TOKEN`,
  `SIGNSRV_USERNAME`, `SIGNSRV_JWT_SECRET` and `SIGNSRV_USER_PASSWORD` are environment
  names only, and the run's log-redaction phase proves none of them reaches the
  journal.
