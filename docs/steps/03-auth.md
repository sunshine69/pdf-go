# 03 — Authentication and authorization

Depends: 02.

## Deliverables

- `internal/signauth/{jwt.go, passwords.go, middleware.go, cookies.go, ratelimit.go}`
- `signsrv admin add/list/passwd`, `signsrv client add <name> <scopes>`
- Middleware wired in `cmd/signsrv/routes.go` for the two audiences
- `internal/signauth/*_test.go`

## Design

**Tokens.** Ed25519, signed by a key generated on first start into
`var/jwt.ed25519.key` (0600) with a `.pub` sibling. Compact JWS, hand-rolled on
`crypto/ed25519` + `encoding/base64` + JSON — no JWT dependency.

```
header {"alg":"EdDSA","kid":"<sha256(pub)[0:8]>","typ":"JWT"}
claims {"iss":"signsrv","sub":"<admin id|client id>","aud":"api","role":"admin|client",
        "scopes":["envelope:write","envelope:read","admin:read"],
        "iat":...,"exp":...,"jti":"<16 random b32>"}
```

Access token TTL 15 min. Refresh token: 256-bit random, stored hashed with
`sub`, single use, rotates on use, TTL 12 days. `jti` of access tokens is checked
against `revoked_jtis`; logout and password change revoke the current `jti` and
the refresh row.

**Password.** argon2id, `m=64MiB, t=3, p=2`, 16-byte salt, 32-byte key, encoded
`argon2id$v=19$m=65536,t=3,p=2$<b64 salt>$<b64 key>`. Constant-time compare.
Login is timing-equalised: a dummy hash is computed when the email is unknown.

**Middleware.**

```
requireAPI(scopes ...string)   // Authorization: Bearer, aud=api, scopes ⊆ claims
requireAdmin()                 // role=admin and aud=api
requireSigner()                // cookie signsession + token -> party context
```

Order for every request: rate limit -> auth -> scope -> handler. `requireSigner`
loads the party row into the context (`signflow.PartyFrom(ctx)`); handlers must
never accept a party id from the request body.

**Session cookie (signers).** Set by `POST /sign/{token}/claim`. Name
`signsrv_s`, value `<random 256-bit>` whose SHA-256 is stored in
`parties.session_hash`. Attributes:
`HttpOnly; Secure; SameSite=Strict; Path=/api/v1/sign/; Max-Age=<token expiry>`.
Cookie is bound to the party row only. A second claim for the same party replaces
`session_hash`, invalidating the previous session.

**Machine clients.** `signsrv client add api "envelope:write envelope:read"`
prints the key once, stores SHA-256. Key is presented as `Authorization: Bearer`
in the same shape as a JWT (`aud=api`, role `client`), minted by
`POST /api/v1/auth/token` that accepts `{"key":"..."}` and returns a 15-minute
access token. This keeps one verification path.

**Rate limiting.** In-memory sliding window keyed `(route, ip)`; default buckets
from the overview. `X-Forwarded-For` trusted only when `SIGNSRV_TRUST_PROXY=1`.

## Acceptance

```
go test ./internal/signauth
# must cover: valid/expired/tampered signature, wrong aud, missing scope,
# revoked jti, refresh single-use + rotation, argon2 round trip,
# timing-equalised unknown email, cookie flags, rate limit 429
signsrv admin add admin@example.org
curl -s -X POST localhost:8080/api/v1/auth/login -d '{"email":"admin@example.org","password":"..."}'
#   -> access + refresh tokens; then
curl -s -H "Authorization: Bearer $T" localhost:8080/api/v1/envelopes    # 200, []
curl -s localhost:8080/api/v1/envelopes                                    # 401
curl -s -H "Authorization: Bearer $T" localhost:8080/api/v1/admin/stats   # admin scope ok
# client token: create, mint, use, then revoke -> 401
```

## Signoff

- [ ] No JWT library; signature, exp, aud, jti revocation all enforced
- [ ] Admin token cannot be used as a signer session and vice versa
- [ ] Password storage argon2id with documented parameters; login timing equalised
- [ ] Refresh tokens single-use, hashed at rest, rotated
- [ ] Every endpoint has a scope requirement; default-deny for unknown routes
- Reviewer: ____________  Date: ________
