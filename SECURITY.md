# Secrets, in order of blast radius

The secret that signs a document is the signing key. Everything else is a step
toward it. This is the order to protect them, and the order the runbook assumes
when a machine is compromised.

1. **The keystore passphrase + `var/keystore/`.** The passphrase decrypts the
   CA private key. A person with the passphrase and the key file can sign as
   the service. Nothing in the service is above that: a signature made with the
   CA key is trusted by every verifier that has the CA certificate.
   - It is not stored in the config file. It is read from the environment
     (`KEYSTORE_PASS`) or from a systemd credential (`LoadCredential`).
   - `var/keystore/` is mode 0750, owned by the service user. The key file is
     mode 0600.
   - It cannot be recovered. A lost passphrase means the CA is dead: every
     signature made with it still verifies (the certificate is embedded in the
     document), and every future signature needs a new CA.
2. **`var/jwt.ed25519.key`.** The API signing key. A person with it can mint an
   admin access token, which is the admin console and every admin endpoint
   (create, cancel, remind, reissue, the audit zip). It cannot sign a document:
   the keystore passphrase is separate, and an access token is not carried into
   the signing path.
3. **The SMTP password.** It lets a person send mail as the service. The blast
   radius is a phishing channel: mail from the address the parties already
   trust.
4. **The database file (`var/signsrv.db`).** It holds the token hashes, the
   consent text, the signature text, the IP addresses, and the mail bodies. A
   person with the file can read every signing transaction. It cannot sign: the
   tokens are stored as SHA-256 hashes, so a copy of the database does not hand
   out signing links. It is the evidence, and the evidence is what an
   investigator reads.
5. **The admin password.** It mints an admin session. With the console you can
   create envelopes, cancel them, reissue links, and download the audit zip. In
   practice this is the same blast radius as the JWT key.

## Rotation

| secret | rotation | effect |
| --- | --- | --- |
| admin password | `signsrv admin passwd EMAIL` | immediate. The change stamps the credential epoch, so access tokens minted under the old password stop working and the refresh chain is deleted. Other accounts keep their sessions. |
| machine client key | `signsrv client add NAME SCOPES`, then `signsrv client revoke ID` of the old key | the new key takes effect immediately; the old key stops working on revoke |
| JWT key (`var/jwt.ed25519.key`) | replace the file, restart | every API session drops. The signing links are unaffected: a link is a token, not a JWT |
| CA (`var/keystore/ca.key` + `ca.crt`) | move the two files out of the keystore directory (keep them, offline), then restart: the service creates a new CA on first start | signatures made with the old CA keep verifying: each signature carries its own certificate chain. New signatures use the new CA. Tell the verifiers the new CA certificate. |

## Non-secrets

The link token is not a secret in the sense the list above means. It is bearer
capability: a person who has the URL can sign. So the rules are that it is not
logged, not stored in plaintext (only its hash is stored), not sent through a
third-party relay, and it expires. **Not logged** is a rule with two halves, and
the second one is the field name: a log point that carries a token's hash names
the field `token_sha256`, never `token`, because a name is what a reader —
human or shipper — indexes, and `token=<64 hex>` reads like a credential.
A path is logged through `redactPath` and nothing else, including the
"route not found" record, because a verb the mux does not route lands there and
an unrouted signing path is a raw link. The rule and its history are in
[docs/security-endpoint-audit.md](docs/security-endpoint-audit.md). It appears in the URL of the signing page,
so it appears in the party's browser history, in any proxy log between the party
and the service, and in the party's mail client. The one-year HSTS policy in
`deploy/Caddyfile` is part of the answer, and `Referrer-Policy: no-referrer`
keeps the page from handing the token to a third party.

The consent text and the typed signature text are evidence, not secrets. They
are logged, because they are what the party chose. They are stored in the
database, in the row an investigator reads. They are not hidden from the logs,
and the redaction test does not require them to be.

## The config report

`signsrv checkconfig` prints the effective configuration with every secret
replaced by a 12-character SHA-256 digest. This is the line to paste into an
issue, a chat, or a ticket: it lets a reviewer see what is set without learning
what it is.

```
keystore_pass=sha256:83cafdaf6ac2
admin_password=sha256:6a3d6e8f2bd2
smtp_pass=sha256:e99d0f3f0345
```

The same rule applies to the log. The config loader exposes secrets through
accessor functions, not through struct fields, so `slog` cannot walk them. The
access log reduces the path, the cookie header, and the authorization header
before it writes a line:

```
"path":"/api/v1/sign/[token]/claim","cookies":"signsrv_s","auth":"Bearer [credential]"
```

The redaction is asserted by `cmd/signsrv/redaction_test.go`, which runs a real
claim, consent and sign round trip against a log-capture handler and fails if
any captured line contains the link token, the session cookie value, the bearer
token, the keystore passphrase, the SMTP password, or the admin password.

## Reporting

Report a security issue to the address in the project README, not to the public
issue tracker. A signing service is a place where a bug produces forged
signatures; the report is a private channel.
