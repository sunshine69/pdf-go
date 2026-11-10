# Debian package

`signsrv` ships as a `.deb` for Ubuntu/Debian (amd64). Installing it does the whole
first-time setup: service account, config, directories, systemd unit, enable, start.

## Build it

From the repo root:

```sh
packaging/deb/build-deb.sh                # writes dist/signsrv_<version>_amd64.deb
packaging/deb/build-deb.sh /some/out/dir  # or choose the output directory
```

The script cross-compiles a static linux/amd64 binary (`CGO_ENABLED=0`), stages the
payload, substitutes `Installed-Size` into `debian/control`, normalises every file mode
so the result does not depend on the builder's umask, and packs it with `dpkg-deb`.

Needs only `go` and `dpkg-deb`. debhelper is **not** required and not used — the
package is one binary, one helper script, one unit and one config drop-in, so
`debian/control` spells its dependencies out by hand instead of relying on
`${misc:Depends}` substitution.

Override the version when cutting a release:

```sh
SIGNPKG_VERSION=0.1.0-1 packaging/deb/build-deb.sh
```

Inspect the result without installing it:

```sh
dpkg-deb -I dist/signsrv_0.0.1-1_amd64.deb     # control metadata + maintainer scripts
dpkg-deb -c dist/signsrv_0.0.1-1_amd64.deb     # file list and modes
dpkg-deb -e dist/signsrv_0.0.1-1_amd64.deb /tmp/x && less /tmp/x/postinst
```

## Install it

```sh
apt install ./dist/signsrv_0.0.1-1_amd64.deb
```

Use `apt install ./<path>` rather than `dpkg -i`: apt resolves the `Depends`
(`adduser`, `init-system-helpers`) and installs them in the same transaction.

A password prompt, then the service is running. Nothing else to do for local mode.

```
Enter passphrase for the signing CA key:
  ...
Installed signsrv in local mode: invitations are written to
  /var/lib/signsrv/outbox instead of being mailed, and the CA is created for this host.
  sign in at https://your.host/admin/   ·   health: curl -s localhost:8080/healthz
```

### What lands on the system

| Path | What |
| --- | --- |
| `/usr/bin/signsrv` | the server |
| `/usr/lib/signsrv/signsrv-{adduser,firstboot}.sh` | setup helpers, both idempotent |
| `/lib/systemd/system/signsrv.service` | unit, hardened, `StateDirectory=signsrv` |
| `/etc/signsrv/signsrv.env` | config, 0640 `root:signsrv` so the service can read it |
| `/etc/signsrv/secrets.env` | `SIGNSRV_KEYSTORE_PASS`, 0600 `root:root` |
| `/var/lib/signsrv/` | `signsrv:signsrv` 0750 — keystore, db, documents, outbox |
| `/etc/logrotate.d/signsrv` | ships with the `logrotate` recommendation |
| `/usr/share/doc/signsrv/` | README, runbook, security notes, this document |

### Unattended install

The passphrase is normally an interactive prompt. For preseeding or a non-interactive
provisioner, supply it instead — and note that a value in the process environment is
not a secret, so this is for CI, not for a shared machine:

```sh
echo 'SIGNSRV_KEYSTORE_PASS=correct horse' | \
  env SIGNSRV_SECRETS_FILE=- SIGNSRV_KEYSTORE_PASS=correct horse \
      DEBIAN_FRONTEND=noninteractive \
      apt install -y ./dist/signsrv_0.0.1-1_amd64.deb
```

## First-boot behaviour

`signsrv-firstboot.sh` runs from `postinst` and again from the unit's `ExecStartPre` on
every start. It is idempotent and safe to run by hand as root:

```sh
dpkg-reconfigure signsrv
/usr/lib/signsrv/signsrv-firstboot.sh
```

It writes the config only for keys the operator has not already set, so edits to
`/etc/signsrv/signsrv.env` survive every upgrade, reinstall and `dpkg-reconfigure`.

Two modes, chosen by `dev`:

- **`dev=true`, the default.** Invitations are written to `/var/lib/signsrv/outbox`
  instead of being mailed; the CA is created for this host. Usable immediately.
- **`dev=false`.** Mail is sent through a real relay. The unit `EnvironmentFile`s the
  config, so `dev=true` written by the package would override whatever the operator set
  and silently fail to mail — `firstboot` therefore removes `dev` from the file in relay
  mode, and leaves the absence of `dev` to mean "relay mode", which is also the binary's
  own default.

Switching to a relay:

```sh
sed -i 's/^dev=.*/dev=false/' /etc/signsrv/signsrv.env   # or delete the line
# set public_url, smtp_host, smtp_port, smtp_username, mail_from
echo 'SIGNSRV_SMTP_PASS=...' >> /etc/signsrv/secrets.env
systemctl restart signsrv
```

`SIGNSRV_SMTP_PASS` is the one supported setting that has no plain
`signsrv.env` counterpart: `EnvironmentFile` is read before the service's own config,
so a key set there can never be lowered by the config file, and the one value that
must be secret stays secret by construction.

## Listening address, TLS, the admin plane

`listen` defaults to `127.0.0.1:8080`. A public signing service needs a TLS
terminating proxy, so `public_url` is `https://…` while `listen` stays loopback.

There is no separate admin listener: `/admin/` is served on the same port as the
public pages, so the default loopback `listen` is what keeps the admin plane off the
network. Widening `listen` exposes both at once, and the service serves plain HTTP —
the startup validation warns about exactly that, because party tokens and the admin
password would cross the network in the clear. Put a TLS proxy in front, or restrict
access with network policy, before binding anywhere but loopback.

## First admin account

```sh
signsrv -config /etc/signsrv/signsrv.env admin add you@your.host
signsrv -config /etc/signsrv/signsrv.env admin list
signsrv -config /etc/signsrv/signsrv.env admin passwd you@your.host   # rotates the bcrypt cost too
```

The password is read from the terminal, never from argv, so it does not appear in
`ps` or in shell history.

## Upgrades and removal

- **Upgrade** stops the service before replacing the binary (`prerm`), runs migrations,
  restarts it, and leaves `listen` and `admin_binds` exactly as the operator set them.
- An operator who ran `systemctl disable signsrv` is **not** re-enabled by the next
  upgrade — `postinst` consults `deb-systemd-helper was-enabled` before enabling.
- **`purge` deliberately keeps `/var/lib/signsrv`.** It holds the CA private key
  envelope, every signed document, and the append-only audit chain. Documents signed
  under this CA remain signed after the package is gone, and the chain that proves them
  must not depend on a package transaction. `postrm` prints the consequence: the
  passphrase went away with `/etc/signsrv/secrets.env`, and without it the CA cannot be
  opened.
- Deleting the evidence is an explicit act: `rm -rf /var/lib/signsrv`.

If a reinstall reports:

```
signsrv-firstboot: /var/lib/signsrv/keystore/ca.key exists, but its passphrase is not in /etc/signsrv/secrets.env.
```

put the original passphrase back. It refuses to generate a new one because that would
brick every previously issued credential and certificate; if the passphrase is truly
gone and you accept the consequences, `rm -rf /var/lib/signsrv` and reinstall.

## Testing the package

```sh
packaging/deb/test-apt-install.sh          # needs docker
```

Starts a clean Ubuntu with systemd as PID 1, installs with `apt install ./…`, and
asserts the package's whole promise — dependencies resolve, the account is created, the
config is written and readable by the service user but not world-readable, the keystore
is created with a passphrase read from a tty and never passed as an argument, the unit's
sandboxing works, the service is enabled and answering, an operator's config edits
survive an upgrade, migrations run, and `purge` keeps the evidence.

Two container-only details it accounts for, both of which look like package bugs until
you name them:

- `/usr/sbin/policy-rc.d` answering `101` suppresses service starts. That is the Debian
  convention for "do not start services in this environment", and `deb-systemd-invoke`
  honours it. The test removes the file and re-runs `dpkg --configure` to exercise the
  real-host path.
- `deb-systemd-helper` refuses to run outside `dpkg` unless
  `DPKG_MAINTSCRIPT_PACKAGE` is exported; the test sets it only to read state back.
