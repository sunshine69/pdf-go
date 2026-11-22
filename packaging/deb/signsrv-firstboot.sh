#!/bin/sh
# packaging/deb/signsrv-firstboot.sh — bring a freshly installed signsrv to a state
# where the service can start.
#
# Called from postinst, and again by the unit's ExecStartPre on every start. It is
# idempotent and may be run by hand at any time:
#
# Run as root — dpkg-reconfigure and any write under /etc or /var/lib need the root
# uid. Commands are written for a root shell and are deliberately not prefixed with a
# privilege-escalation wrapper: this package has no such dependency, and depending on
# how the machine is administered the operator may already be root, may be in su, or
# may have no such tool installed at all.
#
#   dpkg-reconfigure signsrv
#   /usr/lib/signsrv/signsrv-firstboot.sh
#
# Idempotent has a specific meaning here, and it is not merely "does not mind running
# twice". The one value that must never change silently is the keystore passphrase:
# the CA private key is encrypted with it, and every signature already issued stops
# verifying the moment it is replaced. So a passphrase is generated once, and if a
# keystore is found whose passphrase is gone, this script REFUSES and says what to do,
# rather than inventing one that would orphan the CA and report success.
#
# Everything else self-heals. Missing directories, a missing database schema, a lost
# admin password: repaired on the next start. That matters because ExecStartPre runs
# before every start, so an operator who damages /var/lib/signsrv gets a repair rather
# than a crash loop.
#
# Environment it reads, all optional, used to preseed an unattended install:
#
#   SIGNSETUP_ROOT          prefix to write under, default "/". For testing this
#                           script against a fake root; a real install leaves it unset.
#   SIGNSETUP_STATE         state directory, default /var/lib/signsrv
#   SIGNSETUP_USER          service account, default signsrv
#   SIGNSETUP_BIN           signsrv binary, default /usr/bin/signsrv
#   SIGNSETUP_PUBLIC_URL    https URL the signing links point at
#   SIGNSETUP_MAIL_FROM     envelope sender, e.g. signer@example.org
#   SIGNSETUP_SMTP_HOST     mail relay host
#   SIGNSETUP_SMTP_PORT     relay port, default 587
#   SIGNSETUP_SMTP_STARTTLS true/false, default true
#   SIGNSETUP_SMTP_USER     relay username
#   SIGNSETUP_SMTP_PASS     relay password (written to the 0600 file, never the other)
#   SIGNSETUP_ADMIN_EMAIL   admin account to create at first start
#   SIGNSETUP_ADMIN_PASSWORD password for that account (default: generated)
#   SIGNSETUP_LISTEN        listener, default 127.0.0.1:8080
#   SIGNSETUP_TRUST_PROXY   true when a reverse proxy on this host sets X-Forwarded-*
#   SIGNSETUP_TSA_URL       RFC 3161 timestamp authority
#
# Generated secrets are never printed.

set -eu

PREFIX=${SIGNSETUP_ROOT:-/}
STATE=${SIGNSETUP_STATE:-/var/lib/signsrv}
USER_NAME=${SIGNSETUP_USER:-signsrv}
BIN=${SIGNSETUP_BIN:-/usr/bin/signsrv}

# PREFIX is what gets stuck in front of absolute paths to relocate them under a fake
# root. It is "" for a real install, or "/some/prefix" with no trailing slash for a
# test tree. The default arrives as "/": joining that literally gives "//etc/signsrv",
# which the kernel accepts but which then shows up in every message this script prints
# and in the config file, where it reads as a bug and makes an operator diff a real
# install against a test one.
PREFIX=$(printf '%s' "$PREFIX" | sed -E 's:/*$::')

ETC="${PREFIX}/etc/signsrv"
CONF="$ETC/signsrv.env"
SECRETS="$ETC/secrets.env"

# A real install has an empty PREFIX, and then the paths written into the config are
# exactly the paths the service reads at runtime (/var/lib/signsrv/...).
#
# When SIGNSETUP_ROOT names a fake root, the prefix IS written into the config, so the
# relocated tree is self-consistent: the config, the database and the keystore all agree
# on where things live, and a service started against a fake-root config finds its own
# files rather than the real /var/lib/signsrv. Anything copied out of a fake-root config
# and used on a real host would carry the prefix and have to be edited — that is a
# property of testing a tree at a prefix, not something a production install sees.
STATE_PATH="${PREFIX}${STATE}"

note() { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }
die()  { printf 'signsrv-firstboot: %s\n' "$*" >&2; exit 1; }

[ -x "$BIN" ] || die "no executable at $BIN"

# ----------------------------------------------------------------- directories ----
# 0750 on the state root: inside it are the encrypted CA key, the JWT key, every
# document signed here and the audit chain. Not 0700, because the logrotate stanza
# rotates as the service user's group; the group is what carries that access.
mkdir -p "$ETC" \
         "$STATE_PATH/keystore" \
         "$STATE_PATH/storage" \
         "$STATE_PATH/outbox" \
         "$STATE_PATH/audit" \
         "$STATE_PATH/log"
chmod 0750 "$STATE_PATH" "$STATE_PATH/keystore" 2>/dev/null || true
chmod 0755 "$STATE_PATH/storage" "$STATE_PATH/outbox" \
           "$STATE_PATH/audit" "$STATE_PATH/log" 2>/dev/null || true

if [ "$(id -u)" = 0 ]; then
    chown -R "$USER_NAME:$USER_NAME" "$STATE_PATH" 2>/dev/null || true
    # The directory must be traversable by the service user and the secrets inside it
    # must not be readable by that user. Those two requirements are satisfied by
    # different objects, and getting them wrong in either direction breaks the install:
    #
    #   /etc/signsrv          0750 root:signsrv  <- traversal for signsrv.env
    #   /etc/signsrv/env      0640 root:signsrv  <- the service reads its config
    #   /etc/signsrv/secrets  0600 root:root     <- the service cannot read this
    #
    # root:root on the directory is the trap: the config file's own 0640 root:signsrv
    # grants nothing, because opening a file requires execute on every directory above
    # it. The service then dies at "read config: permission denied" on a box where
    # checkconfig passed, since checkconfig runs as root.
    chown "root:$USER_NAME" "$ETC" 2>/dev/null || true
    chmod 0750 "$ETC"
fi

# ------------------------------------------------------------- read what exists ----
read_secret() { # read_secret <VARNAME> <file>
    [ -f "$2" ] || return 0
    sed -n -E "s/^[[:space:]]*(export[[:space:]]+)?$1[[:space:]]*=[[:space:]]*//p" "$2" |
        head -1 | sed -E 's/^["'\'']//; s/["'\'']$//'
}

rand_hex() { # rand_hex <bytes> — openssl is a Recommends, so fall back rather than die
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "$1"
    else
        od -An -tx1 -N "$1" /dev/urandom 2>/dev/null | tr -d ' \n'
    fi
}

KS_PASS=$(read_secret KEYSTORE_PASS "$SECRETS")
ADMIN_PW=$(read_secret ADMIN_PASSWORD "$SECRETS")
SMTP_PASS_CFG=$(read_secret SMTP_PASS "$SECRETS")
[ -n "$SMTP_PASS_CFG" ] || SMTP_PASS_CFG=${SIGNSETUP_SMTP_PASS:-}

# ------------------------------------------------------------------- keystore ----
# The one unrecoverable object on the box. A passphrase that no longer matches the key
# is not a missing value to be regenerated: it is a CA that can no longer be opened.
if [ -z "$KS_PASS" ] && [ -f "$STATE_PATH/keystore/ca.key" ]; then
    die "$STATE_PATH/keystore/ca.key exists, but its passphrase is not in $SECRETS.
       Restoring it is the only option that keeps your signatures valid. Put it back:
         echo 'KEYSTORE_PASS=<the passphrase>' >> $SECRETS
         chmod 600 $SECRETS
       If the passphrase is truly gone and you accept that every document signed by
       this CA can no longer be re-issued against it, start over deliberately:
         rm -f $STATE_PATH/keystore/ca.key $STATE_PATH/keystore/ca.crt
       Documents already signed still verify — verification needs the certificate,
       which is public — but this instance cannot sign anything new."
fi
if [ -z "$KS_PASS" ]; then
    KS_PASS=$(rand_hex 32)
    sed -i "/^KEYSTORE_PASS=/d" "$SECRETS" 2>/dev/null || true
    printf 'KEYSTORE_PASS=%s\n' "$KS_PASS" >> "$SECRETS"
    chmod 0600 "$SECRETS" 2>/dev/null || true
    if [ "$(id -u)" = 0 ]; then chown root:root "$SECRETS"; fi
    note "secrets: generated a keystore passphrase (the CA is created with it on first start)"
fi

# --------------------------------------------------------------------- config ----
conf_get() {
    [ -f "$CONF" ] || return 0
    sed -n -E "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$CONF" | head -1
}

# conf_set <key> <value>: append only when the key is absent and the value is
# non-empty. `smtp_host=` is not the same as omitting smtp_host — the validator calls a
# present-but-blank value missing, so a blank line reads as a corrupted file.
conf_set() {
    [ -n "${2:-}" ] || return 0
    if [ -z "$(conf_get "$1")" ]; then
        printf '%s=%s\n' "$1" "$2" >> "$CONF"
    fi
}

LISTEN=${SIGNSETUP_LISTEN:-127.0.0.1:8080}
PUBLIC_URL=${SIGNSETUP_PUBLIC_URL:-}
MAIL_FROM=${SIGNSETUP_MAIL_FROM:-}
SMTP_HOST=${SIGNSETUP_SMTP_HOST:-$(conf_get smtp_host)}
SMTP_PORT=${SIGNSETUP_SMTP_PORT:-587}
SMTP_STARTTLS=${SIGNSETUP_SMTP_STARTTLS:-true}
SMTP_USER=${SIGNSETUP_SMTP_USER:-}
ADMIN_EMAIL=$(printf '%s' "${SIGNSETUP_ADMIN_EMAIL:-}" | tr 'A-Z' 'a-z')

# A signing service cannot become both reachable and secure-by-default without two
# facts nobody can guess: the https URL the signing links point at, and a mail relay.
# So when no relay was supplied the install comes up in local mode instead of in a
# restart loop: the service starts, creates its CA, signs and verifies, and writes
# every invitation to the outbox rather than mailing it. A working service with a
# stated limitation beats a broken one with an opinion.
#
# When a relay IS supplied, dev must stay off. In dev the service generates a keystore
# passphrase at each start, which would orphan the CA the first time it wrote one.
if [ -z "$SMTP_HOST" ]; then
    MODE=local
    DEV_DEFAULT=true
    PUBLIC_DEFAULT="http://$LISTEN"
    MAIL_DEFAULT=signer@localhost
else
    MODE=relay
    DEV_DEFAULT=false
    PUBLIC_DEFAULT=${PUBLIC_URL:-https://localhost}
    MAIL_DEFAULT=${MAIL_FROM:-signer@localhost}
fi

if [ ! -f "$CONF" ]; then
    cat > "$CONF" <<'CONFHEADER'
# /etc/signsrv/signsrv.env — key=value, read by signsrv with -config.
#
# Secrets are NOT here. They live in /etc/signsrv/secrets.env (0600, root) and reach
# the process through systemd's EnvironmentFile, because this file must be readable by
# the service user and a passphrase in it would then be readable by that user too.
#
# Every key is written once. A key that is already present is never rewritten by an
# upgrade or by dpkg-reconfigure, so local edits survive.
CONFHEADER
fi

conf_set listen          "$LISTEN"
conf_set public_url      "${PUBLIC_URL:-$PUBLIC_DEFAULT}"
conf_set trust_proxy     "${SIGNSETUP_TRUST_PROXY:-false}"
conf_set dev             "$DEV_DEFAULT"
conf_set db              "$STATE_PATH/signsrv.db"
conf_set storage_dir     "$STATE_PATH/storage"
conf_set outbox_dir      "$STATE_PATH/outbox"
conf_set audit_dir       "$STATE_PATH/audit"
conf_set log_path        "$STATE_PATH/log/signsrv.jsonl"
conf_set keystore_dir    "$STATE_PATH/keystore"
conf_set jwt_secret_file "$STATE_PATH/jwt.ed25519.key"
conf_set downloads_dir   "$STATE_PATH/downloads"
conf_set mail_from       "$MAIL_DEFAULT"
conf_set smtp_host       "$SMTP_HOST"
conf_set smtp_port       "$SMTP_PORT"
conf_set smtp_starttls   "$SMTP_STARTTLS"
conf_set smtp_user       "$SMTP_USER"
conf_set tsa_url         "${SIGNSETUP_TSA_URL:-https://freetsa.org/tsr}"
conf_set link_ttl        168h
conf_set worker_interval 15s
conf_set max_pdf_mb      25
conf_set log_level       info

if [ "$(id -u)" = 0 ]; then
    # The service reads signsrv.env, so the service user is the group on it and on
    # nothing more than that.
    chown "root:$USER_NAME" "$CONF" 2>/dev/null || true
    [ -f "$SECRETS" ] && chown root:root "$SECRETS" && chmod 0600 "$SECRETS"
fi
chmod 0640 "$CONF" 2>/dev/null || true

if [ -n "$SMTP_PASS_CFG" ] && ! grep -q '^SMTP_PASS=' "$SECRETS" 2>/dev/null; then
    printf 'SMTP_PASS=%s\n' "$SMTP_PASS_CFG" >> "$SECRETS"
    chmod 0600 "$SECRETS" 2>/dev/null || true
    if [ "$(id -u)" = 0 ]; then chown root:root "$SECRETS"; fi
fi

# -------------------------------------------------- admin password, on file early ----
# validate() requires a non-empty admin_password on EVERY start while dev=false, and
# checkconfig just below runs that same validate. So the secrets file has to hold one
# before the configuration is checked — not only after the account is seeded — otherwise
# an install that specified a mail relay fails its own check and the service never starts.
if [ -z "$ADMIN_PW" ] && [ -n "${SIGNSETUP_ADMIN_PASSWORD:-}" ]; then
    ADMIN_PW=$SIGNSETUP_ADMIN_PASSWORD
fi
if [ -z "$ADMIN_PW" ] && [ "$MODE" != local ]; then
    ADMIN_PW=$(rand_hex 12)
fi
if [ -n "$ADMIN_PW" ] && ! grep -q '^ADMIN_PASSWORD=' "$SECRETS" 2>/dev/null; then
    printf 'ADMIN_PASSWORD=%s\n' "$ADMIN_PW" >> "$SECRETS"
    chmod 0600 "$SECRETS" 2>/dev/null || true
    if [ "$(id -u)" = 0 ]; then chown root:root "$SECRETS"; fi
fi

# ------------------------------------------------------------------ validate ----
# Run the checks the service would run at start, so a broken configuration fails here
# where an operator is watching instead of as a restart loop in the journal six hours
# later. The output is printed through a redactor: a failing setup must never echo the
# secret it exists to protect.
redact() { sed -E 's/(pass|secret|password|token)[^ ]*=[^ ]*/\1...=<redacted>/gI'; }

if ! ( . "$SECRETS" 2>/dev/null || true
       export KEYSTORE_PASS="${KEYSTORE_PASS:-$KS_PASS}"
       export ADMIN_PASSWORD="${ADMIN_PASSWORD:-$ADMIN_PW}"
       "$BIN" -config "$CONF" checkconfig >"$ETC/.firstboot-checkconfig.out" 2>&1 ); then
    redact < "$ETC/.firstboot-checkconfig.out" >&2 || true
    rm -f "$ETC/.firstboot-checkconfig.out"
    die "checkconfig rejected the configuration in $CONF (see the problems above)"
fi
rm -f "$ETC/.firstboot-checkconfig.out"
note "config: $CONF verified (checkconfig ok)"

# ADMIN_PASSWORD is now in the secrets file whenever dev=false needs it, so the
# subshell can just load the file. Explicit exports are what the service's EnvironmentFile
# would do; a plain load leaves the values as shell variables that the child never sees.

# ----------------------------------------------------------------- database ----
# migrate opens the file, applies the schema, runs integrity_check. Doing it here means
# the first service start does not race a cold database, and a failure surfaces during
# the install. Re-running it is a no-op.
run_as() { # run_as <cmd...> — as the service user when root, as self otherwise
    if [ "$(id -u)" = 0 ] && command -v setpriv >/dev/null 2>&1; then
        setpriv --reuid="$USER_NAME" --regid="$USER_NAME" --clear-groups "$@"
    elif [ "$(id -u)" = 0 ] && command -v su >/dev/null 2>&1; then
        su -s /bin/sh "$USER_NAME" -c "$(printf '%q ' "$@")"
    else
        "$@"
    fi
}

if ! run_as env KEYSTORE_PASS="$KS_PASS" ${ADMIN_PW:+ADMIN_PASSWORD="$ADMIN_PW"} \
        "$BIN" -config "$CONF" migrate >"$ETC/.firstboot-migrate.out" 2>&1; then
    redact < "$ETC/.firstboot-migrate.out" >&2 || true
    rm -f "$ETC/.firstboot-migrate.out"
    die "signsrv migrate failed against $STATE_PATH/signsrv.db"
fi
rm -f "$ETC/.firstboot-migrate.out"
note "database: $STATE_PATH/signsrv.db at the current schema"

# -------------------------------------------------------------------- admin ----
# There is no config-based admin bootstrap in the service: accounts are rows in the
# database, created only by `admin add`. Meanwhile validate() requires a non-empty
# admin_password on EVERY start whenever dev=false — not only the first — so a secrets
# file without one stops the service from coming up after the next reboot.
#
# So: seed the account here, and only persist the password once the account exists. If
# the seed fails (a malformed address, say), the password is not written and the next
# start retries; the service itself still boots, because dev=false plus a password it
# can read is a valid configuration.
admin_list() {
    run_as env KEYSTORE_PASS="$KS_PASS" ADMIN_PASSWORD="${ADMIN_PW:-x}" \
        "$BIN" -config "$CONF" admin list 2>/dev/null || true
}

persist_admin_pw() {
    sed -i "/^ADMIN_PASSWORD=/d" "$SECRETS" 2>/dev/null || true
    printf 'ADMIN_PASSWORD=%s\n' "$1" >> "$SECRETS"
    chmod 0600 "$SECRETS" 2>/dev/null || true
    if [ "$(id -u)" = 0 ]; then chown root:root "$SECRETS"; fi
}

if [ -n "$ADMIN_EMAIL" ]; then
    if admin_list | grep -qi -- "$ADMIN_EMAIL"; then
        note "admin: $ADMIN_EMAIL already exists, left alone"
    else
        ADMIN_PW=${SIGNSETUP_ADMIN_PASSWORD:-$ADMIN_PW}
        [ -n "$ADMIN_PW" ] || ADMIN_PW=$(rand_hex 12)
        if run_as env KEYSTORE_PASS="$KS_PASS" ADMIN_PASSWORD="$ADMIN_PW" \
                "$BIN" -config "$CONF" admin add "$ADMIN_EMAIL" \
                >"$ETC/.firstboot-admin.out" 2>&1; then
            persist_admin_pw "$ADMIN_PW"
            note "admin: created $ADMIN_EMAIL"
            if [ -n "${SIGNSETUP_ADMIN_PASSWORD:-}" ]; then
                note "       password: the SIGNSETUP_ADMIN_PASSWORD you supplied"
            else
                note "       a password was generated for it and stored in $SECRETS"
                note "       as ADMIN_PASSWORD. Rotate it to something you know:"
            fi
            note "         signsrv -config $CONF admin passwd $ADMIN_EMAIL"
        else
            redact < "$ETC/.firstboot-admin.out" >&2 || true
            warn "signsrv-firstboot: could not create admin $ADMIN_EMAIL. The service will
       still start; fix the cause and it will retry on the next start. Output above."
        fi
        rm -f "$ETC/.firstboot-admin.out"
    fi
fi

# dev=false requires a non-empty admin_password at all times, even when this instance
# has no admin account yet. Provide one rather than leaving the unit unable to start.
if [ "$MODE" = relay ] && [ -z "$ADMIN_PW" ]; then
    ADMIN_PW=$(rand_hex 12)
    persist_admin_pw "$ADMIN_PW"
fi

# ------------------------------------------------------------------- summary ----
if [ "$MODE" = relay ] && [ -z "$ADMIN_EMAIL" ]; then
    # A password was generated to satisfy validation. It logs nobody in, and an
    # operator with a green install has no way to guess that /admin/ is unreachable.
    note ""
    note "  No admin account exists yet. As root, create one now (12+ characters):"
    note "      signsrv-utils admin add you@your.host"
    note "      signsrv-utils admin list"
    note "  signsrv-utils reads the database path from $CONF and asks for nothing"
    note "  else, so it works even when the service itself refuses to start."
    note "  Then sign in at <public_url>/admin/."
fi

if [ "$MODE" = local ]; then
    note ""
    note "  LOCAL MODE (dev=true): invitations are written to $STATE_PATH/outbox"
    note "  instead of being mailed, and the CA is created for this host."
    note "  To go live, set in $CONF:"
    note "      dev=false"
    note "      public_url=https://your.host"
    note "      smtp_host=your.relay    smtp_port=587    mail_from=you@your.host"
    note "  put the relay password in $SECRETS as SMTP_PASS,"
    note "  create an admin, then: systemctl restart signsrv"
fi
exit 0
