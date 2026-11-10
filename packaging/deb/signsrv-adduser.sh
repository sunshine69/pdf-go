#!/bin/sh
# packaging/deb/signsrv-adduser.sh — create the service account.
#
# Called from preinst. Idempotent, and safe to run by hand.
#
# The account is a system account with no password and no login shell: nothing can
# authenticate as signsrv, which is the point — the process runs under it via systemd,
# and nobody should be able to get a shell there.

set -eu

USER_NAME=${SIGNSETUP_USER:-signsrv}
R=${SIGNSETUP_ROOT:-/}

if [ -n "$R" ] && [ "$R" != "/" ]; then
    # Creating an account in a fake root is not something this script pretends to do.
    exit 0
fi

if getent passwd "$USER_NAME" >/dev/null 2>&1; then
    exit 0
fi

if ! command -v adduser >/dev/null 2>&1; then
    echo "signsrv: adduser is missing; cannot create the $USER_NAME account" >&2
    exit 1
fi

# A dedicated group (--group) and an explicit high UID range keep this out of the way
# of local accounts. --disabled-password means no password is set rather than a locked
# one; --shell /usr/sbin/nologin means no interactive login either way.
adduser --system --group --home /var/lib/signsrv \
        --no-create-home --shell /usr/sbin/nologin \
        --disabled-password --gecos "signsrv PDF signing service" \
        "$USER_NAME" >/dev/null 2>&1 || {
    # adduser exits non-zero if the name was taken between the check above and the
    # call. That is not an error for us.
    getent passwd "$USER_NAME" >/dev/null 2>&1 || exit 1
}
exit 0
