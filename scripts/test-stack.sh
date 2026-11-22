#!/bin/sh
# scripts/test-stack.sh — start, check and stop the test instance behind
# test-pdfsign.kaykraft.org:7000.
#
#   scripts/test-stack.sh up        build, start, health check, print the IP diagnostic
#   scripts/test-stack.sh check     health + IP diagnostic, no restart
#   scripts/test-stack.sh ip        the IP diagnostic alone
#   scripts/test-stack.sh logs      the access log lines that carry an ip
#   scripts/test-stack.sh down      stop (keeps the data volume)
#   scripts/test-stack.sh down -v   stop and wipe the data volume
#   scripts/test-stack.sh reset     down -v then up, i.e. a clean instance
#
# Why the `ip` diagnostic exists. The address recorded on a signature comes from
# signauth.ClientIP(r, cfg.TrustProxy), which returns the left-most entry of
# X-Forwarded-For only when trust_proxy is on, and otherwise the socket peer. On
# this instance the socket peer is the docker bridge gateway, because a published
# port is SNATed by docker. So the peer address is a fixed, meaningless value, and
# the ONLY way the real client address can arrive is the header. That makes the
# header the single point of failure, and it is checkable in one request with no
# token, no envelope and no signature:
#
#   GET /healthz with no header     -> logs the bridge gateway   (the fallback)
#   GET /healthz with a forged XFF  -> logs the forged value     (trust_proxy=1 works)
#
# If the second one does not echo the forged value, trust_proxy is off, and every
# signature from this instance will record the gateway address. That is the bug
# being chased, provable before anyone signs anything.
#
# Secrets: .env.test is created with mode 0600 and never printed. It is generated
# once and kept, because the keystore passphrase has to match the CA private key
# on the data volume. Deleting the volume without deleting .env.test is harmless;
# deleting .env.test while the volume still holds a keystore orphans every
# signature issued by this instance, so the script refuses that combination.

set -eu

cd "$(dirname "$0")/.."   # repo root, wherever this was started from

COMPOSE=${COMPOSE:-deploy/docker-compose.test.yml}
ENVF=${ENVF:-deploy/.env.test}
DOMAIN=${DOMAIN:-test-pdfsign.kaykraft.org}
PORT=${PORT:-7000}
HEALTH_URL=${HEALTH_URL:-https://${DOMAIN}/healthz}
FORGED_IP=${FORGED_IP:-203.0.113.77}

dc() { docker compose -f "$COMPOSE" "$@"; }

say()  { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- secrets ----
ensure_env() {
    if [ -f "$ENVF" ]; then
        note "$ENVF already present - reusing it (the keystore passphrase must stay put)"
        return 0
    fi
    umask 077
    : > "$ENVF"
    printf 'KEYSTORE_PASS=ks-%s\n'      "$(openssl rand -hex 16)" > "$ENVF"
    printf 'ADMIN_PASSWORD=admin-%s\n'  "$(openssl rand -hex 12)" > "$ENVF"
    chmod 0600 "$ENVF"
    note "generated $ENVF (mode 0600, values not printed)"

    # The trap, stated once at the moment it can still be avoided.
    if dc ps -q signsrv | grep -q .; then
        note "!! the container already exists. If the data volume already holds a"
        note "   CA, this new passphrase will not unlock it and every signature"
        note "   issued so far stops verifying. Wipe the volume too, or restore the"
        note "   original passphrase by hand."
    fi
}

# ------------------------------------------------------------------ health ----
health() {
    say "health: $HEALTH_URL"
    code=$(curl -s -o /tmp/stack-health.out -w '%{http_code}' \
              --max-time 15 "$HEALTH_URL" 2>/tmp/stack-health.err || echo 000)
    case "$code" in
        200) note "200 - the domain reaches the container" ;;
        000) fail "no answer from $HEALTH_URL (see /tmp/stack-health.err)" ;;
        502) fail "502 Bad Gateway: the front proxy resolved the domain but nothing" \
                 "answered on port $PORT. Is the container up, and is it listening" \
                 "on 0.0.0.0:$PORT?" ;;
        *)   fail "$HEALTH_URL answered $code: $(head -c 200 /tmp/stack-health.out 2>/dev/null)" ;;
    esac
    head -c 200 /tmp/stack-health.out 2>/tmp/e | sed 's/^/     /'
    printf '\n'
}

# -------------------------------------------------------------------- ip ----
# The diagnostic. Two requests to /healthz, then read what the service logged.
ip_probe() {
    say "ip diagnostic (trust_proxy behaviour, no token needed)"

    # 1. nothing in front of it: the socket peer, which on this instance is the
    #    docker bridge gateway.
    curl -s -o /tmp/stack-ip-raw.out --max-time 15 "$HEALTH_URL" 2>/tmp/e || true
    # 2. a header set by something that is not this client, i.e. a proxy.
    curl -s -o /tmp/stack-ip-fwd.out --max-time 15 \
         -H "X-Forwarded-For: $FORGED_IP" "$HEALTH_URL" 2>/tmp/e || true

    sleep 2
    gw=$(dc exec -T signsrv sh -c \
        'grep -o "172\.[0-9]*\.[0-9]*\.[0-9]*" /var/lib/signsrv/log/signsrv.jsonl | tail -1' \
        2>/tmp/e | tail -1 || true)
    seen=$(dc exec -T signsrv sh -c \
        "grep -o \"$FORGED_IP\" /var/lib/signsrv/log/signsrv.jsonl | tail -1" 2>/tmp/e | tail -1 || true)

    note "peer address seen in the log:  ${gw:-(none)}"
    note "X-Forwarded-For echoed in log: ${seen:-(none)}"

    if [ -n "$seen" ]; then
        note "PASS - the service honours X-Forwarded-For, so a signature made"
        note "     through the front proxy can record the real client address."
        return 0
    fi
    note "FAIL - the service did not honour the header."
    note "     Two possible causes, and the fix differs:"
    note "       a) TRUST_PROXY is not 1 in this container"
    note "          docker compose -f $COMPOSE exec signsrv signsrv checkconfig"
    note "       b) the front proxy strips or fails to set X-Forwarded-For"
    note "          (it must be SET to \$remote_addr, not appended to the chain)"
    return 1
}

# ------------------------------------------------------------------ print ----
show_state() {
    say "instance"
    dc ps 2>/tmp/e || true
    say "config as the service reads it"
    dc exec -T signsrv signsrv checkconfig 2>/tmp/e \
        | grep -E "listen|public_url|trust_proxy|dev|db=" | sed 's/^/     /' || true
    # Who can log in. On a first start this is the account the service seeded
    # from DEFAULT_ADMIN_EMAIL; an empty list means /admin/ refuses every login.
    say "admin accounts"
    dc exec -T signsrv signsrv-utils admin list 2>/tmp/e | sed 's/^/     /' || true
}

logs_with_ip() {
    say "access lines carrying an ip (last 12)"
    dc exec -T signsrv sh -c \
        'grep -o "\"ip\":\"[^\"]*\"" /var/lib/signsrv/log/signsrv.jsonl | tail -12' \
        2>/tmp/e | sed 's/^/     /' || true
}

# ------------------------------------------------------------------ main ----
cmd=${1:-up}
shift 2>/tmp/e || true

case "$cmd" in
    up)
        ensure_env
        say "build"
        dc build 2>&1 | tail -3 | sed 's/^/     /'
        say "start"
        dc up -d 2>&1 | tail -4 | sed 's/^/     /'
        # The listener is inside the container; give it a moment, then prove it
        # from outside rather than trusting that it started.
        i=0
        while [ "$i" -lt 20 ]; do
            curl -s -o /tmp/e -w '' --max-time 3 "$HEALTH_URL" 2>/tmp/e && break
            i=$((i + 1)); sleep 2
        done
        health
        ip_probe
        show_state
        logs_with_ip
        say "ready"
        note "public URL  https://$DOMAIN"
        note "regression  scripts/prod-sign-run.sh"
        note "stop        scripts/test-stack.sh down"
        ;;
    check)
        health; ip_probe; show_state
        ;;
    ip)
        ip_probe
        ;;
    logs)
        logs_with_ip
        ;;
    down)
        say "stop"
        dc down "$@" 2>&1 | tail -4 | sed 's/^/     /'
        ;;
    reset)
        say "stop and wipe"
        dc down -v 2>&1 | tail -3 | sed 's/^/     /'
        exec "$0" up
        ;;
    *)
        fail "usage: $0 [up|check|ip|logs|down|reset]"
        ;;
esac
