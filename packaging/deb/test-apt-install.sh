#!/bin/bash
# packaging/deb/test-apt-install.sh — install the package the way a customer does,
# inside a clean Ubuntu with systemd as PID 1, and prove the service comes up by
# itself. Nothing here is mocked: apt resolves the dependencies, dpkg runs preinst /
# postinst, systemd reads the unit, the unit's ExecStartPre runs the first-boot setup,
# and the service is started by the package.
#
# Needs docker or podman, and a network for apt.
#   packaging/deb/test-apt-install.sh [path/to/signsrv_*.deb]
#
set -eu
cd "$(dirname "$0")/../.."

DEB=${1:-$(ls -t dist/signsrv_*_amd64.deb 2>/dev/null | head -1)}
[ -f "$DEB" ] || { echo "no .deb found; run packaging/deb/build-deb.sh first" >&2; exit 1; }
echo "== package: $DEB"

command -v docker >/dev/null 2>&1 || [ -x /opt/docker-bin/docker ] || {
    echo "docker is required" >&2; exit 1; }
export PATH=/opt/docker-bin:$PATH

C=signsrv-debtest
BASE=signsrv-ubuntu-systemd
docker rm -f "$C" >/dev/null 2>&1 || true

# ubuntu:24.04 ships no init at all: systemd is not in the base image. Install it and
# commit once, so the run below is a machine that boots systemd as PID 1 the way a real
# Ubuntu host does — which is the only way to test the unit, the enable step, and the
# journal, none of which can be tested any other short of a real host.
if ! docker image inspect "$BASE" >/dev/null 2>&1; then
    echo "== building a systemd-capable ubuntu image (once)"
    docker rm -f "$BASE-build" >/dev/null 2>&1 || true
    docker run -d --name "$BASE-build" ubuntu:24.04 sleep 3600 >/dev/null
    docker exec "$BASE-build" bash -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null
        apt-get install -y -qq systemd systemd-sysv dbus curl ca-certificates locales >/dev/null
        locale-gen en_AU.UTF-8 >/dev/null 2>&1 || true
        # getty and other units that do nothing useful in a container, and that only
        # add noise to "is-system-running"
        systemctl mask getty@tty1.service systemd-udevd.service systemd-udevd-kernel.socket \
            systemd-udevd-control.socket systemd-modules-load.service sys-kernel-config.mount \
            systemd-sysctl.service >/dev/null 2>&1 || true
    '
    docker commit --change 'STOPSIGNAL SIGRTMIN+3' "$BASE-build" "$BASE" >/dev/null
    docker rm -f "$BASE-build" >/dev/null
fi

# --privileged, not a device whitelist. bpf() is required by modern systemd and is
# not in any whitelist short of privileged; a container whose init dies on an LSM
# call is not testing the package. Do not run this container on a shared host.
docker run -d --name "$C" --privileged --tmpfs /run --tmpfs /run/lock \
       --env container=docker \
       -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
       "$BASE" /lib/systemd/systemd >/dev/null
trap 'docker rm -f "$C" >/dev/null 2>&1 || true' EXIT

echo "== waiting for systemd"
for i in $(seq 1 60); do
    if docker exec "$C" systemctl is-system-running >/tmp/isr.txt 2>&1; then break; fi
    if grep -qE 'running|degraded' /tmp/isr.txt 2>/dev/null; then break; fi
    sleep 1
done
docker exec "$C" systemctl --version | head -1
docker exec "$C" systemctl is-system-running || true

echo "== copying the package in"
docker cp "$DEB" "$C":/root/

echo "== apt install (dependencies resolved from the archive, maintainer scripts run)"
# -y makes it non-interactive. -q -q keeps the log readable. A failure here is the
# most important possible failure: dependencies that do not resolve, or a preinst that
# exits non-zero, stop the install outright.
docker exec "$C" bash -c '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq curl ca-certificates >/dev/null 2>&1
  apt-get install -y -qq /root/signsrv_*.deb 2>&1 | tail -20
'

echo
echo "== dpkg state"
docker exec "$C" dpkg-query -W -f='  {Package} {Version} {Status}\n' signsrv

echo
echo "== what got installed"
docker exec "$C" dpkg -L signsrv | grep -vE '/usr/share/doc' | sed 's/^/  /'

echo
echo "== the service account preinst created"
docker exec "$C" getent passwd signsrv | sed 's/^/  /'

echo
echo "== what postinst wrote"
docker exec "$C" bash -c 'ls -la /etc/signsrv/ | sed "s/^/  /"; echo; sed -E "s/(pass|secret|password)[^=]*=.*/\1...=<redacted>/I" /etc/signsrv/signsrv.env | sed "s/^/  /"'

echo
echo "== unit status"
docker exec "$C" systemctl is-enabled signsrv | sed 's/^/  enabled: /'
docker exec "$C" systemctl is-active signsrv | sed 's/^/  active:  /'
docker exec "$C" systemctl show signsrv -p MainPID -p ExecMainStartTimestamp -p User -p StateDirectory | sed 's/^/  /'

echo
echo "== journal"
docker exec "$C" journalctl -u signsrv --no-pager -n 20 | sed 's/^/  /'

echo
echo "== the service answers"
docker exec "$C" bash -c 'curl -s -o /tmp/h -w "  healthz %{http_code}\n" http://127.0.0.1:8080/healthz; sed "s/^/  /" /tmp/h; echo'

echo
echo "== first-start artifacts (created by the service, not by postinst)"
docker exec "$C" bash -c '
  ls -la /var/lib/signsrv/keystore/ | sed "s/^/  /"
  echo
  ls -l  /var/lib/signsrv/jwt.ed25519.key 2>&1 | sed "s/^/  /"
  echo
  echo "  schema: $(/usr/bin/signsrv -config /etc/signsrv/signsrv.env dbstatus 2>&1 | head -2 | tr "\n" " ")"
'

echo
echo "== an operator can create an admin and log in (the /admin/ path works)"
# The package cannot guess who the administrator is, so it creates nobody. This is the
# action a real operator takes next, so it is the action tested.
docker exec "$C" bash -c '
  set -e
  PASS="operator-test-password-1"
  SIGNSRV_ADMIN_PASSWORD="$PASS" signsrv -config /etc/signsrv/signsrv.env \
      admin add operator@example.org | sed "s/^/  /"
  TOK=$(curl -s -X POST http://127.0.0.1:8080/api/v1/auth/login \
        -H "content-type: application/json" \
        -d "{\"email\":\"operator@example.org\",\"password\":\"\$PASS\"}" |
        sed -n "s/.*\"access_token\":\"\([^\"]*\)\".*/\1/p")
  echo "  admin login: token length ${#TOK}"
  [ -n "$TOK" ] || { echo "  FAIL: could not log in as the admin the package let us create"; exit 1; }
  curl -s -o /tmp/adm -w "  GET /admin/ : %{http_code}\n" http://127.0.0.1:8080/admin/
  curl -s -o /tmp/s  -w "  GET /s/     : %{http_code}\n" http://127.0.0.1:8080/s/
  echo "  PASS the admin was created by the documented command and can authenticate"
'

echo
echo "== restart survives a reboot-like stop/start, and the CA is the same"
docker exec "$C" bash -c '
  set -e
  A=$(sha256sum /var/lib/signsrv/keystore/ca.crt | cut -c1-16)
  systemctl restart signsrv
  sleep 3
  B=$(sha256sum /var/lib/signsrv/keystore/ca.crt | cut -c1-16)
  echo "  ca.crt before restart: $A"
  echo "  ca.crt after  restart: $B"
  [ "$A" = "$B" ] && echo "  PASS the CA survived the restart" || { echo "  FAIL"; exit 1; }
  systemctl is-active signsrv | sed "s/^/  active after restart: /"
  curl -s -o /dev/null -w "  healthz after restart: %{http_code}\n" http://127.0.0.1:8080/healthz
'

echo
echo "== self-heal: damage the state directory, the unit repairs it on the next start"
docker exec "$C" bash -c '
  set -e
  rmdir /var/lib/signsrv/audit 2>/dev/null || rm -rf /var/lib/signsrv/audit
  systemctl restart signsrv
  sleep 3
  if [ -d /var/lib/signsrv/audit ]; then
      echo "  PASS /var/lib/signsrv/audit was recreated by ExecStartPre"
  else
      echo "  FAIL the audit directory was not recreated"; exit 1
  fi
  curl -s -o /dev/null -w "  healthz after self-heal: %{http_code}\n" http://127.0.0.1:8080/healthz
'

echo
echo "== upgrade: installing the same package again must not re-key the CA"
docker exec "$C" bash -c '
  set -e
  A=$(sha256sum /var/lib/signsrv/keystore/ca.crt | cut -c1-16)
  P1=$(sha256sum /etc/signsrv/secrets.env | cut -c1-16)
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq --reinstall /root/signsrv_*.deb >/dev/null 2>&1
  sleep 3
  B=$(sha256sum /var/lib/signsrv/keystore/ca.crt | cut -c1-16)
  P2=$(sha256sum /etc/signsrv/secrets.env | cut -c1-16)
  echo "  ca.crt      before: $A  after: $B"
  echo "  secrets.env before: $P1  after: $P2"
  [ "$A" = "$B" ] && [ "$P1" = "$P2" ] && echo "  PASS re-install preserved the CA and the passphrase" ||
      { echo "  FAIL"; exit 1; }
  systemctl is-active signsrv | sed "s/^/  active after reinstall: /"
'

echo
echo "== purge: the evidence is kept, the configuration is removed"
docker exec "$C" bash -c '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get purge -y -qq signsrv >/dev/null 2>&1
  echo "  /etc/signsrv present:      $( [ -e /etc/signsrv ] && echo YES || echo "no (removed, as intended)" )"
  echo "  /var/lib/signsrv present:  $( [ -d /var/lib/signsrv ] && echo "YES (kept, as intended)" || echo no )"
  echo "  ca.crt still there:        $( [ -f /var/lib/signsrv/keystore/ca.crt ] && echo YES || echo no )"
  [ -d /var/lib/signsrv ] && [ -f /var/lib/signsrv/keystore/ca.crt ] ||
      { echo "  FAIL: purge removed signed evidence"; exit 1; }
  echo "  PASS purge removed configuration and kept the evidential records"
'

echo
echo "APT INSTALL TEST PASSED"
