#!/bin/sh
# packaging/deb/build-deb.sh — build the signsrv .deb without debhelper.
#
#   packaging/deb/build-deb.sh [OUT_DIR]
#
# debhelper is not installed here and is not needed: the package is two binaries, two
# helper scripts, one systemd unit and one config drop-in, so dpkg-deb assembles it
# directly. That is also why debian/control spells out its dependencies instead of
# using ${misc:Depends} — nothing expands substitutions in this path.
#
# Output: <OUT_DIR>/signsrv_<version>_<arch>.deb
set -eu

cd "$(dirname "$0")/../.."
ROOT=$(pwd)
OUT=${1:-dist}
PKG=signsrv

# arch is taken from dpkg, not from `uname -m`: an arm64 build host must produce
# signsrv_..._arm64.deb, and `uname -m` says aarch64 where dpkg says arm64.
ARCH=$(dpkg --print-architecture)
VERSION=$(sed -n -E 's/^Version:[[:space:]]*//p' packaging/deb/debian/control | head -1)
[ -n "$VERSION" ] || { echo "build-deb: no Version: in debian/control" >&2; exit 1; }

STAGE=$(mktemp -d "${TMPDIR:-/tmp}/signsrv-deb.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT

say() { printf '  %s\n' "$*"; }

# -------------------------------------------------------------------- build ----
# CGO off: the SQLite driver is modernc.org/sqlite, pure Go, so the binary has no
# libc dependency and runs on a system with a different glibc than the build host.
# -trimpath keeps build paths out of the binary, so a crash stack on the customer's
# box does not name a directory on the build machine.
say "building signsrv + signsrv-utils (CGO_ENABLED=0, -trimpath)"
mkdir -p "$STAGE/usr/bin" "$STAGE/usr/lib/signsrv" \
         "$STAGE/lib/systemd/system" "$STAGE/etc/logrotate.d" \
         "$STAGE/usr/share/doc/signsrv"
CGO_ENABLED=0 GOOS=linux go build -trimpath --tags "osusergo netgo" -ldflags="-X main.version=v1.0 -extldflags=-static -w -s" \
    -o "$STAGE/usr/bin/signsrv" ./cmd/signsrv
# signsrv-utils ships in the same package on purpose: it is the only way to
# answer questions about the database when the service refuses to start, and a
# version skew between the two binaries is exactly when that matters. Same
# module, same schema, same build — so an upgrade moves both together.
CGO_ENABLED=0 GOOS=linux go build -trimpath --tags "osusergo netgo" -ldflags="-X main.version=v1.0 -extldflags=-static -w -s" \
    -o "$STAGE/usr/bin/signsrv-utils" ./cmd/signsrv-utils
install -m 0755 packaging/deb/signsrv-firstboot.sh "$STAGE/usr/lib/signsrv/signsrv-firstboot.sh"
install -m 0755 packaging/deb/signsrv-adduser.sh   "$STAGE/usr/lib/signsrv/signsrv-adduser.sh"

install -m 0644 packaging/deb/debian/lib/systemd/system/signsrv.service \
        "$STAGE/lib/systemd/system/signsrv.service"
install -m 0644 deploy/logrotate.conf "$STAGE/etc/logrotate.d/signsrv"

for f in README.md runbook.md SECURITY.md docs/DEPLOY-DOCKER.md; do
    [ -f "$f" ] && install -m 0644 "$f" "$STAGE/usr/share/doc/signsrv/$(basename "$f")"
done
if [ -f LICENSE ]; then
    install -m 0644 LICENSE "$STAGE/usr/share/doc/signsrv/copyright"
else
    {
        echo "signsrv"
        echo "Contact packaging@kaykraft.org for licence terms before redistribution."
    } > "$STAGE/usr/share/doc/signsrv/copyright"
fi

# The binary embeds one font (internal/signpdf/assets). An OFL-licensed font
# compiled into an executable is allowed, but the licence text has to travel
# with the package, so it is appended to the copyright file rather than left in
# the source tree only. A missing asset already fails the compile, because
# go:embed is resolved at build time; the check is here so the failure names the
# font instead of reporting a missing embed file.
FONT_TTF="internal/signpdf/assets/PatrickHand-Regular.ttf"
FONT_OFL="internal/signpdf/assets/OFL.txt"
for f in "$FONT_TTF" "$FONT_OFL"; do
    if [ ! -s "$f" ]; then
        echo "build-deb: $f missing; the appearance font must be compiled in" >&2
        exit 1
    fi
done
{
    printf '\n---\n\nThis program embeds the font Patrick Hand.\n\n'
    echo "Files: internal/signpdf/assets/PatrickHand-Regular.ttf"
    sed -e 's/^/ /' "$FONT_OFL"
} >> "$STAGE/usr/share/doc/signsrv/copyright"

# ------------------------------------------------------------------ control ----
# Installed-Size is in 1 KiB blocks and is what dpkg checks free space against before
# unpacking. Guessing it low is a real failure mode: a nearly-full box would unpack
# into a partial install.
SIZE=$(du -sk "$STAGE" | cut -f1)
mkdir -p "$STAGE/DEBIAN"
sed -E "s/^Installed-Size: @INSTALLED_SIZE_KB@$/Installed-Size: $SIZE/" \
    packaging/deb/debian/control > "$STAGE/DEBIAN/control"

for m in preinst postinst prerm postrm; do
    install -m 0755 "packaging/deb/debian/$m" "$STAGE/DEBIAN/$m"
done

if [ ! -s "$STAGE/usr/share/doc/signsrv/copyright" ]; then
    echo "build-deb: debian/copyright missing (required by dpkg)" >&2
    exit 1
fi

# ------------------------------------------------------------------ modes ----
# Modes in the data tar are exactly what dpkg applies on the target, and they come
# from the staging tree — so without this they inherit whatever umask the person who
# ran the build happened to have. A umask of 002 would ship /etc/logrotate.d and
# /usr/bin/signsrv group-writable, which lintian reports and which is wrong for a
# binary that runs as root-adjacent infrastructure under systemd. Declared, not
# inherited: directories 0755, non-executables 0644, executables 0755.
#
# The root of the tree included: a 0700 "./" in the data tar is a lintian finding even
# though dpkg leaves / alone.
find "$STAGE" -type d ! -path "$STAGE/DEBIAN*" -exec chmod 0755 {} +
find "$STAGE" -type f ! -path "$STAGE/DEBIAN*" -exec chmod 0644 {} +
# Every executable in the tree has to be named here: the find above set them all
# to 0644. Adding a binary to the build without adding it here ships it
# non-executable, which is why the block below asserts the modes rather than
# trusting this list to have been kept in sync.
chmod 0755 "$STAGE/usr/bin/signsrv" \
           "$STAGE/usr/bin/signsrv-utils" \
           "$STAGE/usr/lib/signsrv/signsrv-firstboot.sh" \
           "$STAGE/usr/lib/signsrv/signsrv-adduser.sh"

# Assert rather than assume. A binary that lands in the package mode 0644 is a
# silent failure until someone runs it on a customer's box, and the person who
# adds the next binary is unlikely to remember this list exists.
for b in signsrv signsrv-utils; do
    [ -f "$STAGE/usr/bin/$b" ] || { echo "build-deb: /usr/bin/$b was not built" >&2; exit 1; }
done
BADMODE=$(find "$STAGE" -path "$STAGE/usr/bin/*" -type f ! -perm 0755)
[ -z "$BADMODE" ] || {
    echo "build-deb: these must be mode 0755:" >&2
    printf '  %s\n' $BADMODE >&2
    exit 1
}

# -------------------------------------------------------------------- pack ----
# --root-owner-group: the tree is assembled by an unprivileged user, and without this
# every file would carry the builder's uid. dpkg would then install a binary owned by
# a uid that does not exist on the target.
mkdir -p "$OUT"
DEB="$OUT/${PKG}_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --compression=xz --build "$STAGE" "$DEB"

say "built $DEB"
dpkg-deb -I "$DEB" | sed -n '/Package:/,/^$/p' | sed 's/^/    /'
say "contents:"
dpkg-deb -c "$DEB" | awk '{printf "    %s %s\n", substr($1,1,10), $NF}'
exit 0
