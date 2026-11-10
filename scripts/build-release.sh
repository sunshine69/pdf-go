#!/usr/bin/env bash
# Builds the verification tool for the two operating systems the recipient
# guide names, and writes a checksum file alongside them.
#
#   scripts/build-release.sh [OUT_DIR]
#
# OUT_DIR defaults to var/downloads, which is what downloads_dir should point
# at. Once the files are there, the links in Validation-Guide.md resolve:
# /dl/signsrv-linux-amd64 and /dl/signsrv-windows-amd64.exe.
#
# The Linux binary is the one most people want: it is a single file with no
# installer and no runtime. The Windows binary is a single .exe, also with no
# installer, but Windows will warn before running an unsigned binary, and that
# warning is expected — the guide explains what to do about it.
set -euo pipefail

cd "$(dirname "$0")/.."

OUT=${1:-var/downloads}
mkdir -p "$OUT"

# The recipient's command has to be one line, so the trust anchor cannot be a
# second download: it goes into the binary. A tool with no anchor still
# verifies, but its verdict means only "intact", so a release build always pins.
CA_FILE=${CA_FILE:-var/keystore/ca.crt}
if [ ! -f "$CA_FILE" ]; then
  echo "error: no CA at $CA_FILE (set CA_FILE=path/to/ca.crt)" >&2
  echo "       the release binary must carry the instance CA, or a recipient" >&2
  echo "       cannot tell a document signed here from one signed anywhere." >&2
  exit 1
fi
# base64 of the DER: one line, so it survives the linker's argument. The type
# of the target variable is string; -X on a slice silently does nothing.
CA_B64=$(openssl x509 -in "$CA_FILE" -outform DER 2>/dev/null | base64 -w 0)
if [ -z "$CA_B64" ]; then
  echo "error: could not read a certificate from $CA_FILE" >&2
  exit 1
fi
# The target is written as `main.embeddedCA`, not the module import path: the
# linker names symbols of package main by `main`, and `-X` with the import path
# does not error, it silently injects nothing. The check below exists because a
# silent no-op here ships binaries that verify without an anchor and print
# trust:none on every document, which is exactly the failure this step prevents.
LDFLAGS="-X 'main.embeddedCA=$CA_B64'"
echo "pinning binary to CA: $CA_FILE"
openssl x509 -in "$CA_FILE" -noout -subject -enddate

# -trimpath keeps the build reproducible in the file paths it embeds. No CGO:
# the binary must not depend on a C library the recipient's machine may not
# have, and the Windows build has to cross-compile from Linux.
export CGO_ENABLED=0

echo "building linux/amd64"
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/signsrv-linux-amd64" ./cmd/signsrv

echo "building windows/amd64"
# The .exe is part of the published name, not decoration: Windows only runs a
# program when it can see the extension, and a file downloaded as
# signsrv-windows-amd64 is not one a recipient can double-click. The name here,
# the allowlist in cmd/signsrv/downloads.go and the link in Validation-Guide.md
# have to agree.
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/signsrv-windows-amd64.exe" ./cmd/signsrv

# Confirm the injection landed. A `-X` that names the wrong symbol exits 0 and
# changes nothing, and the resulting binary still runs, still prints "valid":
# true for our documents, and reports trust:none — a recipient would only notice
# the anchor was missing by reading the report closely. So the release script
# checks the bytes of the binary it is about to publish instead of trusting the
# linker.
for f in signsrv-linux-amd64 signsrv-windows-amd64.exe; do
  if ! grep -q -- "$CA_B64" "$OUT/$f"; then
    echo "error: $OUT/$f does not contain the trust anchor it was built with" >&2
    echo "       the -X symbol name is wrong; it must be main.embeddedCA." >&2
    exit 1
  fi
done
echo "trust anchor present in both binaries"

# Digests of exactly the two files the guide links to, in the format `sha256sum
# -c` understands, so the checksum file can be checked with one command.
( cd "$OUT" && sha256sum signsrv-linux-amd64 signsrv-windows-amd64.exe > signsrv-checksums.txt )

echo
echo "published to $OUT:"
ls -l "$OUT"
echo
echo "verify with:"
echo "  cd $OUT && sha256sum -c signsrv-checksums.txt"
echo
echo "then set downloads_dir=$OUT in the config and restart, so the links work."
