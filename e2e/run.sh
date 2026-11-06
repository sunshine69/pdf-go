#!/bin/sh
# The end-to-end acceptance run, in one command.
#
#   e2e/run.sh                 run every phase
#   E2E_SKIP_BROWSER=1 e2e/run.sh   run the phases up to and including "send + outbox"
#   e2e/run.sh "audit chain"   run the phases up to the one named
#   e2e/run.sh -list           list the phases
#
# The run builds the binaries itself, so it always tests the tree it is in.
set -e
cd "$(dirname "$0")/.."

E2E_WORK=${E2E_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/signsrv-e2e-XXXXXX")}
export E2E_WORK

command -v go >/dev/null 2>&1 || { echo "run.sh: go is not installed" >&2; exit 1; }

# The browser phase needs node, playwright-core and a Chrome. Check them here,
# because discovering it halfway through the run wastes the whole run.
if [ "${E2E_SKIP_BROWSER:-0}" != "1" ]; then
  if ! command -v node >/dev/null 2>&1; then
    echo "run.sh: node not found; set E2E_SKIP_BROWSER=1 to run without the browser phase" >&2
    exit 1
  fi
  PW=${E2E_NODE_MODULES:-/tmp/pw/node_modules}
  if [ ! -d "$PW/playwright-core" ]; then
    echo "run.sh: installing playwright-core in ${PW%/*}"
    mkdir -p "${PW%/*}"
    (cd "${PW%/*}" && npm install playwright-core --no-audit --no-fund >/dev/null)
  fi
  export E2E_NODE_MODULES=$PW
  CHROME=${CHROME:-$(command -v google-chrome || command -v chromium || command -v chromium-browser || true)}
  if [ -z "$CHROME" ]; then
    echo "run.sh: no Chrome or Chromium found; set CHROME=... or E2E_SKIP_BROWSER=1" >&2
    exit 1
  fi
  export CHROME
fi

echo "work dir: $E2E_WORK"
go build -tags e2e -mod=vendor -o "$E2E_WORK/e2e" ./e2e
# The build tag means `go test ./...` never compiles this file. Running it as a
# binary is the point: it is a program that drives real processes, not a test
# that needs the test harness.
set +e
"$E2E_WORK/e2e" "$@"
rc=$?
set -e
echo
if [ $rc -eq 0 ]; then
  echo "acceptance run passed. Evidence: $E2E_WORK/reports"
else
  echo "acceptance run FAILED. Evidence: $E2E_WORK/reports"
fi
exit $rc
