#!/bin/sh
# scripts/test.sh — every test in the repository, one command.
#
# The Go suites cover the server and the PDF. The signing page is plain
# browser JavaScript with no build step, and its tests (test/spa/) run it in
# Node with a small DOM: the upload path had a bug no Go test could see, where
# the file reader wrote to a variable out of its scope and the browser failed
# the upload in silence.
set -eu

say() { printf '\n== %s\n' "$1"; }

say "format"
unformatted=$(gofmt -l ./cmd ./internal 2>&1)
if [ -n "$unformatted" ]; then
    printf 'not gofmt-clean: %s\n' "$unformatted"
    exit 1
fi

say "vet"
go vet ./cmd/signsrv ./cmd/pdf-go ./internal/signpdf ./internal/signflow

say "go"
go test "$@" ./cmd/signsrv ./cmd/pdf-go ./internal/signpdf ./internal/signflow

say "browser (web/spa)"
node --test 'test/spa/*.test.mjs'
