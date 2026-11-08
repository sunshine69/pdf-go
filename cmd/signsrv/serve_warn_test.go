package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// logConfigWarnings is the part of the public-bind change an operator actually
// meets. `checkconfig` prints the same list, but nobody re-runs it after a
// deploy — a warning that only appears when someone asks for it is a warning
// that never gets read. These tests hold the serve side of that promise.

// A published listener has to land on the log, as a WARN, naming the cost.
func TestServeLogsConfigWarnings(t *testing.T) {
	p := checkConfigServer(t,
		strings.Replace(goodBase, "listen=127.0.0.1:8080", "listen=0.0.0.0:8080", 1), 0o600)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("a public listener is the operator's call: %v", err)
	}

	var buf bytes.Buffer
	logConfigWarnings(slog.New(slog.NewJSONHandler(&buf, nil)), cfg)
	got := buf.String()

	if !strings.Contains(got, `"level":"WARN"`) {
		t.Fatalf("want a WARN record, got %q", got)
	}
	if !strings.Contains(got, "plain HTTP") {
		t.Fatalf("want the plain-HTTP warning on the log, got %q", got)
	}
	// The address belongs in the message: on a box with several listeners,
	// "somewhere is bound too publicly" is not actionable.
	if !strings.Contains(got, "0.0.0.0:8080") {
		t.Fatalf("want the offending address named, got %q", got)
	}
}

// The common shape must stay silent. A warning printed on every start is noise,
// and noise is how warnings get ignored.
func TestServeQuietOnLoopbackConfig(t *testing.T) {
	p := checkConfigServer(t, goodBase, 0o600)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	logConfigWarnings(slog.New(slog.NewJSONHandler(&buf, nil)), cfg)
	if buf.Len() != 0 {
		t.Fatalf("want silence on a loopback config, got %q", buf.String())
	}
}

// serve calls this before it knows whether cfg is usable, and LoadConfig can
// return both an error and a config (or neither). A nil panic at the moment an
// operator is trying to read a configuration error is the worst possible
// failure mode for a logging helper.
func TestServeLogsNilConfigSafely(t *testing.T) {
	var buf bytes.Buffer
	logConfigWarnings(slog.New(slog.NewJSONHandler(&buf, nil)), nil)
	if buf.Len() != 0 {
		t.Fatalf("want nothing for a nil config, got %q", buf.String())
	}
}
