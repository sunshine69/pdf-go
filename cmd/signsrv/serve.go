package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// logConfigWarnings states every finding the service is willing to run with.
// A warning that only appears when someone asks for it is a warning that never
// gets read, so serve says it on every start and checkconfig repeats it in its
// report.
func logConfigWarnings(log *slog.Logger, cfg *Config) {
	if cfg == nil {
		return
	}
	for _, w := range cfg.Warnings() {
		log.Warn("configuration warning", "warning", w)
	}
}

// serve is the `signsrv serve` entry point. It runs until ctx is cancelled
// (SIGINT/SIGTERM are wired in main), then drains.
func serve(ctx context.Context, configPath string) int {
	cfg, err := LoadConfig(configPath)
	log := logger(cfg)
	if err != nil {
		log.Error("configuration", "error", err)
		if cfg != nil {
			for _, p := range cfg.Problems() {
				log.Error("configuration problem", "problem", p)
			}
		}
		return 1
	}
	logConfigWarnings(log, cfg)

	// First-start initialization, in the order the state depends on it: the
	// schema before anything that writes to it, the CA before anything that
	// signs with it, the admin account last because it is the only step an
	// operator may want to make by hand instead. On an instance that has run
	// before, every step is the same work `serve` already did, and the run is
	// three log lines that say so.
	signer, store, err := firstStartInit(ctx, cfg, log)
	if err != nil {
		log.Error("initialization", "error", err)
		return 1
	}
	defer store.Close()

	// The CA this run described is the CA the process signs with: the service
	// built above is handed to the server rather than loaded again there, so
	// the fingerprint in the log is the fingerprint of the key that signs the
	// next envelope, and the keystore is opened once per start.
	s := newServerWithSigner(cfg, log, store, signer)
	if s == nil {
		log.Error("server", "error", "the signing key could not be loaded")
		return 1
	}
	// The queues are part of the service, so the process that serves also
	// drains them. A deployment that wants the worker elsewhere sets
	// worker_interval to 0 and runs `signsrv worker` as its own unit.
	if cfg.WorkerInterval > 0 {
		w := newWorker(cfg, log, store)
		go w.run(ctx, cfg.WorkerInterval)
	}
	if err := s.run(ctx); err != nil {
		s.log.Error("serve", "error", err)
		return 1
	}
	return 0
}

// checkConfig is the `signsrv checkconfig` entry point. Secrets appear as
// digests only.
func checkConfig(configPath string) int {
	cfg, err := LoadConfig(configPath)
	if cfg != nil {
		// The redacted configuration is printed even when it is broken:
		// operators need to see what was actually loaded.
		printOut(cfg.Redacted())
		printOut("")
	}
	problems := []string{}
	if cfg != nil {
		problems = cfg.Problems()
	}
	if err != nil && len(problems) == 0 {
		problems = []string{err.Error()}
	}
	if len(problems) > 0 {
		for _, p := range problems {
			printOut("problem: " + p)
		}
		printOut("")
		printOut("config NOT usable")
		if cfg == nil {
			return 2 // the file could not be parsed at all
		}
		return 1
	}
	for _, w := range cfg.Warnings() {
		printOut("warning: " + w)
	}
	if len(cfg.Warnings()) > 0 {
		printOut("")
	}
	printOut("config ok")
	return 0
}

// logger builds the JSON logger. Records go to stdout and, when log_path is
// set, to that file as well (rotated by copytruncate, see deploy/).
func logger(cfg *Config) *slog.Logger {
	logPath, level := "", "info"
	if cfg != nil {
		logPath, level = cfg.LogPath, cfg.LogLevel
	}
	w := io.Writer(os.Stdout)
	if logPath != "" {
		if err := os.MkdirAll(filepath.Dir(logPath), 0o750); err == nil {
			if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640); err == nil {
				w = io.MultiWriter(os.Stdout, f)
			}
		}
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: slogLevel(level),
	})).With(slog.String("service", "signsrv"), slog.String("version", version))
}

// slogLevel maps a config level to a slog.Level.
func slogLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func printOut(s string) { _, _ = os.Stdout.WriteString(s + "\n") }

// workerCmd is `signsrv worker`: the queue drainer on its own, for a
// deployment that runs it as a second systemd unit so mail delivery and batch
// signing cannot stall the HTTP service. It exits when ctx is cancelled.
func workerCmd(ctx context.Context, configPath string) int {
	cfg, err := LoadConfig(configPath)
	log := logger(cfg)
	if err != nil {
		log.Error("configuration", "error", err)
		return 1
	}
	_, store, err := openStore(ctx, configPath)
	if err != nil {
		log.Error("database", "error", err)
		return 1
	}
	defer store.Close()

	interval := cfg.WorkerInterval
	if interval <= 0 {
		interval = 15 * time.Second
	}
	log.Info("worker starting", "interval", interval.String())
	newWorker(cfg, log, store).run(ctx, interval)
	return 0
}
