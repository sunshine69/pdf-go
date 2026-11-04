package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

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
	// The server needs the database open: the auth layer resolves every
	// credential against it, and the worker drains the queues from it.
	_, store, err := openStore(ctx, configPath)
	if err != nil {
		log.Error("database", "error", err)
		return 1
	}
	defer store.Close()

	s := newServer(cfg, log, store)
	if s == nil {
		log.Error("server", "error", "the signing key could not be loaded")
		return 1
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
