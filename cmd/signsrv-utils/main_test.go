package main

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadDotEnv(t *testing.T) {
	cases := []struct {
		name string
		body string
		want map[string]string
	}{
		{
			name: "bare keys, as the deb package writes them",
			body: "listen=127.0.0.1:8080\ndb=/var/lib/signsrv/signsrv.db\n",
			want: map[string]string{"listen": "127.0.0.1:8080", "db": "/var/lib/signsrv/signsrv.db"},
		},
		{
			name: "upper-case keys, as systemd's EnvironmentFile writes them",
			body: "DB=/var/lib/signsrv/signsrv.db\nKEYSTORE_PASS=hunter2\n",
			want: map[string]string{"db": "/var/lib/signsrv/signsrv.db", "keystore_pass": "hunter2"},
		},
		{
			// This is the whole reason the reader is tolerant: a tool used while
			// the service is broken must not be broken by the same file.
			name: "unknown keys are ignored, not fatal",
			body: "db=/x/y.db\ntypo_addres=oops\nsomething_else=1\n",
			want: map[string]string{"db": "/x/y.db", "typo_addres": "oops", "something_else": "1"},
		},
		{
			name: "comments, blanks, and spaces around the key",
			body: "# comment\n\ndb = /x/y.db \n   # indented comment\n",
			want: map[string]string{"db": "/x/y.db"},
		},
		{
			name: "quotes stripped, since shell-style files have them",
			body: "db=\"/x/y.db\"\nother='a b'\n",
			want: map[string]string{"db": "/x/y.db", "other": "a b"},
		},
		{
			// The value may contain '=' — a password or a postgres DSN will.
			name: "value keeps everything after the first =",
			body: "db=postgres://u:p@h/db?sslmode=require\nadmin_pass=a=b=c\n",
			want: map[string]string{"db": "postgres://u:p@h/db?sslmode=require", "admin_pass": "a=b=c"},
		},
		{
			// Two spellings of the same key in one file is a genuine ambiguity.
			// First wins, so the file's own order is the order of intent.
			name: "first value wins on a duplicate key",
			body: "db=/first.db\ndb=/second.db\n",
			want: map[string]string{"db": "/first.db"},
		},
		{
			name: "a line with no = is skipped, not an error",
			body: "db=/x/y.db\njust-a-word\n",
			want: map[string]string{"db": "/x/y.db"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readDotEnv(write(t, "f.env", tc.body))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
			if len(got) != len(tc.want) {
				t.Errorf("got %d keys (%v), want %d (%v)", len(got), got, len(tc.want), tc.want)
			}
		})
	}
}

// A missing config file yields no keys and no error: resolveDB is the place
// that decides whether that is a problem, so the decision is made once.
func TestReadDotEnvMissingFile(t *testing.T) {
	got, err := readDotEnv(filepath.Join(t.TempDir(), "absent.env"))
	if err != nil {
		t.Fatalf("missing file should not error, got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

func TestResolveDB(t *testing.T) {
	dbPath := write(t, "signsrv.db", "not really sqlite")

	t.Run("-db wins over everything", func(t *testing.T) {
		cfg := write(t, "c.env", "db=/from/config.db\n")
		got, src, err := resolveDB(dbPath, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if got != dbPath || src != "-db" {
			t.Fatalf("got %q from %q", got, src)
		}
	})

	t.Run("$DB wins over the config file", func(t *testing.T) {
		cfg := write(t, "c.env", "db=/from/config.db\n")
		t.Setenv("DB", dbPath)
		got, src, err := resolveDB("", cfg)
		if err != nil {
			t.Fatal(err)
		}
		if got != dbPath || src != "$DB" {
			t.Fatalf("got %q from %q", got, src)
		}
	})

	t.Run("config file is the fallback", func(t *testing.T) {
		cfg := write(t, "c.env", "db="+dbPath+"\n")
		got, src, err := resolveDB("", cfg)
		if err != nil {
			t.Fatal(err)
		}
		if got != dbPath || src != cfg {
			t.Fatalf("got %q from %q, want %q", got, src, cfg)
		}
	})

	t.Run("db_path alias is accepted", func(t *testing.T) {
		cfg := write(t, "c.env", "db_path="+dbPath+"\n")
		got, _, err := resolveDB("", cfg)
		if err != nil || got != dbPath {
			t.Fatalf("got %q, err %v", got, err)
		}
	})

	t.Run("-prefixed db key is accepted", func(t *testing.T) {
		cfg := write(t, "c.env", "DB="+dbPath+"\n")
		got, _, err := resolveDB("", cfg)
		if err != nil || got != dbPath {
			t.Fatalf("got %q, err %v", got, err)
		}
	})

	t.Run("no db key is an error that names the file", func(t *testing.T) {
		cfg := write(t, "c.env", "listen=127.0.0.1:8080\n")
		_, _, err := resolveDB("", cfg)
		if err == nil {
			t.Fatal("want an error when the file has no db setting")
		}
	})

	// The tool must not invent a location for a database. Guessing a default
	// and then writing an admin into it is how an installation ends up with two.
	t.Run("no default path is invented", func(t *testing.T) {
		cfg := filepath.Join(t.TempDir(), "absent.env")
		_, _, err := resolveDB("", cfg)
		if err == nil {
			t.Fatal("want an error when neither config nor env names a database")
		}
	})

	t.Run("CONFIG points at the file", func(t *testing.T) {
		cfg := write(t, "c.env", "db="+dbPath+"\n")
		t.Setenv("CONFIG", cfg)
		got, src, err := resolveDB("", "")
		if err != nil {
			t.Fatal(err)
		}
		if got != dbPath || src != cfg {
			t.Fatalf("got %q from %q", got, src)
		}
	})

	// An explicit -config must beat the environment, or a script cannot override
	// a container's inherited CONFIG.
	t.Run("-flag beats $CONFIG", func(t *testing.T) {
		flagged := write(t, "flagged.env", "db="+dbPath+"\n")
		write(t, "ignored.env", "db=/ignored.db\n")
		t.Setenv("CONFIG", filepath.Join(filepath.Dir(flagged), "ignored.env"))
		got, _, err := resolveDB("", flagged)
		if err != nil || got != dbPath {
			t.Fatalf("got %q, err %v", got, err)
		}
	})
}

func TestTrimLine(t *testing.T) {
	for _, in := range []string{"pw\n", "pw\r\n", "  pw  \n", "pw"} {
		if got := trimLine(in); got != "pw" {
			t.Errorf("trimLine(%q) = %q", in, got)
		}
	}
}
