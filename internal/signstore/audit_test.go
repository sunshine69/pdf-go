package signstore

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func auditSeed(t *testing.T, s *Store, ids []string) {
	t.Helper()
	ctx := context.Background()
	for i, id := range ids {
		env(t, s, id)
		if err := s.AddEvent(ctx, id, "admin", "created", `{"n":1}`); err != nil {
			t.Fatal(err)
		}
		if err := s.AddEvent(ctx, id, "system", "sent", `{"n":2}`); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err := s.AddEvent(ctx, id, "party", "consent", `{"sha":"aa"}`); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func auditLines(t *testing.T, dir, day string) []AuditLine {
	t.Helper()
	f, err := os.Open(AuditPath(dir, day))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []AuditLine
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var l AuditLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatal(err)
		}
		out = append(out, l)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// rewrite replaces a day's file with the given lines.
func rewrite(t *testing.T, dir, day string, lines []AuditLine) {
	t.Helper()
	out := make([]string, len(lines))
	for i, l := range lines {
		b, err := json.Marshal(l)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = string(b)
	}
	if err := os.WriteFile(AuditPath(dir, day),
		[]byte(strings.Join(out, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAuditWriteThenVerify(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	dir := t.TempDir()
	auditSeed(t, s, []string{"112233445566778899001122334455aa", "112233445566778899001122334455bb"})

	n, err := AuditWrite(ctx, s.DB(), dir, "2026-11-05")
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != 5 {
		t.Fatalf("events written = %d, want 5", n)
	}
	count, err := AuditVerify(s.DB(), dir)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if count != n {
		t.Fatalf("verified = %d, want %d", count, n)
	}
	lines := auditLines(t, dir, "2026-11-05")
	if lines[0].PrevHash != "" {
		t.Fatalf("first line prev_hash = %q, want empty", lines[0].PrevHash)
	}
	for i := 1; i < len(lines); i++ {
		if lines[i].PrevHash != lines[i-1].Hash {
			t.Fatalf("line %d prev_hash = %q, want %q", i, lines[i].PrevHash, lines[i-1].Hash)
		}
	}
}

func TestAuditWriteIsIdempotentAndAppends(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	dir := t.TempDir()
	auditSeed(t, s, []string{"112233445566778899001122334455aa"})

	n, err := AuditWrite(ctx, s.DB(), dir, "2026-11-05")
	if err != nil || n != 3 {
		t.Fatalf("first write: n=%d err=%v", n, err)
	}
	// Running again writes nothing: the position has moved past every event.
	n, err = AuditWrite(ctx, s.DB(), dir, "2026-11-05")
	if err != nil || n != 0 {
		t.Fatalf("second write: n=%d err=%v, want 0 nil", n, err)
	}
	// New events, a new day: the chain continues across the day boundary.
	if err := s.AddEvent(ctx, "112233445566778899001122334455aa", "system", "signed", `{"sha":"bb"}`); err != nil {
		t.Fatal(err)
	}
	n, err = AuditWrite(ctx, s.DB(), dir, "2026-11-06")
	if err != nil || n != 1 {
		t.Fatalf("next day write: n=%d err=%v", n, err)
	}
	first := auditLines(t, dir, "2026-11-05")
	second := auditLines(t, dir, "2026-11-06")
	if second[0].PrevHash != first[len(first)-1].Hash {
		t.Fatalf("day boundary: prev_hash = %q, want %q", second[0].PrevHash, first[len(first)-1].Hash)
	}
	count, err := AuditVerify(s.DB(), dir)
	if err != nil || count != 4 {
		t.Fatalf("verify across days: count=%d err=%v", count, err)
	}
}

// The three shapes of tampering an audit log is attacked with, each caught by a
// different half of the check.
func TestAuditVerifyCatchesTampering(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	dir := t.TempDir()
	day := "2026-11-05"
	auditSeed(t, s, []string{"112233445566778899001122334455aa", "112233445566778899001122334455bb"})
	if _, err := AuditWrite(ctx, s.DB(), dir, day); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		transform func(lines []AuditLine)
		want      string
	}{
		// A line edited in place: its own hash no longer matches.
		{"payload edited", func(l []AuditLine) { l[1].Payload = json.RawMessage(`{"n":99}`) },
			"hash"},
		{"actor edited", func(l []AuditLine) { l[2].Actor = "attacker" }, "hash"},
		// A line edited and rehashed: the chain stays internally consistent, so
		// the cross-check against the events table is what catches it.
		{"payload edited and rehashed", func(l []AuditLine) {
			l[1].Payload = json.RawMessage(`{"n":99}`)
			l[1].Hash = auditHash(&l[1])
		}, "events table"},
		// A line removed: the chain breaks at the line that moved up.
		{"line removed", func(l []AuditLine) {
			l[1] = l[2]
			l[2] = l[3]
			l[1].PrevHash = l[0].Hash
			l[1].Hash = auditHash(&l[1])
		}, "events missing"},
		// Lines swapped: ids are no longer increasing.
		{"lines swapped", func(l []AuditLine) {
			l[0], l[1] = l[1], l[0]
			l[0].PrevHash = ""
			l[0].Hash = auditHash(&l[0])
			l[1].PrevHash = l[0].Hash
			l[1].Hash = auditHash(&l[1])
		}, "events missing"},
	}
	for _, c := range cases {
		// Each case starts from a clean file: the directory is rebuilt from the
		// events table, which is the source of truth.
		os.RemoveAll(dir)
		dir = t.TempDir()
		if _, err := AuditWrite(ctx, s.DB(), dir, day); err != nil {
			t.Fatal(err)
		}
		lines := auditLines(t, dir, day)
		c.transform(lines)
		rewrite(t, dir, day, lines)
		_, err := AuditVerify(s.DB(), dir)
		if err == nil {
			t.Fatalf("%s: chain verified after tampering", c.name)
		}
		if !strings.Contains(err.Error(), day) {
			t.Fatalf("%s: error names no day: %v", c.name, err)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: error %q does not mention %q", c.name, err, c.want)
		}
	}
}

func TestAuditVerifyCatchesMissingEvents(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	dir := t.TempDir()
	day := "2026-11-05"
	auditSeed(t, s, []string{"112233445566778899001122334455aa"})
	if _, err := AuditWrite(ctx, s.DB(), dir, day); err != nil {
		t.Fatal(err)
	}
	// An event exists in the table that the log does not contain.
	if err := s.AddEvent(ctx, "112233445566778899001122334455aa", "system", "signed", `{"sha":"bb"}`); err != nil {
		t.Fatal(err)
	}
	_, err := AuditVerify(s.DB(), dir)
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing events must be reported: %v", err)
	}
	// Writing the missing events makes the log verify again.
	if _, err := AuditWrite(ctx, s.DB(), dir, "2026-11-06"); err != nil {
		t.Fatal(err)
	}
	count, err := AuditVerify(s.DB(), dir)
	if err != nil || count != 4 {
		t.Fatalf("after catching up: count=%d err=%v", count, err)
	}
}

func TestAuditWriteRefusesTamperedTail(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	dir := t.TempDir()
	day := "2026-11-05"
	auditSeed(t, s, []string{"112233445566778899001122334455aa"})
	if _, err := AuditWrite(ctx, s.DB(), dir, day); err != nil {
		t.Fatal(err)
	}
	lines := auditLines(t, dir, day)
	lines[len(lines)-1].Actor = "attacker"
	lines[len(lines)-1].Hash = auditHash(&lines[len(lines)-1])
	rewrite(t, dir, day, lines)
	_, err := AuditWrite(ctx, s.DB(), dir, "2026-11-06")
	if err == nil {
		t.Fatal("writing onto a tampered tail was accepted")
	}
	if !strings.Contains(err.Error(), "refusing to append") {
		t.Fatalf("error %q does not say it refused to append", err)
	}
}

// An empty day file leaves the chain where the last day that wrote anything
// left it. The writer's tail check has to look through the empty files: a
// tampered tail must not be extended because a later day happened to be empty.
func TestAuditWriteRefusesTamperedTailBehindEmptyDay(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	dir := t.TempDir()
	auditSeed(t, s, []string{"112233445566778899001122334455aa"})
	if _, err := AuditWrite(ctx, s.DB(), dir, "2026-11-05"); err != nil {
		t.Fatal(err)
	}
	// A day with no events: appended as an empty file.
	if n, err := AuditWrite(ctx, s.DB(), dir, "2026-11-06"); err != nil || n != 0 {
		t.Fatalf("empty day: n=%d err=%v", n, err)
	}
	lines := auditLines(t, dir, "2026-11-05")
	lines[len(lines)-1].Actor = "attacker"
	lines[len(lines)-1].Hash = auditHash(&lines[len(lines)-1])
	rewrite(t, dir, "2026-11-05", lines)
	_, err := AuditWrite(ctx, s.DB(), dir, "2026-11-07")
	if err == nil {
		t.Fatal("writing onto a tampered tail behind an empty day was accepted")
	}
	if !strings.Contains(err.Error(), "refusing to append") {
		t.Fatalf("error %q does not say tampered", err)
	}
}
func TestAuditWriteRefusesBackwardsDay(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	dir := t.TempDir()
	auditSeed(t, s, []string{"112233445566778899001122334455aa"})
	if _, err := AuditWrite(ctx, s.DB(), dir, "2026-11-06"); err != nil {
		t.Fatal(err)
	}
	if _, err := AuditWrite(ctx, s.DB(), dir, "2026-11-05"); err == nil {
		t.Fatal("writing a day before the last written day was accepted")
	}
}

func TestAuditVerifyEmptyDirIsFine(t *testing.T) {
	s := newTestStore(t)
	n, err := AuditVerify(s.DB(), filepath.Join(t.TempDir(), "nope"))
	if err != nil || n != 0 {
		t.Fatalf("empty dir: n=%d err=%v", n, err)
	}
}

func TestAuditFilesAreOwnerOnly(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	dir := t.TempDir()
	auditSeed(t, s, []string{"112233445566778899001122334455aa"})
	if _, err := AuditWrite(ctx, s.DB(), dir, "2026-11-05"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(AuditPath(dir, "2026-11-05"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("audit file mode = %o, want 600", fi.Mode().Perm())
	}
}
