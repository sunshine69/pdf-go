package main

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sunshine69/pdf-go/internal/signauth"
)

// TestConfiguredLoginLimitIsHonoured is the point of the whole feature: the
// budget a deployment writes in its config file is the budget the route
// enforces, not the one compiled into the binary. Two attempts allowed, so
// the third is refused and the second is not.
func TestConfiguredLoginLimitIsHonoured(t *testing.T) {
	cfg := testConfig(t)
	cfg.SignLimits.Login = 2
	ts, _ := authServer(t, cfg)

	for i := 1; i <= 2; i++ {
		status, _ := post(t, ts, "/api/v1/auth/login",
			`{"email":"admin@example.test","password":"wrong-password-here"}`, "")
		if status == http.StatusTooManyRequests {
			t.Fatalf("attempt %d of 2 allowed: got 429", i)
		}
	}
	status, out := post(t, ts, "/api/v1/auth/login",
		`{"email":"admin@example.test","password":"wrong-password-here"}`, "")
	if status != http.StatusTooManyRequests {
		t.Fatalf("third attempt with login_limit=2: status %d, want 429", status)
	}
	if code := codeOf(t, out); code != "rate_limited" {
		t.Errorf("detail = %v, want rate_limited", code)
	}
}

// TestLoginLimitOffAnswersNo429: a negative value is the operator's switch
// for "do not throttle this route". Twenty attempts on a bucket configured to
// -1 must not include a 429, even though the built-in limit is five.
func TestLoginLimitOffAnswersNo429(t *testing.T) {
	cfg := testConfig(t)
	cfg.SignLimits.Login = -1
	ts, _ := authServer(t, cfg)

	for i := 1; i <= 20; i++ {
		status, _ := post(t, ts, "/api/v1/auth/login",
			`{"email":"admin@example.test","password":"wrong-password-here"}`, "")
		if status == http.StatusTooManyRequests {
			t.Fatalf("attempt %d on a disabled bucket: got 429", i)
		}
	}
}

// TestLimitWindowIsConfigurable checks the other half of the pair: a shorter
// window drains sooner, so a bucket that was full is open again inside the
// minute the built-in window would have held it shut. Normalise must not
// overwrite a window the operator did set.
func TestLimitWindowIsConfigurable(t *testing.T) {
	l := signauth.DefaultLimits()
	l.Login = 1
	l.Window = 40 * time.Millisecond
	if got := l.Normalise().Window; got != 40*time.Millisecond {
		t.Fatalf("Normalise overrode a set window: %v", got)
	}

	lim := signauth.NewLimiter()
	if ok, _ := lim.Allow("login:1.2.3.4", l.Login, l.Window); !ok {
		t.Fatal("first request refused on an empty bucket")
	}
	if ok, _ := lim.Allow("login:1.2.3.4", l.Login, l.Window); ok {
		t.Fatal("second request allowed on a bucket of one")
	}
	time.Sleep(60 * time.Millisecond)
	if ok, _ := lim.Allow("login:1.2.3.4", l.Login, l.Window); !ok {
		t.Fatal("bucket still full after its configured window drained")
	}
}

// TestLimitsDefaultWhenUnset is what keeps this change additive: a config with
// no rate_limit_ lines runs the limits it ran with before the keys existed,
// and one unset field in a partly configured set falls back to the default
// rather than to zero, which would have silently disabled that bucket.
func TestLimitsDefaultWhenUnset(t *testing.T) {
	if got := (signauth.Limits{}).Normalise(); got != signauth.DefaultLimits() {
		t.Errorf("zero Limits normalised to %+v, want the defaults", got)
	}

	cfg := testConfig(t)
	if got := cfg.SignLimits.Normalise(); got != signauth.DefaultLimits() {
		t.Errorf("test config limits = %+v, want the defaults", got)
	}

	cfg.SignLimits.Create = 3
	got := cfg.SignLimits.Normalise()
	if got.Create != 3 {
		t.Errorf("Create = %d, want the configured 3", got.Create)
	}
	if got.Login != signauth.LoginLimit {
		t.Errorf("Login = %d, want the default %d", got.Login, signauth.LoginLimit)
	}
}

// TestLoadConfigRateLimits reads the keys from a file, which is the interface
// an operator actually touches, and checks the two failure modes that matter:
// a value that is not a number is reported instead of quietly ignored, and an
// unknown key in the family is rejected, so a typo cannot look like a setting.
func TestLoadConfigRateLimits(t *testing.T) {
	p := checkConfigServer(t, goodBase+
		"rate_limit_login=9\nrate_limit_create=2\n"+
		"rate_limit_window=2m\nrate_limit_remind=-1\n", 0o600)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v\nproblems: %v", err, cfg.Problems())
	}
	l := cfg.SignLimits
	if l.Login != 9 || l.Create != 2 {
		t.Errorf("limits = login %d create %d, want 9 and 2", l.Login, l.Create)
	}
	if l.Window != 2*time.Minute {
		t.Errorf("window = %v, want 2m", l.Window)
	}
	if l.Normalise().Remind != -1 {
		t.Errorf("remind = %d, want -1 kept through Normalise", l.Normalise().Remind)
	}
	if l.Send != signauth.SendLimit {
		t.Errorf("send = %d, want the default %d", l.Send, signauth.SendLimit)
	}
	// The summary is what an operator reads to compare two instances, so a
	// disabled bucket has to be visible in it.
	if !strings.Contains(cfg.Redacted(), "remind=off") {
		t.Errorf("summary does not show the disabled remind bucket:\n%s", cfg.Redacted())
	}

	p = checkConfigServer(t, goodBase+"rate_limit_login=nine\n", 0o600)
	cfg, err = LoadConfig(p)
	if err == nil {
		t.Fatal("a non-numeric limit loaded without error")
	}
	if !strings.Contains(err.Error(), "rate_limit_login") {
		t.Errorf("error %q does not name the offending key", err)
	}

	p = checkConfigServer(t, goodBase+"rate_limit_loshin=9\n", 0o600)
	if _, err := LoadConfig(p); err == nil ||
		!strings.Contains(err.Error(), "rate_limit_loshin") {
		t.Fatalf("unknown key err = %v, want one naming rate_limit_loshin", err)
	}
}
