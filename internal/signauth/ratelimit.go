package signauth

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Rate limits. In-memory and per process: the service runs one instance, and
// a network-level limiter in front of it is a deployment detail, not a
// reason to skip the application-level one. The limits live here because the
// routes that need them are the routes that cost something: a login attempt
// runs argon2id, a claim touches the database, a consent is irreversible.
//
// Sliding window, not a token bucket. The cost being smoothed is a CPU burst
// per source address, and a window that counts the requests of the last
// minute is the shape of that cost.

// Default limits of the service, as the overview specifies them. A deployment
// that does not configure anything gets exactly these; the Limits struct below
// carries them to the routes, and the config file overrides any of them.
const (
	LoginLimit   = 5 // attempts per minute per address
	ClaimLimit   = 10
	ConsentLimit = 10 // per envelope, keyed by envelope id, not by address
	LinkLimit    = 60 // link opens per minute per address

	// CreateLimit is the per-minute budget of the create endpoint. A create
	// runs a fill, a certification signature, and a TSA request, so it is the
	// most expensive authenticated call in the service. 20/min is enough for
	// a working office and small enough that a script cannot fill the
	// storage directory.
	CreateLimit = 20

	// SendLimit is the per-minute budget of the send endpoint. A send writes a
	// queue row per party and, when a sender is configured, renders and sends
	// each message. It is cheaper than a create and more expensive than a read,
	// so it gets its own bucket: a client that spam-sends cannot exhaust the
	// create budget.
	//
	// Since send became the repeatable mailing action, this bucket is also the
	// only thing standing between an insistent operator and a party's inbox. A
	// second send while the first is still queued is free — the queue holds at
	// most one unsent row per party per kind, so extra clicks add nothing. A
	// second send after the first has gone out is genuinely another message,
	// which is what the button is for. The tight guard against a mail cannon is
	// RemindLimit below, which still rides the remind route.
	SendLimit = 30

	// APILimit is the generic ceiling for an authenticated caller on a route
	// that costs no more than a read. The expensive routes get their own
	// buckets above so their cost is limited on its own terms.
	APILimit = 600

	// MailTestLimit is the per-minute budget of the admin mail-test route. Six
	// is enough for an operator checking a new SMTP relay and not enough to
	// turn the service into someone's mail cannon from the settings page.
	MailTestLimit = 6
	// RemindLimit is the budget of the remind endpoint, counted per envelope
	// on a ten-minute window rather than the standard one: two reminders an
	// envelope per ten minutes is enough to nudge a slow signer and not enough
	// to turn the service into someone's mail cannon.
	RemindLimit = 2

	// RemindWindow is the window RemindLimit counts on. It is the only limit
	// in the service that does not use Window, which is why the remind route
	// is wired through RateLimitWindow.
	RemindWindow = 10 * time.Minute
)

// Limits is the set of budgets one deployment runs with. Every field is in
// requests per Window, except Remind and RemindWindow which are a pair.
//
// The routes read this struct instead of the constants above, which is what
// makes a limit a configuration item rather than a recompile. The zero value
// is not usable — call DefaultLimits, or Normalise on a partly filled struct.
//
// A limit of zero or less disables that bucket: Allow reports every request
// inside the limit. That is deliberate — an operator who sets login_limit=0
// means "do not throttle login", and the argon2 cost of a flood is then a
// capacity question for the host, not an application rule.
type Limits struct {
	Login        int
	Claim        int
	Consent      int
	Link         int
	Create       int
	Send         int
	API          int
	Remind       int
	MailTest     int
	Window       time.Duration
	RemindWindow time.Duration
}

// DefaultLimits is what the service ran with before any of this was
// configurable, spelled out as a value so the constants stay the single
// source of truth and callers have a struct to copy into.
func DefaultLimits() Limits {
	return Limits{
		Login:        LoginLimit,
		Claim:        ClaimLimit,
		Consent:      ConsentLimit,
		Link:         LinkLimit,
		Create:       CreateLimit,
		Send:         SendLimit,
		API:          APILimit,
		Remind:       RemindLimit,
		MailTest:     MailTestLimit,
		Window:       Window,
		RemindWindow: RemindWindow,
	}
}

// Normalise fills in any zero field with the default, leaving a negative
// value alone because that is the operator's "off" switch.
func (l Limits) Normalise() Limits {
	d := DefaultLimits()
	// Plain assignments rather than a loop over addresses: Normalise runs on
	// the request path, and taking the address of a field of a value receiver
	// makes the copy escape to the heap.
	l.Login = orDefault(l.Login, d.Login)
	l.Claim = orDefault(l.Claim, d.Claim)
	l.Consent = orDefault(l.Consent, d.Consent)
	l.Link = orDefault(l.Link, d.Link)
	l.Create = orDefault(l.Create, d.Create)
	l.Send = orDefault(l.Send, d.Send)
	l.API = orDefault(l.API, d.API)
	l.Remind = orDefault(l.Remind, d.Remind)
	l.MailTest = orDefault(l.MailTest, d.MailTest)
	if l.Window == 0 {
		l.Window = d.Window
	}
	if l.RemindWindow == 0 {
		l.RemindWindow = d.RemindWindow
	}
	return l
}

// orDefault fills an unset limit with the default and leaves anything else
// alone. Negative survives because that is the "switch this bucket off"
// spelling; zero is reserved for "the operator did not mention this one".
func orDefault(got, want int) int {
	if got == 0 {
		return want
	}
	return got
}

// Window is the span a limiter counts.
const Window = time.Minute

// Limiter is a sliding window counter keyed by a caller-built string,
// normally "<route>:<ip>". It is safe for concurrent use.
type Limiter struct {
	mu        sync.Mutex
	hits      map[string][]time.Time
	lastSwept time.Time
}

// NewLimiter returns an empty limiter.
func NewLimiter() *Limiter {
	return &Limiter{hits: map[string][]time.Time{}}
}

// Allow records a hit for key and reports whether it is inside the limit. When
// it reports false, the second value is how long the caller must wait, which
// becomes the Retry-After header.
func (l *Limiter) Allow(key string, limit int, window time.Duration) (bool, time.Duration) {
	if limit <= 0 {
		return true, 0
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweep(now, window)

	stamp := l.hits[key]
	kept := stamp[:0]
	for _, t := range stamp {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= limit {
		l.hits[key] = kept
		// The oldest hit in the window is the first slot that will free up.
		return false, window - now.Sub(kept[0]) + time.Second
	}
	kept = append(kept, now)
	l.hits[key] = kept
	return true, 0
}

// sweep drops the keys whose window has fully drained, so a long-running
// process does not accumulate an entry per address ever seen.
func (l *Limiter) sweep(now time.Time, window time.Duration) {
	if now.Sub(l.lastSwept) < window {
		return
	}
	l.lastSwept = now
	for key, stamp := range l.hits {
		var live []time.Time
		for _, t := range stamp {
			if now.Sub(t) < window {
				live = append(live, t)
			}
		}
		if len(live) == 0 {
			delete(l.hits, key)
			continue
		}
		l.hits[key] = live
	}
}

// Reset forgets every counter. Nothing calls it in the service today: a
// restart clears the counters as well, and the counters are per process
// anyway. It stays because a load test needs to hand a limiter back clean.
func (l *Limiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits = map[string][]time.Time{}
}

// ClientIP is the address the limiter counts. X-Forwarded-For is honoured only
// when the deployment says a proxy is in front, because a client that can set
// the header can choose the bucket it is rate limited in.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			// The left-most address is the client; the ones appended by the
			// proxies trail it.
			first, _, _ := strings.Cut(fwd, ",")
			if ip := strings.TrimSpace(first); ip != "" {
				return ip
			}
		}
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
