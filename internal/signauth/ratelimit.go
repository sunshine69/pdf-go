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

// Rate limits of the service, as the overview specifies them.
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
)

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

// Reset forgets every counter. It is for tests and for the admin endpoint
// that clears a limiter after a load test.
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
