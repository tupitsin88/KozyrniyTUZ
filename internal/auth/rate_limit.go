package auth

import (
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxRateLimitEntries = 16384

type sourceBucket struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

type sourceRateLimiter struct {
	mu              sync.Mutex
	buckets         map[string]sourceBucket
	capacity        float64
	refillPerSecond float64
	maxEntries      int
	checks          uint64
}

func newSourceRateLimiter(capacity int, refillPeriod time.Duration) *sourceRateLimiter {
	if capacity < 1 || refillPeriod <= 0 {
		panic("invalid source rate limiter settings")
	}
	return &sourceRateLimiter{
		buckets:         make(map[string]sourceBucket),
		capacity:        float64(capacity),
		refillPerSecond: float64(capacity) / refillPeriod.Seconds(),
		maxEntries:      maxRateLimitEntries,
	}
}

func (limiter *sourceRateLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	limiter.checks++
	if limiter.checks%256 == 0 {
		limiter.removeStale(now)
	}
	bucket, exists := limiter.buckets[key]
	if !exists {
		if len(limiter.buckets) >= limiter.maxEntries {
			limiter.removeStale(now)
			if len(limiter.buckets) >= limiter.maxEntries {
				return false, time.Minute
			}
		}
		bucket = sourceBucket{tokens: limiter.capacity, updated: now}
	}
	if now.After(bucket.updated) {
		bucket.tokens = math.Min(limiter.capacity, bucket.tokens+now.Sub(bucket.updated).Seconds()*limiter.refillPerSecond)
		bucket.updated = now
	}
	bucket.lastSeen = now
	if bucket.tokens < 1 {
		limiter.buckets[key] = bucket
		return false, time.Duration(math.Ceil((1 - bucket.tokens) / limiter.refillPerSecond * float64(time.Second)))
	}
	bucket.tokens--
	limiter.buckets[key] = bucket
	return true, 0
}

func (limiter *sourceRateLimiter) removeStale(now time.Time) {
	cutoff := now.Add(-10 * time.Minute)
	for key, bucket := range limiter.buckets {
		if bucket.lastSeen.Before(cutoff) {
			delete(limiter.buckets, key)
		}
	}
}

func limitAuthenticationRequests(next http.Handler, limiter *sourceRateLimiter, key, trustedOrigin string, trustedProxies []netip.Prefix) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !hasExactOrigin(r, trustedOrigin) {
			next.ServeHTTP(w, r)
			return
		}
		allowed, retryAfter := limiter.allow(key+"|"+requestSourceIP(r, trustedProxies), time.Now())
		if !allowed {
			seconds := int(math.Ceil(retryAfter.Seconds()))
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			writeError(w, http.StatusTooManyRequests, "too many authentication requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requestSourceIP(r *http.Request, trustedProxies []netip.Prefix) string {
	peer, ok := parseRemoteIP(r.RemoteAddr)
	if !ok {
		return "unknown"
	}
	if !ipInPrefixes(peer, trustedProxies) {
		return peer.String()
	}
	forwarded := r.Header.Values("X-Forwarded-For")
	if len(forwarded) != 1 {
		return peer.String()
	}
	for _, entry := range reverseSplit(forwarded[0]) {
		candidate, err := netip.ParseAddr(strings.TrimSpace(entry))
		if err != nil {
			return peer.String()
		}
		peer = candidate.Unmap()
		if !ipInPrefixes(peer, trustedProxies) {
			return peer.String()
		}
	}
	return peer.String()
}

func reverseSplit(value string) []string {
	entries := strings.Split(value, ",")
	for left, right := 0, len(entries)-1; left < right; left, right = left+1, right-1 {
		entries[left], entries[right] = entries[right], entries[left]
	}
	return entries
}

func parseRemoteIP(remoteAddress string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = remoteAddress
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

func ipInPrefixes(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
