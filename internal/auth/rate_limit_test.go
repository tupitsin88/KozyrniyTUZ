package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestSourceRateLimiterRefillsTokens(t *testing.T) {
	limiter := newSourceRateLimiter(2, time.Minute)
	now := time.Now()
	for range 2 {
		if allowed, _ := limiter.allow("192.0.2.1", now); !allowed {
			t.Fatal("request within bucket capacity was rejected")
		}
	}
	if allowed, retryAfter := limiter.allow("192.0.2.1", now); allowed || retryAfter <= 0 {
		t.Fatalf("over-limit request result = (%v, %s), want denial with retry delay", allowed, retryAfter)
	}
	if allowed, _ := limiter.allow("192.0.2.1", now.Add(30*time.Second)); !allowed {
		t.Fatal("request after one token refill was rejected")
	}
}

func TestSourceRateLimiterBoundsStoredSources(t *testing.T) {
	limiter := newSourceRateLimiter(1, time.Minute)
	limiter.maxEntries = 1
	now := time.Now()
	if allowed, _ := limiter.allow("192.0.2.1", now); !allowed {
		t.Fatal("initial source was rejected")
	}
	if allowed, _ := limiter.allow("192.0.2.2", now); allowed {
		t.Fatal("new source was accepted while limiter state was full")
	}
	if allowed, _ := limiter.allow("192.0.2.2", now.Add(11*time.Minute)); !allowed {
		t.Fatal("new source was rejected after stale state was removed")
	}
	if got := len(limiter.buckets); got != 1 {
		t.Fatalf("stored source count = %d, want 1", got)
	}
}

func TestRequestSourceIPTrustsForwardedChainOnlyFromConfiguredProxy(t *testing.T) {
	proxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	request := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	request.RemoteAddr = "203.0.113.8:4000"
	request.Header.Set("X-Forwarded-For", "198.51.100.9")
	if got := requestSourceIP(request, proxies); got != "203.0.113.8" {
		t.Fatalf("source IP = %q, want direct peer address", got)
	}

	request.RemoteAddr = "10.0.0.2:4000"
	request.Header.Set("X-Forwarded-For", "198.51.100.9, 10.0.0.1")
	if got := requestSourceIP(request, proxies); got != "198.51.100.9" {
		t.Fatalf("source IP = %q, want rightmost untrusted proxy address", got)
	}
}

func TestAuthenticationRateLimitReturnsRetryAfter(t *testing.T) {
	calls := 0
	limiter := newSourceRateLimiter(1, time.Minute)
	handler := limitAuthenticationRequests(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}), limiter, "login", "http://localhost:8080", nil)
	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader("{}"))
		req.RemoteAddr = "192.0.2.3:4321"
		req.Header.Set("Origin", "http://localhost:8080")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	if response := request(); response.Code != http.StatusNoContent {
		t.Fatalf("first status = %d, want 204", response.Code)
	}
	if response := request(); response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatalf("limited response = %d with Retry-After %q", response.Code, response.Header().Get("Retry-After"))
	}
	if calls != 1 {
		t.Fatalf("downstream handler calls = %d, want 1", calls)
	}
}

func TestAuthenticationRequestsWithUntrustedOriginDoNotConsumeBucket(t *testing.T) {
	limiter := newSourceRateLimiter(1, time.Minute)
	handler := limitAuthenticationRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasExactOrigin(r, "http://localhost:8080") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}), limiter, "login", "http://localhost:8080", nil)
	request := func(origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
		req.RemoteAddr = "192.0.2.4:4321"
		req.Header.Set("Origin", origin)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	if response := request("http://untrusted.example"); response.Code != http.StatusForbidden {
		t.Fatalf("untrusted-origin status = %d, want 403", response.Code)
	}
	if response := request("http://localhost:8080"); response.Code != http.StatusNoContent {
		t.Fatalf("trusted-origin status = %d, want 204", response.Code)
	}
}

func TestPasswordOperationLimitRejectsExcessWorkImmediately(t *testing.T) {
	service := &Service{passwordOperations: make(chan struct{}, 1)}
	service.passwordOperations <- struct{}{}
	_, err := service.hashPassword("not-used", argonParameters{memory: 19456, iterations: 2, parallel: 1})
	if !errors.Is(err, ErrAuthenticationCapacity) {
		t.Fatalf("hashPassword error = %v, want ErrAuthenticationCapacity", err)
	}
}
