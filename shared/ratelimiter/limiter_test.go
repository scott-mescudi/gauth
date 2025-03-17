package ratelimiter

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func createRequest(method, url string) *http.Request {
	req, _ := http.NewRequest(method, url, nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	return req
}

func TestBasicRateLimiting(t *testing.T) {
	limiter := NewGauthLimiter(2, time.Second*2, time.Second*5, time.Second)
	defer limiter.Shutdown()

	handler := limiter.RateLimiter(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// First request, should be allowed
	req1 := createRequest("GET", "/test")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Fatalf("expected status %d but got %d", http.StatusOK, rr1.Code)
	}

	// Second request, should be allowed
	req2 := createRequest("GET", "/test")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Fatalf("expected status %d but got %d", http.StatusOK, rr2.Code)
	}

	// Third request, should be rate-limited (status 429)
	req3 := createRequest("GET", "/test")
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)

	if rr3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected status %d but got %d", http.StatusTooManyRequests, rr3.Code)
	}
}

func TestRateLimitingTimeout(t *testing.T) {
	limiter := NewGauthLimiter(2, time.Second*2, time.Second*5, time.Second)
	defer limiter.Shutdown()

	handler := limiter.RateLimiter(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req1 := createRequest("GET", "/test")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	req2 := createRequest("GET", "/test")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	req3 := createRequest("GET", "/test")
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)

	if rr3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected status %d but got %d", http.StatusTooManyRequests, rr3.Code)
	}

	time.Sleep(2 * time.Second)

	req4 := createRequest("GET", "/test")
	rr4 := httptest.NewRecorder()
	handler.ServeHTTP(rr4, req4)

	if rr4.Code != http.StatusOK {
		t.Fatalf("expected status %d but got %d", http.StatusOK, rr4.Code)
	}
}

func TestCleanup(t *testing.T) {
	limiter := NewGauthLimiter(2, time.Second*2, time.Second*5, time.Second)
	defer limiter.Shutdown()

	handler := limiter.RateLimiter(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req1 := createRequest("GET", "/test")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	time.Sleep(6 * time.Second)

	req2 := createRequest("GET", "/test")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Fatalf("expected status %d but got %d", http.StatusOK, rr2.Code)
	}
}
