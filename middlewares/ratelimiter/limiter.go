package ratelimiter

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type GauthLimiter struct {
	store     map[string]*Request
	mu        *sync.RWMutex
	timeFrame time.Duration
	tokens    uint64
	cancel    chan struct{}
}

type Request struct {
	LastReq time.Time
	Tokens  uint64
	Timeout bool
}

func (r *Request) Allow() bool {
	return r.Tokens == 0
}

func generateID(r *http.Request) string {
	ua := r.UserAgent()

	if xfHeader := r.Header.Get("X-Forwarded-For"); xfHeader != "" {
		ips := strings.TrimSpace(strings.SplitN(xfHeader, ",", 2)[0])
		return ips + ua
	}

	ips := r.RemoteAddr
	if idx := strings.Index(ips, ":"); idx != -1 {
		return ips[:idx]
	}

	return ips + ua
}

func (l *GauthLimiter) Cleanup(timeInactive, checkInterval time.Duration) {
	ticker := time.NewTicker(checkInterval)

	for {
		select {
		case <-l.cancel:
			return
		case <-ticker.C:

			for k, v := range l.store {
				if time.Now().After(v.LastReq.Add(timeInactive)) {
					l.mu.Lock()
					delete(l.store, k)
					l.mu.Unlock()

				}
			}
		}
	}
}

func NewGauthLimiter(tokens uint64, timeFrame, timeInactive, checkInterval time.Duration) *GauthLimiter {
	l := &GauthLimiter{
		store:     map[string]*Request{},
		mu:        &sync.RWMutex{},
		timeFrame: timeFrame,
		tokens:    tokens,
		cancel:    make(chan struct{}),
	}
	go l.Cleanup(timeInactive, checkInterval)
	return l
}

func (l *GauthLimiter) Shutdown() {
	l.cancel <- struct{}{}
}

func (l *GauthLimiter) RateLimiter(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := generateID(r)
		l.mu.RLock()
		defer l.mu.RUnlock()

		req, ok := l.store[id]
		if !ok {
			req = &Request{
				LastReq: time.Now(),
				Tokens:  l.tokens - 1,
				Timeout: false,
			}
			l.store[id] = req
			next.ServeHTTP(w, r)
			return
		}

		if req.Timeout {
			if time.Now().After(req.LastReq.Add(l.timeFrame)) {
				req.Timeout = false
				req.Tokens = l.tokens - 1
				req.LastReq = time.Now()
				next.ServeHTTP(w, r)
				return
			} else {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(l.timeFrame.Seconds())))
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
		}

		if req.Tokens == 0 {
			req.Timeout = true
			req.LastReq = time.Now()
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(l.timeFrame.Seconds())))
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		req.Tokens--
		req.LastReq = time.Now()
		next.ServeHTTP(w, r)
	})
}
