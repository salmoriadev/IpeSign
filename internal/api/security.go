package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type nonceContextKey struct{}

type tokenBucket struct {
	mu            sync.Mutex
	tokens        float64
	burst         float64
	refillPerNano float64
	last          time.Time
}

func newTokenBucket(perMinute float64, burst int) *tokenBucket {
	return &tokenBucket{
		tokens:        float64(burst),
		burst:         float64(burst),
		refillPerNano: perMinute / 60 / float64(time.Second),
		last:          time.Now(),
	}
}

func (limiter *tokenBucket) Allow() bool {
	if limiter == nil {
		return true
	}

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	now := time.Now()
	elapsed := float64(now.Sub(limiter.last))
	limiter.tokens = min(limiter.burst, limiter.tokens+(elapsed*limiter.refillPerNano))
	limiter.last = now
	if limiter.tokens < 1 {
		return false
	}
	limiter.tokens--
	return true
}

func (s *Server) rateLimit(limiter *tokenBucket, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodOptions && !limiter.Allow() {
			w.Header().Set("Retry-After", "2")
			writeError(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func parseAllowedOrigins(raw string) (map[string]struct{}, error) {
	origins := make(map[string]struct{})
	for _, candidate := range strings.Split(raw, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || candidate == "*" {
			continue
		}
		parsed, err := url.Parse(candidate)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
			return nil, fmt.Errorf("invalid CORS origin %q", candidate)
		}
		origins[parsed.Scheme+"://"+parsed.Host] = struct{}{}
	}
	return origins, nil
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" {
			if !s.originAllowed(origin, r) {
				writeError(w, http.StatusForbidden, "cross-origin request denied")
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Add("Vary", "Origin")
		}

		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) originAllowed(origin string, r *http.Request) bool {
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return false
	}
	if strings.EqualFold(parsed.Host, r.Host) && parsed.Scheme == requestScheme(r) {
		return true
	}
	_, allowed := s.allowedOrigins[parsed.Scheme+"://"+parsed.Host]
	return allowed
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	forwarded := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]))
	if forwarded == "http" || forwarded == "https" {
		return forwarded
	}
	return "http"
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonceBytes := make([]byte, 18)
		if _, err := rand.Read(nonceBytes); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to initialize response security")
			return
		}
		nonce := base64.RawStdEncoding.EncodeToString(nonceBytes)

		w.Header().Set("Content-Security-Policy", strings.Join([]string{
			"default-src 'self'",
			"base-uri 'none'",
			"object-src 'none'",
			"frame-src 'none'",
			"frame-ancestors 'none'",
			"form-action 'self'",
			"script-src 'self' 'nonce-" + nonce + "'",
			"script-src-attr 'none'",
			"style-src 'self' 'nonce-" + nonce + "'",
			"style-src-attr 'unsafe-inline'",
			"img-src 'self' blob: data:",
			"font-src 'self'",
			"media-src 'none'",
			"connect-src 'self'",
			"worker-src 'self' blob:",
		}, "; "))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=(), payment=(), usb=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Origin-Agent-Cluster", "?1")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		if requestScheme(r) == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			w.Header().Set("Cache-Control", "no-store")
		}

		ctx := context.WithValue(r.Context(), nonceContextKey{}, nonce)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func responseNonce(ctx context.Context) string {
	nonce, _ := ctx.Value(nonceContextKey{}).(string)
	return nonce
}
