package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"ipesign/internal/core"
)

func TestSecurityHeadersAndSameOriginCORS(t *testing.T) {
	t.Setenv("IPESIGN_MASTER_KEY", "test-master-key")
	server, err := NewServer(Config{DataDir: filepath.Join(t.TempDir(), "data")})
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodGet, "https://ipesign.example/v1/health", nil)
	req.Host = "ipesign.example"
	req.Header.Set("Origin", "https://ipesign.example")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://ipesign.example" {
		t.Fatalf("same-origin CORS header = %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
	for name, expected := range map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	} {
		if actual := rec.Header().Get(name); actual != expected {
			t.Fatalf("%s = %q, want %q", name, actual, expected)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self' 'nonce-") || !strings.Contains(csp, "script-src-attr 'none'") || strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Fatalf("unexpected CSP: %s", csp)
	}

	evilReq := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	evilReq.Host = "ipesign.example"
	evilReq.Header.Set("Origin", "https://evil.example")
	evilRec := httptest.NewRecorder()
	handler.ServeHTTP(evilRec, evilReq)
	if evilRec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin status = %d", evilRec.Code)
	}

	downgradeReq := httptest.NewRequest(http.MethodGet, "https://ipesign.example/v1/health", nil)
	downgradeReq.Header.Set("Origin", "http://ipesign.example")
	downgradeRec := httptest.NewRecorder()
	handler.ServeHTTP(downgradeRec, downgradeReq)
	if downgradeRec.Code != http.StatusForbidden {
		t.Fatalf("cross-scheme status = %d", downgradeRec.Code)
	}
}

func TestIndexReceivesPerResponseCSPNonce(t *testing.T) {
	t.Setenv("IPESIGN_MASTER_KEY", "test-master-key")
	staticDir := t.TempDir()
	index := []byte(`<html><body><script nonce="{{CSP_NONCE}}"></script></body></html>`)
	if err := os.WriteFile(filepath.Join(staticDir, "index.html"), index, 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		StaticDir: staticDir,
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	match := regexp.MustCompile(`nonce="([A-Za-z0-9+/]+)"`).FindStringSubmatch(rec.Body.String())
	if len(match) != 2 {
		t.Fatalf("nonce missing from HTML: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "'nonce-"+match[1]+"'") {
		t.Fatalf("CSP and HTML nonces do not match")
	}
}

func TestUploadBodyLimitAndRateLimit(t *testing.T) {
	t.Setenv("IPESIGN_MASTER_KEY", "test-master-key")
	server, err := NewServer(Config{DataDir: filepath.Join(t.TempDir(), "data")})
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()

	oversizedPDF := append([]byte("%PDF-1.4\n"), bytes.Repeat([]byte("x"), core.MaxPDFSize+maxMultipartOverhead)...)
	body, contentType, err := multipartRequest(oversizedPDF, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/documents/verify", body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d body = %s", rec.Code, rec.Body.String())
	}

	for attempt := 1; attempt <= 6; attempt++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/documents/sign", strings.NewReader("invalid"))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=test")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if attempt == 6 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("rate-limited status = %d body = %s", rec.Code, rec.Body.String())
		}
	}
}
