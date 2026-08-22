package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestLoginUsesHTTPOnlyCookiesWithoutReturningTokens(t *testing.T) {
	t.Setenv("IPESIGN_MASTER_KEY", "test-master-key")
	const jwtSecret = "test-supabase-secret"
	const providerURL = "https://example.supabase.co"

	providerClient := &http.Client{Transport: authRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/auth/v1/token" || r.URL.Query().Get("grant_type") != "password" {
			return nil, fmt.Errorf("unexpected auth request: %s", r.URL.String())
		}
		now := time.Now().UTC()
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss":           providerURL + "/auth/v1",
			"aud":           "authenticated",
			"sub":           "user-123",
			"email":         "user@example.com",
			"role":          "authenticated",
			"exp":           now.Add(time.Hour).Unix(),
			"iat":           now.Unix(),
			"user_metadata": map[string]any{"full_name": "User Example", "ipe_address": "ipe.example"},
		})
		signed, err := token.SignedString([]byte(jwtSecret))
		if err != nil {
			return nil, err
		}
		var body bytes.Buffer
		if err := json.NewEncoder(&body).Encode(map[string]any{
			"access_token":  signed,
			"refresh_token": "refresh-value",
			"expires_in":    3600,
		}); err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(&body),
			Request:    r,
		}, nil
	})}

	server, err := NewServer(Config{
		DataDir:                filepath.Join(t.TempDir(), "data"),
		SupabaseURL:            providerURL,
		SupabaseJWTSecret:      jwtSecret,
		SupabasePublishableKey: "publishable-key",
		AuthHTTPClient:         providerClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()

	loginBody := bytes.NewBufferString(`{"email":"user@example.com","password":"correct horse battery staple"}`)
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", loginBody)
	loginReq.Host = "ipesign.example"
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	handler.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login status = %d body = %s", loginRec.Code, loginRec.Body.String())
	}
	if strings.Contains(loginRec.Body.String(), "access_token") || strings.Contains(loginRec.Body.String(), "refresh-value") {
		t.Fatalf("login response exposed a token: %s", loginRec.Body.String())
	}

	cookies := loginRec.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookies = %d, want 2", len(cookies))
	}
	for _, cookie := range cookies {
		if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
			t.Fatalf("insecure cookie: %#v", cookie)
		}
	}

	meReq := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	meReq.Host = "ipesign.example"
	for _, cookie := range cookies {
		meReq.AddCookie(cookie)
	}
	meRec := httptest.NewRecorder()
	handler.ServeHTTP(meRec, meReq)
	if meRec.Code != http.StatusOK {
		t.Fatalf("me status = %d body = %s", meRec.Code, meRec.Body.String())
	}
	var session struct {
		Email       string `json:"email"`
		ProfileName string `json:"profileName"`
		IpeAddress  string `json:"ipeAddress"`
	}
	if err := json.Unmarshal(meRec.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session.Email != "user@example.com" || session.ProfileName != "User Example" || session.IpeAddress != "ipe.example" {
		t.Fatalf("session = %#v", session)
	}
}

type authRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn authRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
