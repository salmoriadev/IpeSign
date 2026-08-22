package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestServiceSessionFromBearerWithJWKS(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	jwksURL := "https://example.supabase.co"
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != jwksURL+"/auth/v1/.well-known/jwks.json" {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(strings.NewReader("not found")),
					Header:     make(http.Header),
				}, nil
			}

			body, _ := json.Marshal(map[string]any{
				"keys": []map[string]string{
					{
						"kty": "EC",
						"kid": "test-key",
						"alg": "ES256",
						"crv": "P-256",
						"x":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes()),
						"y":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes()),
					},
				},
			})

			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	now := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":           jwksURL + "/auth/v1",
		"aud":           "authenticated",
		"sub":           "user-123",
		"email":         "user@example.com",
		"role":          "authenticated",
		"exp":           now.Add(time.Hour).Unix(),
		"iat":           now.Unix(),
		"app_metadata":  map[string]any{"full_name": "Trusted Example"},
		"user_metadata": map[string]any{"full_name": "User Example"},
	})
	token.Header["kid"] = "test-key"

	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	service, err := NewService(Config{
		SupabaseURL: jwksURL,
		HTTPClient:  client,
		Clock:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	session, err := service.SessionFromBearer("Bearer " + signed)
	if err != nil {
		t.Fatalf("SessionFromBearer() error = %v", err)
	}

	if session.UserID != "user-123" {
		t.Fatalf("session.UserID = %q", session.UserID)
	}
	if session.Email != "user@example.com" {
		t.Fatalf("session.Email = %q", session.Email)
	}
	if session.DisplayName != "Trusted Example" {
		t.Fatalf("session.DisplayName = %q", session.DisplayName)
	}
	if session.ProfileName != "User Example" {
		t.Fatalf("session.ProfileName = %q", session.ProfileName)
	}
}

func TestUserMetadataDoesNotBecomeTrustedDisplayName(t *testing.T) {
	now := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":           "https://example.supabase.co/auth/v1",
		"aud":           "authenticated",
		"sub":           "user-123",
		"email":         "user@example.com",
		"role":          "authenticated",
		"exp":           now.Add(time.Hour).Unix(),
		"iat":           now.Unix(),
		"user_metadata": map[string]any{"full_name": "Attacker Controlled"},
	})
	signed, err := token.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatal(err)
	}

	service, err := NewService(Config{
		SupabaseURL:       "https://example.supabase.co",
		SupabaseJWTSecret: "test-secret",
		Clock:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := service.SessionFromBearer("Bearer " + signed)
	if err != nil {
		t.Fatal(err)
	}
	if session.DisplayName != "user@example.com" {
		t.Fatalf("trusted display name = %q", session.DisplayName)
	}
	if session.ProfileName != "Attacker Controlled" {
		t.Fatalf("profile name = %q", session.ProfileName)
	}
}

func TestSessionRejectsWrongAudienceAndRole(t *testing.T) {
	now := time.Now().UTC()
	service, err := NewService(Config{
		SupabaseURL:       "https://example.supabase.co",
		SupabaseJWTSecret: "test-secret",
		Clock:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		aud  string
		role string
	}{
		{name: "wrong audience", aud: "anon", role: "authenticated"},
		{name: "wrong role", aud: "authenticated", role: "service_role"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"iss":  "https://example.supabase.co/auth/v1",
				"aud":  test.aud,
				"sub":  "user-123",
				"role": test.role,
				"exp":  now.Add(time.Hour).Unix(),
				"iat":  now.Unix(),
			})
			signed, err := token.SignedString([]byte("test-secret"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.SessionFromToken(signed); err == nil {
				t.Fatal("untrusted token was accepted")
			}
		})
	}
}

func TestServiceRejectsNonHTTPSSupabaseURL(t *testing.T) {
	if _, err := NewService(Config{SupabaseURL: "http://example.supabase.co"}); err == nil {
		t.Fatal("non-HTTPS Supabase URL was accepted")
	}
}

func TestSessionRejectsOversizedToken(t *testing.T) {
	service, err := NewService(Config{SupabaseJWTSecret: "test-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SessionFromToken(strings.Repeat("x", maxTokenBytes+1)); err == nil {
		t.Fatal("oversized token was accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestJSONWebKeyPublicKeyRSA(t *testing.T) {
	jwk := jsonWebKey{
		KeyType: "RSA",
		N:       base64.RawURLEncoding.EncodeToString(big.NewInt(3233).Bytes()),
		E:       base64.RawURLEncoding.EncodeToString(big.NewInt(17).Bytes()),
	}

	key, err := jwk.publicKey()
	if err != nil {
		t.Fatalf("publicKey() error = %v", err)
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("publicKey() type = %T", key)
	}
	if rsaKey.E != 17 || rsaKey.N.Cmp(big.NewInt(3233)) != 0 {
		t.Fatalf("rsa key mismatch")
	}
}
