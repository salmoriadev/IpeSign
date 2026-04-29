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
		"iss":          jwksURL + "/auth/v1",
		"sub":          "user-123",
		"email":        "user@example.com",
		"role":         "authenticated",
		"exp":          now.Add(time.Hour).Unix(),
		"iat":          now.Unix(),
		"user_metadata": map[string]any{"full_name": "User Example"},
	})
	token.Header["kid"] = "test-key"

	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	service := NewService(Config{
		SupabaseURL: jwksURL,
		HTTPClient:  client,
		Clock:       func() time.Time { return now },
	})

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
	if session.DisplayName != "User Example" {
		t.Fatalf("session.DisplayName = %q", session.DisplayName)
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
