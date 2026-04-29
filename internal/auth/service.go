package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const defaultJWKSCacheTTL = 10 * time.Minute

type Config struct {
	SupabaseURL       string
	SupabaseJWTSecret string
	HTTPClient        *http.Client
	Clock             func() time.Time
	JWKSCacheTTL      time.Duration
}

type Service struct {
	supabaseURL string
	issuer      string
	jwksURL     string
	jwtSecret   []byte
	httpClient  *http.Client
	clock       func() time.Time
	cacheTTL    time.Duration

	mu          sync.RWMutex
	cachedKeys  map[string]any
	cacheExpiry time.Time
}

type Session struct {
	UserID      string            `json:"userId"`
	Email       string            `json:"email,omitempty"`
	DisplayName string            `json:"displayName,omitempty"`
	Role        string            `json:"role,omitempty"`
	Claims      map[string]any    `json:"claims,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type jwksDocument struct {
	Keys []jsonWebKey `json:"keys"`
}

type jsonWebKey struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
	Y         string `json:"y"`
	N         string `json:"n"`
	E         string `json:"e"`
}

func NewService(cfg Config) *Service {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}

	cacheTTL := cfg.JWKSCacheTTL
	if cacheTTL <= 0 {
		cacheTTL = defaultJWKSCacheTTL
	}

	supabaseURL := strings.TrimRight(strings.TrimSpace(cfg.SupabaseURL), "/")
	issuer := ""
	jwksURL := ""
	if supabaseURL != "" {
		issuer = supabaseURL + "/auth/v1"
		jwksURL = issuer + "/.well-known/jwks.json"
	}

	return &Service{
		supabaseURL: supabaseURL,
		issuer:      issuer,
		jwksURL:     jwksURL,
		jwtSecret:   []byte(strings.TrimSpace(cfg.SupabaseJWTSecret)),
		httpClient:  client,
		clock:       clock,
		cacheTTL:    cacheTTL,
		cachedKeys:  map[string]any{},
	}
}

func (s *Service) Enabled() bool {
	return s.issuer != "" || len(s.jwtSecret) > 0
}

func (s *Service) SessionFromBearer(header string) (*Session, error) {
	tokenString := bearerToken(header)
	if tokenString == "" {
		return nil, fmt.Errorf("missing bearer token")
	}
	if !s.Enabled() {
		return nil, fmt.Errorf("supabase auth is not configured")
	}

	parserOptions := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256", "ES256", "HS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30 * time.Second),
		jwt.WithTimeFunc(s.clock),
	}
	if s.issuer != "" {
		parserOptions = append(parserOptions, jwt.WithIssuer(s.issuer))
	}
	parser := jwt.NewParser(parserOptions...)

	claims := jwt.MapClaims{}
	token, err := parser.ParseWithClaims(tokenString, claims, s.keyFunc)
	if err != nil {
		return nil, fmt.Errorf("invalid auth token")
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid auth token")
	}

	userID := firstNonEmpty(asString(claims["sub"]))
	if userID == "" {
		return nil, fmt.Errorf("invalid auth token")
	}

	email := firstNonEmpty(asString(claims["email"]))
	displayName := firstNonEmpty(
		asString(claims["name"]),
		asString(claims["full_name"]),
		asString(claims["display_name"]),
		asNestedString(claims["user_metadata"], "full_name"),
		asNestedString(claims["user_metadata"], "fullName"),
		asNestedString(claims["user_metadata"], "name"),
		asNestedString(claims["user_metadata"], "display_name"),
		asNestedString(claims["raw_user_meta_data"], "full_name"),
		asNestedString(claims["raw_user_meta_data"], "fullName"),
		asNestedString(claims["raw_user_meta_data"], "name"),
		asNestedString(claims["raw_user_meta_data"], "display_name"),
		email,
		userID,
	)

	return &Session{
		UserID:      userID,
		Email:       email,
		DisplayName: displayName,
		Role:        firstNonEmpty(asString(claims["role"]), "authenticated"),
		Claims:      claims,
		Metadata: map[string]string{
			"issuer": s.issuer,
		},
	}, nil
}

func (s *Service) keyFunc(token *jwt.Token) (any, error) {
	switch token.Method.Alg() {
	case jwt.SigningMethodHS256.Alg():
		if len(s.jwtSecret) == 0 {
			return nil, fmt.Errorf("missing jwt secret")
		}
		return s.jwtSecret, nil
	case jwt.SigningMethodRS256.Alg(), jwt.SigningMethodES256.Alg():
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("missing kid")
		}
		return s.lookupJWK(kid)
	default:
		return nil, fmt.Errorf("unsupported signing method")
	}
}

func (s *Service) lookupJWK(kid string) (any, error) {
	s.mu.RLock()
	if key, ok := s.cachedKeys[kid]; ok && s.clock().Before(s.cacheExpiry) {
		s.mu.RUnlock()
		return key, nil
	}
	s.mu.RUnlock()

	if err := s.refreshJWKS(context.Background()); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.cachedKeys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown kid")
	}
	return key, nil
}

func (s *Service) refreshJWKS(ctx context.Context) error {
	if s.jwksURL == "" {
		return fmt.Errorf("jwks url is not configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.jwksURL, nil)
	if err != nil {
		return err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks request failed with status %d", resp.StatusCode)
	}

	var doc jwksDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}

	keys := make(map[string]any, len(doc.Keys))
	for _, jwk := range doc.Keys {
		key, err := jwk.publicKey()
		if err != nil {
			return err
		}
		if jwk.KeyID != "" {
			keys[jwk.KeyID] = key
		}
	}

	s.mu.Lock()
	s.cachedKeys = keys
	s.cacheExpiry = s.clock().Add(s.cacheTTL)
	s.mu.Unlock()
	return nil
}

func (jwk jsonWebKey) publicKey() (any, error) {
	switch jwk.KeyType {
	case "RSA":
		nBytes, err := decodeBase64URL(jwk.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := decodeBase64URL(jwk.E)
		if err != nil {
			return nil, err
		}

		e := 0
		for _, b := range eBytes {
			e = (e << 8) | int(b)
		}
		if e == 0 {
			return nil, fmt.Errorf("invalid rsa exponent")
		}

		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: e,
		}, nil
	case "EC":
		if jwk.Curve != "P-256" {
			return nil, fmt.Errorf("unsupported ec curve")
		}

		xBytes, err := decodeBase64URL(jwk.X)
		if err != nil {
			return nil, err
		}
		yBytes, err := decodeBase64URL(jwk.Y)
		if err != nil {
			return nil, err
		}

		key := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}
		if !key.Curve.IsOnCurve(key.X, key.Y) {
			return nil, fmt.Errorf("invalid ec public key")
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported jwk type")
	}
}

func decodeBase64URL(value string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("empty jwk component")
	}
	return base64.RawURLEncoding.DecodeString(value)
}

func bearerToken(header string) string {
	trimmed := strings.TrimSpace(header)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(trimmed), "bearer ") {
		return strings.TrimSpace(trimmed[7:])
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	default:
		return ""
	}
}

func asNestedString(value any, key string) string {
	switch typed := value.(type) {
	case map[string]any:
		return asString(typed[key])
	case jwt.MapClaims:
		return asString(typed[key])
	default:
		return ""
	}
}
