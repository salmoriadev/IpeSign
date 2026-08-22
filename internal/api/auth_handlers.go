package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"ipesign/internal/auth"
)

const (
	accessCookieName  = "ipesign_access"
	refreshCookieName = "ipesign_refresh"
	maxAuthBodyBytes  = 16 << 10
	refreshCookieTTL  = 30 * 24 * time.Hour
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type signupRequest struct {
	Name       string `json:"name"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	IpeAddress string `json:"ipeAddress"`
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.auth.PasswordAuthEnabled() {
		writeError(w, http.StatusNotImplemented, "supabase password auth is not configured")
		return
	}

	var input loginRequest
	if err := decodeJSONBody(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !validEmail(input.Email) || input.Password == "" || len(input.Password) > 1024 {
		writeError(w, http.StatusBadRequest, "valid email and password are required")
		return
	}

	tokens, err := s.auth.SignInWithPassword(r.Context(), input.Email, input.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	session, err := s.auth.SessionFromToken(tokens.AccessToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid session returned by authentication provider")
		return
	}

	setSessionCookies(w, r, tokens)
	writeJSON(w, http.StatusOK, session)
}

func (s *Server) handleAuthSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.auth.PasswordAuthEnabled() {
		writeError(w, http.StatusNotImplemented, "supabase password auth is not configured")
		return
	}

	var input signupRequest
	if err := decodeJSONBody(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	input.IpeAddress = strings.TrimSpace(input.IpeAddress)
	if len(input.Name) < 2 || len(input.Name) > 128 {
		writeError(w, http.StatusBadRequest, "name must contain between 2 and 128 characters")
		return
	}
	if !validEmail(input.Email) || len(input.Email) > 320 {
		writeError(w, http.StatusBadRequest, "a valid email is required")
		return
	}
	if len(input.Password) < 8 || len(input.Password) > 1024 {
		writeError(w, http.StatusBadRequest, "password must contain at least 8 characters")
		return
	}
	if len(input.IpeAddress) > 128 {
		writeError(w, http.StatusBadRequest, "Ipe address is too long")
		return
	}

	result, err := s.auth.SignUp(r.Context(), input.Name, input.Email, input.Password, input.IpeAddress)
	if err != nil {
		var requestErr *auth.RequestError
		if errors.As(err, &requestErr) && requestErr.StatusCode >= 400 && requestErr.StatusCode < 500 {
			writeError(w, http.StatusBadRequest, requestErr.Message)
			return
		}
		writeError(w, http.StatusBadGateway, "authentication provider is unavailable")
		return
	}

	if result.RequiresEmailConfirmation {
		writeJSON(w, http.StatusAccepted, map[string]any{
			"requiresEmailConfirmation": true,
		})
		return
	}

	session, err := s.auth.SessionFromToken(result.AccessToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid session returned by authentication provider")
		return
	}
	setSessionCookies(w, r, &result.TokenSet)
	writeJSON(w, http.StatusCreated, session)
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	accessToken, _ := requestAccessToken(r)
	clearSessionCookies(w, r)
	if accessToken != "" {
		_ = s.auth.Logout(r.Context(), accessToken)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.auth.Enabled() {
		writeError(w, http.StatusNotImplemented, "supabase auth is not configured")
		return
	}

	session, err := s.sessionFromRequest(w, r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired session")
		return
	}
	writeJSON(w, http.StatusOK, session)
}

func (s *Server) sessionFromRequest(w http.ResponseWriter, r *http.Request) (*auth.Session, error) {
	accessToken, bearer := requestAccessToken(r)
	if accessToken != "" {
		session, err := s.auth.SessionFromToken(accessToken)
		if err == nil || bearer {
			return session, err
		}
	}

	refreshCookie, err := r.Cookie(refreshCookieName)
	if err != nil || strings.TrimSpace(refreshCookie.Value) == "" {
		return nil, fmt.Errorf("session is missing")
	}
	tokens, err := s.auth.RefreshSession(r.Context(), refreshCookie.Value)
	if err != nil {
		clearSessionCookies(w, r)
		return nil, fmt.Errorf("session refresh failed")
	}
	session, err := s.auth.SessionFromToken(tokens.AccessToken)
	if err != nil {
		clearSessionCookies(w, r)
		return nil, err
	}
	setSessionCookies(w, r, tokens)
	return session, nil
}

func requestAccessToken(r *http.Request) (string, bool) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(authorization) > 7 && strings.EqualFold(authorization[:7], "bearer ") {
		return strings.TrimSpace(authorization[7:]), true
	}
	cookie, err := r.Cookie(accessCookieName)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(cookie.Value), false
}

func setSessionCookies(w http.ResponseWriter, r *http.Request, tokens *auth.TokenSet) {
	accessTTL := time.Duration(tokens.ExpiresIn) * time.Second
	if accessTTL <= 0 || accessTTL > 24*time.Hour {
		accessTTL = time.Hour
	}
	setAuthCookie(w, r, accessCookieName, tokens.AccessToken, accessTTL)
	setAuthCookie(w, r, refreshCookieName, tokens.RefreshToken, refreshCookieTTL)
}

func clearSessionCookies(w http.ResponseWriter, r *http.Request) {
	setAuthCookie(w, r, accessCookieName, "", -time.Hour)
	setAuthCookie(w, r, refreshCookieName, "", -time.Hour)
}

func setAuthCookie(w http.ResponseWriter, r *http.Request, name, value string, ttl time.Duration) {
	maxAge := int(ttl.Seconds())
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secureCookieForHost(r.Host),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	}
	if ttl > 0 {
		cookie.Expires = time.Now().Add(ttl).UTC()
	} else {
		cookie.Expires = time.Unix(1, 0).UTC()
	}
	http.SetCookie(w, cookie)
}

func secureCookieForHost(hostPort string) bool {
	host := hostPort
	if parsedHost, _, err := net.SplitHostPort(hostPort); err == nil {
		host = parsedHost
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return fmt.Errorf("request body is too large")
		}
		return fmt.Errorf("invalid JSON request")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("request body must contain one JSON object")
	}
	return nil
}

func validEmail(value string) bool {
	value = strings.TrimSpace(value)
	parsed, err := mail.ParseAddress(value)
	return err == nil && strings.EqualFold(parsed.Address, value)
}
