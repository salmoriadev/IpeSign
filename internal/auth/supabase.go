package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxAuthResponseBytes = 1 << 20

type TokenSet struct {
	AccessToken  string          `json:"access_token"`
	RefreshToken string          `json:"refresh_token"`
	ExpiresIn    int             `json:"expires_in"`
	User         json.RawMessage `json:"user,omitempty"`
}

type SignupResult struct {
	TokenSet
	RequiresEmailConfirmation bool
}

type RequestError struct {
	StatusCode int
	Message    string
}

func (e *RequestError) Error() string {
	return e.Message
}

func (s *Service) SignInWithPassword(ctx context.Context, email, password string) (*TokenSet, error) {
	var result TokenSet
	err := s.request(ctx, http.MethodPost, "/auth/v1/token?grant_type=password", map[string]any{
		"email":    strings.TrimSpace(email),
		"password": password,
	}, "", &result)
	if err != nil {
		return nil, err
	}
	if !completeTokenSet(&result) {
		return nil, fmt.Errorf("supabase returned an incomplete session")
	}
	return &result, nil
}

func (s *Service) SignUp(ctx context.Context, name, email, password, ipeAddress string) (*SignupResult, error) {
	metadata := map[string]string{
		"full_name":   strings.TrimSpace(name),
		"ipe_address": strings.TrimSpace(ipeAddress),
	}
	var result TokenSet
	err := s.request(ctx, http.MethodPost, "/auth/v1/signup", map[string]any{
		"email":    strings.TrimSpace(email),
		"password": password,
		"data":     metadata,
	}, "", &result)
	if err != nil {
		return nil, err
	}
	if result.AccessToken != "" && !completeTokenSet(&result) {
		return nil, fmt.Errorf("supabase returned an incomplete session")
	}
	return &SignupResult{
		TokenSet:                  result,
		RequiresEmailConfirmation: result.AccessToken == "",
	}, nil
}

func (s *Service) RefreshSession(ctx context.Context, refreshToken string) (*TokenSet, error) {
	if strings.TrimSpace(refreshToken) == "" || len(refreshToken) > maxTokenBytes {
		return nil, fmt.Errorf("missing refresh token")
	}
	var result TokenSet
	err := s.request(ctx, http.MethodPost, "/auth/v1/token?grant_type=refresh_token", map[string]string{
		"refresh_token": refreshToken,
	}, "", &result)
	if err != nil {
		return nil, err
	}
	if !completeTokenSet(&result) {
		return nil, fmt.Errorf("supabase returned an incomplete refreshed session")
	}
	return &result, nil
}

func (s *Service) Logout(ctx context.Context, accessToken string) error {
	if strings.TrimSpace(accessToken) == "" {
		return nil
	}
	if len(accessToken) > maxTokenBytes {
		return fmt.Errorf("invalid access token")
	}
	return s.request(ctx, http.MethodPost, "/auth/v1/logout", nil, accessToken, nil)
}

func completeTokenSet(tokens *TokenSet) bool {
	return tokens != nil &&
		tokens.AccessToken != "" && len(tokens.AccessToken) <= maxTokenBytes &&
		tokens.RefreshToken != "" && len(tokens.RefreshToken) <= maxTokenBytes
}

func (s *Service) request(ctx context.Context, method, path string, payload any, accessToken string, destination any) error {
	if !s.PasswordAuthEnabled() {
		return fmt.Errorf("supabase password auth is not configured")
	}

	baseURL, err := url.Parse(s.supabaseURL)
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" {
		return fmt.Errorf("invalid supabase URL")
	}
	endpoint, err := baseURL.Parse(path)
	if err != nil || endpoint.Host != baseURL.Host {
		return fmt.Errorf("invalid supabase auth endpoint")
	}

	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode supabase auth request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return fmt.Errorf("create supabase auth request: %w", err)
	}
	req.Header.Set("apikey", s.publishableKey)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("supabase auth is unavailable")
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, maxAuthResponseBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read supabase auth response: %w", err)
	}
	if len(raw) > maxAuthResponseBytes {
		return fmt.Errorf("supabase auth response is too large")
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return decodeRequestError(resp.StatusCode, raw)
	}
	if destination == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return fmt.Errorf("decode supabase auth response: %w", err)
	}
	return nil
}

func decodeRequestError(statusCode int, raw []byte) error {
	var payload struct {
		Error            string `json:"error"`
		Message          string `json:"msg"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(raw, &payload)
	message := firstNonEmpty(payload.ErrorDescription, payload.Message, payload.Error)
	if message == "" || len(message) > 240 {
		message = "supabase authentication request failed"
	}
	return &RequestError{StatusCode: statusCode, Message: message}
}
