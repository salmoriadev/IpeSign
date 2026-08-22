package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"ipesign/internal/auth"
	"ipesign/internal/core"
)

type Config struct {
	DataDir                string
	DatabaseURL            string
	MasterKey              string
	SupabaseURL            string
	SupabaseJWTSecret      string
	SupabasePublishableKey string
	AllowedOrigin          string
	StaticDir              string
	AuthHTTPClient         *http.Client
}

type SignResult = core.SignResult
type VerifyResult = core.VerifyResult
type RecordResult = core.RecordResult

type Server struct {
	service        *core.Service
	auth           *auth.Service
	allowedOrigins map[string]struct{}
	staticDir      string
	signLimiter    *tokenBucket
	verifyLimiter  *tokenBucket
	authLimiter    *tokenBucket
}

func NewServer(cfg Config) (*Server, error) {
	allowedOrigins, err := parseAllowedOrigins(cfg.AllowedOrigin)
	if err != nil {
		return nil, err
	}
	service, err := core.NewService(core.Config{
		DataDir:     cfg.DataDir,
		DatabaseURL: cfg.DatabaseURL,
		MasterKey:   cfg.MasterKey,
	})
	if err != nil {
		return nil, err
	}
	authService, err := auth.NewService(auth.Config{
		SupabaseURL:            cfg.SupabaseURL,
		SupabaseJWTSecret:      cfg.SupabaseJWTSecret,
		SupabasePublishableKey: cfg.SupabasePublishableKey,
		HTTPClient:             cfg.AuthHTTPClient,
	})
	if err != nil {
		return nil, err
	}

	return &Server{
		service:        service,
		auth:           authService,
		allowedOrigins: allowedOrigins,
		staticDir:      firstNonEmpty(cfg.StaticDir, "./apps/web/public"),
		signLimiter:    newTokenBucket(30, 5),
		verifyLimiter:  newTokenBucket(120, 10),
		authLimiter:    newTokenBucket(30, 5),
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// API Routes
	mux.HandleFunc("/v1/auth/config", s.handleAuthConfig)
	mux.Handle("/v1/auth/login", s.rateLimit(s.authLimiter, http.HandlerFunc(s.handleAuthLogin)))
	mux.Handle("/v1/auth/signup", s.rateLimit(s.authLimiter, http.HandlerFunc(s.handleAuthSignup)))
	mux.Handle("/v1/auth/logout", s.rateLimit(s.authLimiter, http.HandlerFunc(s.handleAuthLogout)))
	mux.Handle("/v1/auth/me", s.rateLimit(s.authLimiter, http.HandlerFunc(s.handleAuthMe)))
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/ca", s.handleCA)
	mux.Handle("/v1/sign", s.rateLimit(s.signLimiter, http.HandlerFunc(s.handleSign)))
	mux.Handle("/v1/documents/sign", s.rateLimit(s.signLimiter, http.HandlerFunc(s.handleSign)))
	mux.Handle("/v1/verify", s.rateLimit(s.verifyLimiter, http.HandlerFunc(s.handleVerify)))
	mux.Handle("/v1/documents/verify", s.rateLimit(s.verifyLimiter, http.HandlerFunc(s.handleVerify)))
	mux.HandleFunc("/v1/chain/walk", s.handleWalk)
	mux.HandleFunc("/v1/chain/verify", s.handleChainVerify)
	mux.HandleFunc("/v1/records/", s.handleRecord)

	mux.Handle("/", s.staticHandler())

	return s.securityHeaders(s.cors(mux))
}

func (s *Server) SignPDF(pdfBytes []byte, filename string, policyID string, identity core.SignerIdentity) ([]byte, *SignResult, error) {
	return s.service.SignPDF(pdfBytes, filename, policyID, identity)
}

func (s *Server) VerifyEmbeddedPDF(signedPdfBytes []byte) (*VerifyResult, error) {
	return s.service.VerifyEmbeddedPDF(signedPdfBytes)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	result, err := s.service.Health()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, s.service.CAInfo())
}

func (s *Server) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"authEnabled": s.auth.PasswordAuthEnabled(),
	})
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var identity core.SignerIdentity
	var err error
	if s.auth.Enabled() {
		// Reject unauthenticated requests before reading a potentially large body.
		identity, err = s.signerIdentityFromRequest(w, r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or expired session")
			return
		}
	}

	pdfBytes, filename, policyID, err := readPDFUpload(w, r)
	if err != nil {
		writeUploadError(w, err)
		return
	}

	if !s.auth.Enabled() {
		identity, err = s.signerIdentityFromRequest(w, r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid signer identity")
			return
		}
	}

	signedPdfBytes, _, err := s.service.SignPDF(pdfBytes, filename, policyID, identity)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/pdf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(signedPdfBytes)
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	pdfBytes, _, _, err := readPDFUpload(w, r)
	if err != nil {
		writeUploadError(w, err)
		return
	}

	result, err := s.service.VerifyEmbeddedPDF(pdfBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleWalk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	result, err := s.service.Walk(strings.ToLower(r.URL.Query().Get("direction")))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleChainVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	report, err := s.service.VerifyChain()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	recordID := strings.TrimPrefix(r.URL.Path, "/v1/records/")
	recordID = strings.TrimSpace(recordID)
	if recordID == "" {
		writeError(w, http.StatusBadRequest, "record id is required")
		return
	}

	record, err := s.service.GetRecord(recordID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, record)
}

const maxMultipartOverhead = 1 << 20

var errUploadTooLarge = errors.New("request body exceeds the upload limit")

func readPDFUpload(w http.ResponseWriter, r *http.Request) ([]byte, string, string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, core.MaxPDFSize+maxMultipartOverhead)
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return nil, "", "", errUploadTooLarge
		}
		return nil, "", "", fmt.Errorf("parse multipart form: %w", err)
	}
	defer r.MultipartForm.RemoveAll()

	if len(r.MultipartForm.File) != 1 || len(r.MultipartForm.File["pdf"]) != 1 {
		return nil, "", "", fmt.Errorf("exactly one pdf file is required")
	}

	file, header, err := r.FormFile("pdf")
	if err != nil {
		return nil, "", "", fmt.Errorf("pdf file is required")
	}
	defer file.Close()

	pdfBytes, err := io.ReadAll(io.LimitReader(file, core.MaxPDFSize+1))
	if err != nil {
		return nil, "", "", fmt.Errorf("read pdf: %w", err)
	}

	if err := core.ValidatePDFBytes(pdfBytes); err != nil {
		return nil, "", "", err
	}

	policyID := r.FormValue("policy_id")
	if policyID == "" {
		policyID = core.DefaultPolicyID
	}
	if len(policyID) > 128 {
		return nil, "", "", fmt.Errorf("policy id is too long")
	}

	filename := filepath.Base(strings.TrimSpace(header.Filename))
	if filename == "." || filename == "" {
		filename = "document.pdf"
	}
	return pdfBytes, filename, policyID, nil
}

func (s *Server) signerIdentityFromRequest(w http.ResponseWriter, r *http.Request) (core.SignerIdentity, error) {
	if s.auth.Enabled() {
		session, err := s.sessionFromRequest(w, r)
		if err != nil {
			return core.SignerIdentity{}, err
		}

		// Certificate identity is derived only from verified claims. Profile fields
		// and multipart values are presentation data and must not override it.
		return core.SignerIdentity{
			CommonName:   firstNonEmpty(session.Email, session.UserID),
			EmailAddress: session.Email,
		}, nil
	}

	return core.SignerIdentity{
		CommonName:         strings.TrimSpace(r.FormValue("common_name")),
		EmailAddress:       strings.TrimSpace(r.FormValue("email_address")),
		Organization:       strings.TrimSpace(r.FormValue("organization")),
		OrganizationalUnit: strings.TrimSpace(r.FormValue("organizational_unit")),
		Country:            strings.TrimSpace(r.FormValue("country")),
		Province:           strings.TrimSpace(r.FormValue("province")),
		Locality:           strings.TrimSpace(r.FormValue("locality")),
	}, nil
}

func writeUploadError(w http.ResponseWriter, err error) {
	if errors.Is(err, errUploadTooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"error": message,
	})
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
