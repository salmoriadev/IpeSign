package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"ipesign/internal/auth"
	"ipesign/internal/core"
)

type Config struct {
	DataDir            string
	DatabaseURL        string
	MasterKey          string
	SupabaseURL        string
	SupabaseJWTSecret  string
	AllowedOrigin      string
}

type SignResult = core.SignResult
type VerifyResult = core.VerifyResult
type RecordResult = core.RecordResult

type Server struct {
	service *core.Service
	auth    *auth.Service
	allowedOrigin string
}

func NewServer(cfg Config) (*Server, error) {
	service, err := core.NewService(core.Config{
		DataDir:     cfg.DataDir,
		DatabaseURL: cfg.DatabaseURL,
		MasterKey:   cfg.MasterKey,
	})
	if err != nil {
		return nil, err
	}

	return &Server{
		service: service,
		auth: auth.NewService(auth.Config{
			SupabaseURL:       cfg.SupabaseURL,
			SupabaseJWTSecret: cfg.SupabaseJWTSecret,
		}),
		allowedOrigin: firstNonEmpty(cfg.AllowedOrigin, "*"),
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// API Routes
	mux.HandleFunc("/v1/auth/me", s.handleAuthMe)
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/ca", s.handleCA)
	mux.HandleFunc("/v1/sign", s.handleSign)
	mux.HandleFunc("/v1/documents/sign", s.handleSign)
	mux.HandleFunc("/v1/verify", s.handleVerify)
	mux.HandleFunc("/v1/documents/verify", s.handleVerify)
	mux.HandleFunc("/v1/chain/walk", s.handleWalk)
	mux.HandleFunc("/v1/chain/verify", s.handleChainVerify)
	mux.HandleFunc("/v1/records/", s.handleRecord)

	// Serve Static Files for Web UI
	fileServer := http.FileServer(http.Dir("./apps/web/public"))
	mux.Handle("/", fileServer)

	// CORS Middleware
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", s.allowedOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		mux.ServeHTTP(w, r)
	})
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

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.auth.Enabled() {
		writeError(w, http.StatusNotImplemented, "supabase auth is not configured")
		return
	}

	session, err := s.auth.SessionFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, session)
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	pdfBytes, filename, policyID, err := readPDFUpload(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	identity, err := s.signerIdentityFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
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

	pdfBytes, _, _, err := readPDFUpload(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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

func readPDFUpload(r *http.Request) ([]byte, string, string, error) {
	if err := r.ParseMultipartForm(core.MaxPDFSize); err != nil {
		return nil, "", "", fmt.Errorf("parse multipart form: %w", err)
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

	return pdfBytes, header.Filename, policyID, nil
}

func (s *Server) signerIdentityFromRequest(r *http.Request) (core.SignerIdentity, error) {
	identity := core.SignerIdentity{
		CommonName:         strings.TrimSpace(r.FormValue("common_name")),
		EmailAddress:       strings.TrimSpace(r.FormValue("email_address")),
		Organization:       strings.TrimSpace(r.FormValue("organization")),
		OrganizationalUnit: strings.TrimSpace(r.FormValue("organizational_unit")),
		Country:            strings.TrimSpace(r.FormValue("country")),
		Province:           strings.TrimSpace(r.FormValue("province")),
		Locality:           strings.TrimSpace(r.FormValue("locality")),
	}

	if !s.auth.Enabled() {
		return identity, nil
	}

	session, err := s.auth.SessionFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		return core.SignerIdentity{}, err
	}

	identity.CommonName = firstNonEmpty(identity.CommonName, session.DisplayName, session.Email, session.UserID)
	identity.EmailAddress = firstNonEmpty(identity.EmailAddress, session.Email)
	return identity, nil
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
