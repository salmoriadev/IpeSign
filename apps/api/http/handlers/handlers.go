package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	coreapi "ipesign/internal/api"
)

const maxPDFSize = 20 << 20

type API struct {
	server *coreapi.Server
}

func New(server *coreapi.Server) *API {
	return &API{server: server}
}

func (h *API) Health(w http.ResponseWriter, r *http.Request) {
	result, err := h.server.Health()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *API) CA(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.server.CA())
}

func (h *API) Sign(w http.ResponseWriter, r *http.Request) {
	pdfBytes, filename, err := readPDFUpload(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	result, err := h.server.SignPDF(pdfBytes, filename, r.FormValue("policy_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *API) Verify(w http.ResponseWriter, r *http.Request) {
	pdfBytes, _, err := readPDFUpload(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	result, err := h.server.VerifyPDF(pdfBytes, r.FormValue("certificate_pem"), r.FormValue("signature_base64"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *API) Record(w http.ResponseWriter, r *http.Request) {
	result, err := h.server.GetRecord(r.PathValue("recordId"))
	if errors.Is(err, coreapi.ErrRecordNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *API) ChainWalk(w http.ResponseWriter, r *http.Request) {
	result, err := h.server.ChainWalk(r.URL.Query().Get("direction"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *API) ChainVerify(w http.ResponseWriter, r *http.Request) {
	result, err := h.server.ChainVerify()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func readPDFUpload(r *http.Request) ([]byte, string, error) {
	if err := r.ParseMultipartForm(maxPDFSize); err != nil {
		return nil, "", fmt.Errorf("parse multipart form: %w", err)
	}

	file, header, err := r.FormFile("pdf")
	if err != nil {
		return nil, "", fmt.Errorf("pdf file is required")
	}
	defer file.Close()

	pdfBytes, err := io.ReadAll(io.LimitReader(file, maxPDFSize+1))
	if err != nil {
		return nil, "", fmt.Errorf("read pdf: %w", err)
	}

	if len(pdfBytes) == 0 {
		return nil, "", fmt.Errorf("pdf is empty")
	}

	if len(pdfBytes) > maxPDFSize {
		return nil, "", fmt.Errorf("pdf exceeds 20MB limit")
	}

	return pdfBytes, header.Filename, nil
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
