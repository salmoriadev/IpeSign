package api

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestServerSignsAndVerifiesPDF(t *testing.T) {
	server, err := NewServer(Config{
		DataDir: filepath.Join(t.TempDir(), "data"),
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	handler := server.Handler()
	pdf := []byte("%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF")

	signBody, signContentType, err := multipartRequest(pdf, map[string]string{
		"policy_id": "participation-v1",
	})
	if err != nil {
		t.Fatalf("multipartRequest(sign) error = %v", err)
	}

	signReq := httptest.NewRequest(http.MethodPost, "/v1/sign", signBody)
	signReq.Header.Set("Content-Type", signContentType)
	signRec := httptest.NewRecorder()
	handler.ServeHTTP(signRec, signReq)

	if signRec.Code != http.StatusOK {
		t.Fatalf("sign status = %d body = %s", signRec.Code, signRec.Body.String())
	}

	var signResp struct {
		DocumentHash    string `json:"documentHash"`
		SignatureBase64 string `json:"signatureBase64"`
		CertificatePEM  string `json:"certificatePem"`
		RecordID        string `json:"recordId"`
	}
	if err := json.Unmarshal(signRec.Body.Bytes(), &signResp); err != nil {
		t.Fatalf("decode sign response: %v", err)
	}

	if signResp.DocumentHash == "" || signResp.SignatureBase64 == "" || signResp.CertificatePEM == "" || signResp.RecordID == "" {
		t.Fatalf("sign response missing fields: %s", signRec.Body.String())
	}

	verifyBody, verifyContentType, err := multipartRequest(pdf, map[string]string{
		"certificate_pem":  signResp.CertificatePEM,
		"signature_base64": signResp.SignatureBase64,
	})
	if err != nil {
		t.Fatalf("multipartRequest(verify) error = %v", err)
	}

	verifyReq := httptest.NewRequest(http.MethodPost, "/v1/verify", verifyBody)
	verifyReq.Header.Set("Content-Type", verifyContentType)
	verifyRec := httptest.NewRecorder()
	handler.ServeHTTP(verifyRec, verifyReq)

	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify status = %d body = %s", verifyRec.Code, verifyRec.Body.String())
	}

	var verifyResp struct {
		Valid              bool   `json:"valid"`
		LedgerRecordValid  bool   `json:"ledgerRecordValid"`
		SingleUseConfirmed bool   `json:"singleUseConfirmed"`
		RecordID           string `json:"recordId"`
	}
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}

	if !verifyResp.Valid || !verifyResp.LedgerRecordValid || !verifyResp.SingleUseConfirmed {
		t.Fatalf("verify response invalid: %s", verifyRec.Body.String())
	}

	if verifyResp.RecordID != signResp.RecordID {
		t.Fatalf("record id = %q, want %q", verifyResp.RecordID, signResp.RecordID)
	}
}

func TestServerPersistsAuthorityAndChain(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")

	firstServer, err := NewServer(Config{DataDir: dataDir})
	if err != nil {
		t.Fatalf("NewServer(first) error = %v", err)
	}

	handler := firstServer.Handler()
	pdf := []byte("%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF")

	signBody, signContentType, err := multipartRequest(pdf, map[string]string{
		"policy_id": "participation-v1",
	})
	if err != nil {
		t.Fatalf("multipartRequest(sign) error = %v", err)
	}

	signReq := httptest.NewRequest(http.MethodPost, "/v1/sign", signBody)
	signReq.Header.Set("Content-Type", signContentType)
	signRec := httptest.NewRecorder()
	handler.ServeHTTP(signRec, signReq)
	if signRec.Code != http.StatusOK {
		t.Fatalf("sign status = %d body = %s", signRec.Code, signRec.Body.String())
	}

	var signResp struct {
		SignatureBase64 string `json:"signatureBase64"`
		CertificatePEM  string `json:"certificatePem"`
		RecordID        string `json:"recordId"`
	}
	if err := json.Unmarshal(signRec.Body.Bytes(), &signResp); err != nil {
		t.Fatalf("decode sign response: %v", err)
	}

	secondServer, err := NewServer(Config{DataDir: dataDir})
	if err != nil {
		t.Fatalf("NewServer(second) error = %v", err)
	}

	verifyBody, verifyContentType, err := multipartRequest(pdf, map[string]string{
		"certificate_pem":  signResp.CertificatePEM,
		"signature_base64": signResp.SignatureBase64,
	})
	if err != nil {
		t.Fatalf("multipartRequest(verify) error = %v", err)
	}

	verifyReq := httptest.NewRequest(http.MethodPost, "/v1/verify", verifyBody)
	verifyReq.Header.Set("Content-Type", verifyContentType)
	verifyRec := httptest.NewRecorder()
	secondServer.Handler().ServeHTTP(verifyRec, verifyReq)

	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify after restart status = %d body = %s", verifyRec.Code, verifyRec.Body.String())
	}

	var verifyResp struct {
		Valid    bool   `json:"valid"`
		RecordID string `json:"recordId"`
	}
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}

	if !verifyResp.Valid {
		t.Fatalf("verify after restart invalid: %s", verifyRec.Body.String())
	}

	if verifyResp.RecordID != signResp.RecordID {
		t.Fatalf("record id = %q, want %q", verifyResp.RecordID, signResp.RecordID)
	}
}

func multipartRequest(pdf []byte, fields map[string]string) (*bytes.Buffer, string, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("pdf", "sample.pdf")
	if err != nil {
		return nil, "", err
	}

	if _, err := part.Write(pdf); err != nil {
		return nil, "", err
	}

	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			return nil, "", err
		}
	}

	if err := writer.Close(); err != nil {
		return nil, "", err
	}

	return body, writer.FormDataContentType(), nil
}
