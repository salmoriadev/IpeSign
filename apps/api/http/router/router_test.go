package router_test

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	httprouter "ipesign/apps/api/http/router"
	coreapi "ipesign/internal/api"
	"ipesign/internal/ledger/localchain"
)

var samplePDF = []byte("%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF")

func TestRouterSignsAndVerifiesCanonicalRoutes(t *testing.T) {
	handler := newTestHandler(t, filepath.Join(t.TempDir(), "data"))

	signResp := signDocument(t, handler, "/v1/documents/sign")
	verifyResp := verifyDocument(t, handler, "/v1/documents/verify", signResp.CertificatePEM, signResp.SignatureBase64)

	if !verifyResp.Valid {
		t.Fatalf("verify response invalid: %+v", verifyResp)
	}

	if !verifyResp.SignatureValid || !verifyResp.LedgerRecordValid || !verifyResp.SingleUseConfirmed {
		t.Fatalf("verify response missing guarantees: %+v", verifyResp)
	}

	if verifyResp.RecordID != signResp.RecordID {
		t.Fatalf("record id = %q, want %q", verifyResp.RecordID, signResp.RecordID)
	}
}

func TestRouterSupportsLegacyAliases(t *testing.T) {
	handler := newTestHandler(t, filepath.Join(t.TempDir(), "data"))

	signResp := signDocument(t, handler, "/v1/sign")
	verifyResp := verifyDocument(t, handler, "/v1/verify", signResp.CertificatePEM, signResp.SignatureBase64)

	if !verifyResp.Valid {
		t.Fatalf("legacy alias verify invalid: %+v", verifyResp)
	}

	if verifyResp.RecordID != signResp.RecordID {
		t.Fatalf("record id = %q, want %q", verifyResp.RecordID, signResp.RecordID)
	}
}

func TestRouterPersistsAndReturnsRecord(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	firstHandler := newTestHandler(t, dataDir)

	signResp := signDocument(t, firstHandler, "/v1/documents/sign")

	secondHandler := newTestHandler(t, dataDir)
	verifyResp := verifyDocument(t, secondHandler, "/v1/documents/verify", signResp.CertificatePEM, signResp.SignatureBase64)
	if !verifyResp.Valid {
		t.Fatalf("verify after restart invalid: %+v", verifyResp)
	}

	recordReq := httptest.NewRequest(http.MethodGet, "/v1/records/"+signResp.RecordID, nil)
	recordRec := httptest.NewRecorder()
	secondHandler.ServeHTTP(recordRec, recordReq)

	if recordRec.Code != http.StatusOK {
		t.Fatalf("record status = %d body = %s", recordRec.Code, recordRec.Body.String())
	}

	var recordResp coreapi.RecordResult
	if err := json.Unmarshal(recordRec.Body.Bytes(), &recordResp); err != nil {
		t.Fatalf("decode record response: %v", err)
	}

	if recordResp.RecordID != signResp.RecordID {
		t.Fatalf("record id = %q, want %q", recordResp.RecordID, signResp.RecordID)
	}

	if recordResp.CertHash != signResp.CertHash {
		t.Fatalf("cert hash = %q, want %q", recordResp.CertHash, signResp.CertHash)
	}

	if recordResp.DocumentHash != signResp.DocumentHash || recordResp.SignatureHash != signResp.SignatureHash {
		t.Fatalf("record response hashes do not match sign response: %+v", recordResp)
	}

	if !recordResp.SingleUse || !recordResp.SingleUseConfirmed || !recordResp.LedgerRecordValid || !recordResp.ChainValid {
		t.Fatalf("record response missing integrity flags: %+v", recordResp)
	}

	if recordResp.PublicKeyHash == "" || recordResp.IssuerID == "" || recordResp.PolicyID == "" || recordResp.CertificateIssuedAt == "" || recordResp.SignedAt == "" {
		t.Fatalf("record response missing metadata: %+v", recordResp)
	}
}

func TestRouterReturns404ForUnknownRecordAndKeepsChainEndpoints(t *testing.T) {
	handler := newTestHandler(t, filepath.Join(t.TempDir(), "data"))

	signDocument(t, handler, "/v1/documents/sign")

	recordReq := httptest.NewRequest(http.MethodGet, "/v1/records/missing-record", nil)
	recordRec := httptest.NewRecorder()
	handler.ServeHTTP(recordRec, recordReq)

	if recordRec.Code != http.StatusNotFound {
		t.Fatalf("missing record status = %d body = %s", recordRec.Code, recordRec.Body.String())
	}

	healthReq := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	healthRec := httptest.NewRecorder()
	handler.ServeHTTP(healthRec, healthReq)
	if healthRec.Code != http.StatusOK {
		t.Fatalf("health status = %d body = %s", healthRec.Code, healthRec.Body.String())
	}

	var healthResp coreapi.HealthResult
	if err := json.Unmarshal(healthRec.Body.Bytes(), &healthResp); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if healthResp.Status != "ok" || healthResp.ChainBlocks == 0 {
		t.Fatalf("unexpected health response: %+v", healthResp)
	}

	chainVerifyReq := httptest.NewRequest(http.MethodGet, "/v1/chain/verify", nil)
	chainVerifyRec := httptest.NewRecorder()
	handler.ServeHTTP(chainVerifyRec, chainVerifyReq)
	if chainVerifyRec.Code != http.StatusOK {
		t.Fatalf("chain verify status = %d body = %s", chainVerifyRec.Code, chainVerifyRec.Body.String())
	}

	var verifyResp localchain.VerificationReport
	if err := json.Unmarshal(chainVerifyRec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("decode chain verify response: %v", err)
	}
	if !verifyResp.Valid || verifyResp.BlocksVerified == 0 {
		t.Fatalf("unexpected chain verify response: %+v", verifyResp)
	}

	chainWalkReq := httptest.NewRequest(http.MethodGet, "/v1/chain/walk?direction=reverse", nil)
	chainWalkRec := httptest.NewRecorder()
	handler.ServeHTTP(chainWalkRec, chainWalkReq)
	if chainWalkRec.Code != http.StatusOK {
		t.Fatalf("chain walk status = %d body = %s", chainWalkRec.Code, chainWalkRec.Body.String())
	}

	var walkResp coreapi.ChainWalkResult
	if err := json.Unmarshal(chainWalkRec.Body.Bytes(), &walkResp); err != nil {
		t.Fatalf("decode chain walk response: %v", err)
	}
	if walkResp.Direction != "reverse" || len(walkResp.Blocks) == 0 {
		t.Fatalf("unexpected chain walk response: %+v", walkResp)
	}
}

func newTestHandler(t *testing.T, dataDir string) http.Handler {
	t.Helper()

	server, err := coreapi.NewServer(coreapi.Config{DataDir: dataDir})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	return httprouter.New(server)
}

func signDocument(t *testing.T, handler http.Handler, path string) coreapi.SignResult {
	t.Helper()

	body, contentType, err := multipartRequest(samplePDF, map[string]string{
		"policy_id": coreapi.DefaultPolicyID,
	})
	if err != nil {
		t.Fatalf("multipartRequest(sign) error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, path, body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("sign status = %d body = %s", rec.Code, rec.Body.String())
	}

	var signResp coreapi.SignResult
	if err := json.Unmarshal(rec.Body.Bytes(), &signResp); err != nil {
		t.Fatalf("decode sign response: %v", err)
	}

	if signResp.DocumentHash == "" || signResp.SignatureBase64 == "" || signResp.CertificatePEM == "" || signResp.RecordID == "" {
		t.Fatalf("sign response missing fields: %+v", signResp)
	}

	return signResp
}

func verifyDocument(t *testing.T, handler http.Handler, path string, certificatePEM string, signatureBase64 string) coreapi.VerifyResult {
	t.Helper()

	body, contentType, err := multipartRequest(samplePDF, map[string]string{
		"certificate_pem":  certificatePEM,
		"signature_base64": signatureBase64,
	})
	if err != nil {
		t.Fatalf("multipartRequest(verify) error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, path, body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d body = %s", rec.Code, rec.Body.String())
	}

	var verifyResp coreapi.VerifyResult
	if err := json.Unmarshal(rec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}

	return verifyResp
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
