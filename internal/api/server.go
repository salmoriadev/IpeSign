package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"ipesign/internal/authority"
	"ipesign/internal/cryptoutil"
	"ipesign/internal/ledger/localchain"
	"ipesign/internal/persist"
)

const maxPDFSize = 20 << 20
const DefaultPolicyID = "participation-v1"

type Server struct {
	store     persist.StateStore
	ledgerKey ed25519.PrivateKey
	authority *authority.Authority
	chain     *localchain.Chain
	recordSeq atomic.Uint64
}

type Config struct {
	DataDir     string
	DatabaseURL string
}

type SignResult struct {
	Mode              string `json:"mode"`
	FileName          string `json:"fileName"`
	IssuerID          string `json:"issuerId"`
	DocumentHash      string `json:"documentHash"`
	SignedHashBase64  string `json:"signedHashBase64"`
	SignatureBase64   string `json:"signatureBase64"`
	SignatureHash     string `json:"signatureHash"`
	CertificatePEM    string `json:"certificatePem"`
	CertHash          string `json:"certHash"`
	PublicKeyHash     string `json:"publicKeyHash"`
	PolicyID          string `json:"policyId"`
	SingleUse         bool   `json:"singleUse"`
	RecordID          string `json:"recordId"`
	SignedPDFHash     string `json:"signedPdfHash"`
	EphemeralDisposed bool   `json:"ephemeralDisposed"`
}

type VerifyResult struct {
	Valid                      bool   `json:"valid"`
	DocumentHash               string `json:"documentHash"`
	CertificateTrusted         bool   `json:"certificateTrusted"`
	CertificateDocumentHash    string `json:"certificateDocumentHash"`
	CertificateDocumentMatches bool   `json:"certificateDocumentMatches"`
	PolicyID                   string `json:"policyId"`
	SingleUseInCertificate     bool   `json:"singleUseInCertificate"`
	SignatureValid             bool   `json:"signatureValid"`
	LedgerRecordValid          bool   `json:"ledgerRecordValid"`
	SingleUseConfirmed         bool   `json:"singleUseConfirmed"`
	RecordID                   string `json:"recordId"`
	CertHash                   string `json:"certHash"`
	SignatureHash              string `json:"signatureHash"`
	CertificateRevoked         bool   `json:"certificateRevoked"`
	SignatureRevoked           bool   `json:"signatureRevoked"`
}

func NewServer(cfg Config) (*Server, error) {
	store, err := persist.NewStateStore(persist.Config{
		DataDir:     cfg.DataDir,
		DatabaseURL: cfg.DatabaseURL,
	})
	if err != nil {
		return nil, err
	}

	exists, err := store.Exists()
	if err != nil {
		return nil, err
	}

	if exists {
		return loadServerFromDisk(store)
	}

	return bootstrapServer(store)
}

func looksLikePDF(raw []byte) bool {
	return len(raw) >= 5 && string(raw[:5]) == "%PDF-"
}

func validatePDFBytes(raw []byte) error {
	if len(raw) == 0 {
		return fmt.Errorf("pdf is empty")
	}

	if len(raw) > maxPDFSize {
		return fmt.Errorf("pdf exceeds 20MB limit")
	}

	if !looksLikePDF(raw) {
		return fmt.Errorf("file does not look like a PDF")
	}

	return nil
}

func (s *Server) SignPDF(pdfBytes []byte, filename string, policyID string) (*SignResult, error) {
	if err := validatePDFBytes(pdfBytes); err != nil {
		return nil, err
	}

	if filename == "" {
		filename = "document.pdf"
	}

	if policyID == "" {
		policyID = DefaultPolicyID
	}

	digest := cryptoutil.SHA256Digest(pdfBytes)
	documentHash := cryptoutil.SHA256Tagged(pdfBytes)

	issued, err := s.authority.IssueDocumentCertificate(documentHash, policyID)
	if err != nil {
		return nil, fmt.Errorf("issue certificate: %w", err)
	}

	privateKey := issued.PrivateKey
	defer func() {
		cryptoutil.ZeroBytes(privateKey)
		cryptoutil.ZeroBytes(issued.PrivateKey)
		privateKey = nil
		issued.PrivateKey = nil
	}()

	if _, err := s.chain.AppendEvent(localchain.EventTypeCertificateIssued, localchain.CertificateIssuedPayload{
		CertHash:      issued.CertHash,
		PublicKeyHash: issued.PublicKeyHash,
		IssuerID:      s.authority.IssuerID(),
		DocumentHash:  documentHash,
		PolicyID:      policyID,
		SingleUse:     true,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		return nil, fmt.Errorf("register certificate: %w", err)
	}

	if err := s.save(); err != nil {
		return nil, fmt.Errorf("persist certificate: %w", err)
	}

	signature := ed25519.Sign(privateKey, digest[:])
	signatureHash := cryptoutil.SHA256Tagged(signature)
	recordID := "pdfsig-" + strconv.FormatUint(s.recordSeq.Add(1), 10)

	if _, err := s.chain.AppendEvent(localchain.EventTypeSignatureRegistered, localchain.SignatureRegisteredPayload{
		RecordID:      recordID,
		CertHash:      issued.CertHash,
		DocumentHash:  documentHash,
		SignedPDFHash: documentHash,
		SignatureHash: signatureHash,
		IssuerID:      s.authority.IssuerID(),
		PolicyID:      policyID,
		SignedAt:      time.Now().UTC().Format(time.RFC3339),
		Status:        "VALID",
	}); err != nil {
		return nil, fmt.Errorf("register signature: %w", err)
	}

	if err := s.save(); err != nil {
		return nil, fmt.Errorf("persist signature: %w", err)
	}

	return &SignResult{
		Mode:              "hash-only",
		FileName:          filename,
		IssuerID:          s.authority.IssuerID(),
		DocumentHash:      documentHash,
		SignedHashBase64:  base64.StdEncoding.EncodeToString(signature),
		SignatureBase64:   base64.StdEncoding.EncodeToString(signature),
		SignatureHash:     signatureHash,
		CertificatePEM:    issued.CertificatePEM,
		CertHash:          issued.CertHash,
		PublicKeyHash:     issued.PublicKeyHash,
		PolicyID:          policyID,
		SingleUse:         true,
		RecordID:          recordID,
		SignedPDFHash:     documentHash,
		EphemeralDisposed: true,
	}, nil
}

func (s *Server) VerifyPDF(pdfBytes []byte, certificatePEM string, signatureBase64 string) (*VerifyResult, error) {
	if err := validatePDFBytes(pdfBytes); err != nil {
		return nil, err
	}

	if certificatePEM == "" || signatureBase64 == "" {
		return nil, fmt.Errorf("certificate_pem and signature_base64 are required")
	}

	cert, err := authority.ParseCertificatePEM(certificatePEM)
	if err != nil {
		return nil, err
	}

	if err := s.authority.VerifyIssuedCertificate(cert); err != nil {
		return nil, err
	}

	documentHash := cryptoutil.SHA256Tagged(pdfBytes)
	digest := cryptoutil.SHA256Digest(pdfBytes)
	certificateDocumentHash := authority.ExtractDocumentHash(cert)
	policyID := authority.ExtractPolicyID(cert)
	singleUse := authority.ExtractSingleUse(cert)

	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	publicKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate public key is not ed25519")
	}

	signatureValid := ed25519.Verify(publicKey, digest[:], signature)
	certHash := cryptoutil.SHA256Tagged(cert.Raw)
	signatureHash := cryptoutil.SHA256Tagged(signature)

	recordResult, err := s.chain.VerifyRecord(localchain.VerifyRecordInput{
		CertHash:      certHash,
		DocumentHash:  documentHash,
		SignedPDFHash: documentHash,
		SignatureHash: signatureHash,
	})
	if err != nil {
		return nil, fmt.Errorf("verify record: %w", err)
	}

	valid := signatureValid &&
		certificateDocumentHash == documentHash &&
		singleUse &&
		recordResult.Valid

	return &VerifyResult{
		Valid:                      valid,
		DocumentHash:               documentHash,
		CertificateTrusted:         true,
		CertificateDocumentHash:    certificateDocumentHash,
		CertificateDocumentMatches: certificateDocumentHash == documentHash,
		PolicyID:                   policyID,
		SingleUseInCertificate:     singleUse,
		SignatureValid:             signatureValid,
		LedgerRecordValid:          recordResult.Valid,
		SingleUseConfirmed:         recordResult.SingleUseConfirmed,
		RecordID:                   recordResult.RecordID,
		CertHash:                   certHash,
		SignatureHash:              signatureHash,
		CertificateRevoked:         recordResult.CertificateRevoked,
		SignatureRevoked:           recordResult.SignatureRevoked,
	}, nil
}

func bootstrapServer(store persist.StateStore) (*Server, error) {
	ledgerVerifyKey, ledgerSigningKey, err := localchain.GenerateSealer()
	if err != nil {
		return nil, fmt.Errorf("generate ledger keys: %w", err)
	}

	chain, err := localchain.NewChain(localchain.Config{
		Signer:    ledgerSigningKey,
		VerifyKey: ledgerVerifyKey,
	})
	if err != nil {
		return nil, fmt.Errorf("create chain: %w", err)
	}

	auth, err := authority.New(authority.Config{
		IssuerID:   "ipe",
		IssuerName: "Ipe",
	})
	if err != nil {
		return nil, fmt.Errorf("create authority: %w", err)
	}

	if _, err := chain.AppendEvent(localchain.EventTypeIssuerRegistered, localchain.IssuerRegisteredPayload{
		IssuerID:        auth.IssuerID(),
		Name:            auth.IssuerName(),
		CAPublicKeyHash: auth.PublicKeyHash(),
		CreatedAt:       time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		return nil, fmt.Errorf("register issuer: %w", err)
	}

	server := &Server{
		store:     store,
		ledgerKey: ledgerSigningKey,
		authority: auth,
		chain:     chain,
	}

	if err := server.save(); err != nil {
		return nil, err
	}

	return server, nil
}

func loadServerFromDisk(store persist.StateStore) (*Server, error) {
	state, err := store.Load()
	if err != nil {
		return nil, err
	}

	auth, err := authority.Load(authority.Config{
		IssuerID:   "ipe",
		IssuerName: "Ipe",
	}, state.CACertPEM, state.CAKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load authority: %w", err)
	}

	chain, err := localchain.OpenChain(localchain.Config{
		Signer: state.LedgerKey,
	}, state.Blocks)
	if err != nil {
		return nil, fmt.Errorf("load chain: %w", err)
	}

	server := &Server{
		store:     store,
		ledgerKey: state.LedgerKey,
		authority: auth,
		chain:     chain,
	}
	server.recordSeq.Store(nextRecordSequence(chain))

	return server, nil
}

func (s *Server) save() error {
	caKeyPEM, err := s.authority.PrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("encode authority private key: %w", err)
	}

	return s.store.Save(&persist.State{
		CACertPEM: []byte(s.authority.CertificatePEM()),
		CAKeyPEM:  caKeyPEM,
		LedgerKey: s.ledgerKey,
		Blocks:    s.chain.Snapshot(),
	})
}

func nextRecordSequence(chain *localchain.Chain) uint64 {
	var max uint64

	_ = chain.TraverseForward(func(node *localchain.Node) error {
		if node.Block.EventType != localchain.EventTypeSignatureRegistered {
			return nil
		}

		var payload localchain.SignatureRegisteredPayload
		if err := json.Unmarshal(node.Block.Payload, &payload); err != nil {
			return nil
		}

		value := strings.TrimPrefix(payload.RecordID, "pdfsig-")
		number, err := strconv.ParseUint(value, 10, 64)
		if err == nil && number > max {
			max = number
		}

		return nil
	})

	return max
}
