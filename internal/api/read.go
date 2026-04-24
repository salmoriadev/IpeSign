package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"ipesign/internal/ledger/localchain"
)

var ErrRecordNotFound = errors.New("record not found")

type HealthResult struct {
	Status        string `json:"status"`
	IssuerID      string `json:"issuerId"`
	IssuerName    string `json:"issuerName"`
	ChainBlocks   int    `json:"chainBlocks"`
	LastBlockHash string `json:"lastBlockHash,omitempty"`
}

type CAResult struct {
	IssuerID          string `json:"issuerId"`
	IssuerName        string `json:"issuerName"`
	CACertificate     string `json:"caCertificate"`
	CACertificateHash string `json:"caCertificateHash"`
	CAPublicKeyHash   string `json:"caPublicKeyHash"`
}

type ChainBlockResult struct {
	Index       uint64    `json:"index"`
	EventType   string    `json:"eventType"`
	BlockHash   string    `json:"blockHash"`
	PrevHash    string    `json:"prevHash"`
	Timestamp   time.Time `json:"timestamp"`
	PayloadHash string    `json:"payloadHash"`
}

type ChainWalkResult struct {
	Direction string             `json:"direction"`
	Blocks    []ChainBlockResult `json:"blocks"`
}

type RecordResult struct {
	RecordID            string `json:"recordId"`
	CertHash            string `json:"certHash"`
	PublicKeyHash       string `json:"publicKeyHash"`
	IssuerID            string `json:"issuerId"`
	PolicyID            string `json:"policyId"`
	DocumentHash        string `json:"documentHash"`
	SignedPDFHash       string `json:"signedPdfHash"`
	SignatureHash       string `json:"signatureHash"`
	SingleUse           bool   `json:"singleUse"`
	Status              string `json:"status"`
	CertificateRevoked  bool   `json:"certificateRevoked"`
	SignatureRevoked    bool   `json:"signatureRevoked"`
	SingleUseConfirmed  bool   `json:"singleUseConfirmed"`
	LedgerRecordValid   bool   `json:"ledgerRecordValid"`
	ChainValid          bool   `json:"chainValid"`
	CertificateIssuedAt string `json:"certificateIssuedAt"`
	SignedAt            string `json:"signedAt"`
}

func (s *Server) Health() (*HealthResult, error) {
	report, err := s.chain.Verify()
	if err != nil {
		return nil, err
	}

	return &HealthResult{
		Status:        "ok",
		IssuerID:      s.authority.IssuerID(),
		IssuerName:    s.authority.IssuerName(),
		ChainBlocks:   report.BlocksVerified,
		LastBlockHash: report.LastBlockHash,
	}, nil
}

func (s *Server) CA() *CAResult {
	return &CAResult{
		IssuerID:          s.authority.IssuerID(),
		IssuerName:        s.authority.IssuerName(),
		CACertificate:     s.authority.CertificatePEM(),
		CACertificateHash: s.authority.CertificateHash(),
		CAPublicKeyHash:   s.authority.PublicKeyHash(),
	}
}

func (s *Server) ChainVerify() (*localchain.VerificationReport, error) {
	return s.chain.Verify()
}

func (s *Server) ChainWalk(direction string) (*ChainWalkResult, error) {
	normalizedDirection := strings.ToLower(direction)
	if normalizedDirection != "reverse" {
		normalizedDirection = "forward"
	}

	blocks := make([]ChainBlockResult, 0, s.chain.Len())
	appendNode := func(node *localchain.Node) error {
		blocks = append(blocks, ChainBlockResult{
			Index:       node.Block.Index,
			EventType:   node.Block.EventType,
			BlockHash:   node.Block.BlockHash,
			PrevHash:    node.Block.PrevHash,
			Timestamp:   node.Block.Timestamp,
			PayloadHash: node.Block.PayloadHash,
		})
		return nil
	}

	var err error
	if normalizedDirection == "reverse" {
		err = s.chain.TraverseBackward(appendNode)
	} else {
		err = s.chain.TraverseForward(appendNode)
	}
	if err != nil {
		return nil, err
	}

	return &ChainWalkResult{
		Direction: normalizedDirection,
		Blocks:    blocks,
	}, nil
}

func (s *Server) GetRecord(recordID string) (*RecordResult, error) {
	if strings.TrimSpace(recordID) == "" {
		return nil, fmt.Errorf("record id is required")
	}

	signatureNode := s.chain.GetSignatureNodeByRecordID(recordID)
	if signatureNode == nil {
		return nil, ErrRecordNotFound
	}

	var signaturePayload localchain.SignatureRegisteredPayload
	if err := json.Unmarshal(signatureNode.Block.Payload, &signaturePayload); err != nil {
		return nil, fmt.Errorf("decode signature record: %w", err)
	}

	certificateNode := s.chain.GetCertificateNode(signaturePayload.CertHash)
	if certificateNode == nil {
		return nil, fmt.Errorf("certificate record not found for record %q", recordID)
	}

	var certificatePayload localchain.CertificateIssuedPayload
	if err := json.Unmarshal(certificateNode.Block.Payload, &certificatePayload); err != nil {
		return nil, fmt.Errorf("decode certificate record: %w", err)
	}

	recordVerification, err := s.chain.VerifyRecord(localchain.VerifyRecordInput{
		CertHash:      signaturePayload.CertHash,
		DocumentHash:  signaturePayload.DocumentHash,
		SignedPDFHash: signaturePayload.SignedPDFHash,
		SignatureHash: signaturePayload.SignatureHash,
	})
	if err != nil {
		return nil, fmt.Errorf("verify record: %w", err)
	}

	return &RecordResult{
		RecordID:            signaturePayload.RecordID,
		CertHash:            certificatePayload.CertHash,
		PublicKeyHash:       certificatePayload.PublicKeyHash,
		IssuerID:            certificatePayload.IssuerID,
		PolicyID:            certificatePayload.PolicyID,
		DocumentHash:        certificatePayload.DocumentHash,
		SignedPDFHash:       signaturePayload.SignedPDFHash,
		SignatureHash:       signaturePayload.SignatureHash,
		SingleUse:           certificatePayload.SingleUse,
		Status:              signaturePayload.Status,
		CertificateRevoked:  recordVerification.CertificateRevoked,
		SignatureRevoked:    recordVerification.SignatureRevoked,
		SingleUseConfirmed:  recordVerification.SingleUseConfirmed,
		LedgerRecordValid:   recordVerification.Valid,
		ChainValid:          recordVerification.ChainValid,
		CertificateIssuedAt: timestampOrFallback(certificatePayload.CreatedAt, certificateNode.Block.Timestamp),
		SignedAt:            timestampOrFallback(signaturePayload.SignedAt, signatureNode.Block.Timestamp),
	}, nil
}

func timestampOrFallback(value string, fallback time.Time) string {
	if value != "" {
		return value
	}

	return fallback.UTC().Format(time.RFC3339)
}
