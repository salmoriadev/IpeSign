package core

import (
	"encoding/json"
	"fmt"
	"strings"

	"ipesign/internal/ledger/localchain"
	"ipesign/internal/persist"
)

func NewService(cfg Config) (*Service, error) {
	stateStore, err := persist.NewStateStore(persist.Config{
		DataDir:     cfg.DataDir,
		DatabaseURL: cfg.DatabaseURL,
		MasterKey:   cfg.MasterKey,
	})
	if err != nil {
		return nil, err
	}

	stateExists, err := stateStore.Exists()
	if err != nil {
		return nil, err
	}

	if stateExists {
		return loadService(stateStore)
	}

	return bootstrapService(stateStore)
}

func (service *Service) Backend() string {
	return service.store.Backend()
}

func (service *Service) Health() (*Summary, error) {
	verificationReport, err := service.chain.Verify()
	if err != nil {
		return nil, err
	}

	return &Summary{
		Status:        "ok",
		IssuerID:      service.authority.IssuerID(),
		IssuerName:    service.authority.IssuerName(),
		ChainBlocks:   verificationReport.BlocksVerified,
		LastBlockHash: verificationReport.LastBlockHash,
	}, nil
}

func (service *Service) CAInfo() *CAInfo {
	return &CAInfo{
		IssuerID:          service.authority.IssuerID(),
		IssuerName:        service.authority.IssuerName(),
		CACertificate:     service.authority.CertificatePEM(),
		CACertificateHash: service.authority.CertificateHash(),
		CAPublicKeyHash:   service.authority.PublicKeyHash(),
	}
}

func (service *Service) VerifyChain() (*localchain.VerificationReport, error) {
	verificationReport, err := service.chain.Verify()
	return verificationReport, err
}

func (service *Service) Walk(direction string) (*ChainWalkResult, error) {
	normalizedDirection := normalizeWalkDirection(direction)
	chainBlocks := make([]ChainWalkBlock, 0, service.chain.Len())
	appendChainBlock := func(node *localchain.Node) error {
		chainBlocks = append(chainBlocks, newChainWalkBlock(node))
		return nil
	}

	var walkErr error
	if normalizedDirection == "reverse" {
		walkErr = service.chain.TraverseBackward(appendChainBlock)
	} else {
		walkErr = service.chain.TraverseForward(appendChainBlock)
	}
	if walkErr != nil {
		return nil, walkErr
	}

	chainWalkResult := &ChainWalkResult{
		Direction: normalizedDirection,
		Blocks:    chainBlocks,
	}

	return chainWalkResult, nil
}

func (service *Service) GetRecord(recordID string) (*RecordResult, error) {
	if recordID == "" {
		return nil, fmt.Errorf("record id is required")
	}

	signatureNode := service.chain.GetSignatureNodeByRecordID(recordID)
	if signatureNode == nil {
		return nil, fmt.Errorf("record not found")
	}

	signaturePayload, err := decodeLedgerPayload[localchain.SignatureRegisteredPayload](signatureNode.Block.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode signature record: %w", err)
	}

	certificateNode := service.chain.GetCertificateNode(signaturePayload.CertHash)
	if certificateNode == nil {
		return nil, fmt.Errorf("certificate for record not found")
	}

	certificatePayload, err := decodeLedgerPayload[localchain.CertificateIssuedPayload](certificateNode.Block.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode certificate record: %w", err)
	}

	recordVerification, err := service.chain.VerifyRecord(localchain.VerifyRecordInput{
		CertHash:      signaturePayload.CertHash,
		DocumentHash:  signaturePayload.DocumentHash,
		SignedPDFHash: signaturePayload.SignedPDFHash,
		SignatureHash: signaturePayload.SignatureHash,
	})
	if err != nil {
		return nil, fmt.Errorf("verify record: %w", err)
	}

	recordResult := newRecordResult(signaturePayload, certificatePayload, recordVerification)
	return recordResult, nil
}

func normalizeWalkDirection(direction string) string {
	if strings.EqualFold(direction, "reverse") {
		return "reverse"
	}

	return "forward"
}

func newChainWalkBlock(node *localchain.Node) ChainWalkBlock {
	return ChainWalkBlock{
		Index:       node.Block.Index,
		EventType:   node.Block.EventType,
		BlockHash:   node.Block.BlockHash,
		PrevHash:    node.Block.PrevHash,
		Timestamp:   node.Block.Timestamp,
		PayloadHash: node.Block.PayloadHash,
	}
}

func newRecordResult(
	signaturePayload localchain.SignatureRegisteredPayload,
	certificatePayload localchain.CertificateIssuedPayload,
	recordVerification *localchain.RecordVerificationResult,
) *RecordResult {
	return &RecordResult{
		RecordID:              signaturePayload.RecordID,
		CertHash:              signaturePayload.CertHash,
		PublicKeyHash:         certificatePayload.PublicKeyHash,
		IssuerID:              signaturePayload.IssuerID,
		PolicyID:              signaturePayload.PolicyID,
		DocumentHash:          signaturePayload.DocumentHash,
		SignedPDFHash:         signaturePayload.SignedPDFHash,
		SignatureHash:         signaturePayload.SignatureHash,
		SingleUse:             certificatePayload.SingleUse,
		Valid:                 recordVerification.Valid,
		LedgerRecordValid:     recordVerification.Valid,
		SingleUseConfirmed:    recordVerification.SingleUseConfirmed,
		CertificateRevoked:    recordVerification.CertificateRevoked,
		SignatureRevoked:      recordVerification.SignatureRevoked,
		CertificateValidFrom:  certificatePayload.ValidFrom,
		CertificateValidUntil: certificatePayload.ValidUntil,
		CertificateCreatedAt:  certificatePayload.CreatedAt,
		SignedAt:              signaturePayload.SignedAt,
		Status:                signaturePayload.Status,
	}
}

func decodeLedgerPayload[T any](raw []byte) (T, error) {
	var payload T
	err := json.Unmarshal(raw, &payload)
	return payload, err
}
