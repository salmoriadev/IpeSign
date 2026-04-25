package localchain

import (
	"encoding/json"
	"fmt"
)

type transitionValidator func(*Chain, json.RawMessage) error

var transitionValidators = map[string]transitionValidator{
	EventTypeGenesis:             func(c *Chain, _ json.RawMessage) error { return c.validateGenesisTransitionLocked() },
	EventTypeIssuerRegistered:    func(c *Chain, p json.RawMessage) error { return c.validateIssuerRegistrationTransitionLocked(p) },
	EventTypeCertificateIssued:   func(c *Chain, p json.RawMessage) error { return c.validateCertificateIssuanceTransitionLocked(p) },
	EventTypeSignatureRegistered: func(c *Chain, p json.RawMessage) error { return c.validateSignatureRegistrationTransitionLocked(p) },
	EventTypeCertificateRevoked:  func(c *Chain, p json.RawMessage) error { return c.validateCertificateRevocationTransitionLocked(p) },
	EventTypeSignatureRevoked:    func(c *Chain, p json.RawMessage) error { return c.validateSignatureRevocationTransitionLocked(p) },
}

func (chain *Chain) validateTransitionLocked(eventType string, rawPayload json.RawMessage) error {
	if validator, exists := transitionValidators[eventType]; exists {
		return validator(chain, rawPayload)
	}
	return ErrUnknownEventType
}

func (chain *Chain) validateGenesisTransitionLocked() error {
	if chain.length != 0 {
		return ErrGenesisAlreadyExists
	}

	return nil
}

func (chain *Chain) validateIssuerRegistrationTransitionLocked(rawPayload json.RawMessage) error {
	issuerPayload, err := decodePayload[IssuerRegisteredPayload](rawPayload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	if issuerPayload.IssuerID == "" || issuerPayload.Name == "" {
		return fmt.Errorf("%w: issuerId and name are required", ErrInvalidPayload)
	}

	if _, exists := chain.issuers[issuerPayload.IssuerID]; exists {
		return ErrIssuerAlreadyExists
	}

	return nil
}

func (chain *Chain) validateCertificateIssuanceTransitionLocked(rawPayload json.RawMessage) error {
	certificatePayload, err := decodePayload[CertificateIssuedPayload](rawPayload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	if err := validateCertificatePayload(certificatePayload); err != nil {
		return err
	}

	if _, exists := chain.issuers[certificatePayload.IssuerID]; !exists {
		return ErrIssuerNotFound
	}

	if _, exists := chain.certificates[certificatePayload.CertHash]; exists {
		return ErrCertificateAlreadyExists
	}

	return nil
}

func (chain *Chain) validateSignatureRegistrationTransitionLocked(rawPayload json.RawMessage) error {
	signaturePayload, err := decodePayload[SignatureRegisteredPayload](rawPayload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	if err := validateSignaturePayload(signaturePayload); err != nil {
		return err
	}

	certificateNode, certificateExists := chain.certificates[signaturePayload.CertHash]
	if !certificateExists {
		return ErrCertificateNotFound
	}

	if _, revoked := chain.revokedCertificates[signaturePayload.CertHash]; revoked {
		return ErrCertificateRevoked
	}

	if _, exists := chain.signaturesByRecordID[signaturePayload.RecordID]; exists {
		return ErrSignatureAlreadyExists
	}

	certificatePayload, err := decodePayload[CertificateIssuedPayload](certificateNode.Block.Payload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	if err := chain.validateSignatureAgainstCertificate(signaturePayload, certificatePayload); err != nil {
		return err
	}

	return nil
}

func (chain *Chain) validateCertificateRevocationTransitionLocked(rawPayload json.RawMessage) error {
	revocationPayload, err := decodePayload[CertificateRevokedPayload](rawPayload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	if revocationPayload.CertHash == "" || revocationPayload.Reason == "" {
		return fmt.Errorf("%w: certHash and reason are required", ErrInvalidPayload)
	}

	if _, exists := chain.certificates[revocationPayload.CertHash]; !exists {
		return ErrCertificateNotFound
	}

	if _, exists := chain.revokedCertificates[revocationPayload.CertHash]; exists {
		return ErrCertificateRevoked
	}

	return nil
}

func (chain *Chain) validateSignatureRevocationTransitionLocked(rawPayload json.RawMessage) error {
	revocationPayload, err := decodePayload[SignatureRevokedPayload](rawPayload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	if revocationPayload.RecordID == "" || revocationPayload.CertHash == "" || revocationPayload.Reason == "" {
		return fmt.Errorf("%w: recordId, certHash and reason are required", ErrInvalidPayload)
	}

	signatureNode, exists := chain.signaturesByRecordID[revocationPayload.RecordID]
	if !exists {
		return ErrSignatureNotFound
	}

	signaturePayload, err := decodePayload[SignatureRegisteredPayload](signatureNode.Block.Payload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	if signaturePayload.CertHash != revocationPayload.CertHash {
		return fmt.Errorf("%w: certHash mismatch with signature", ErrInvalidPayload)
	}

	if _, exists := chain.revokedSignaturesByID[revocationPayload.RecordID]; exists {
		return ErrSignatureRevoked
	}

	return nil
}

func (chain *Chain) validateSignatureAgainstCertificate(
	signaturePayload SignatureRegisteredPayload,
	certificatePayload CertificateIssuedPayload,
) error {
	if certificatePayload.SingleUse {
		return chain.validateSingleUseSignature(signaturePayload, certificatePayload)
	}

	return validateSignatureConsistency(signaturePayload, certificatePayload)
}

func (chain *Chain) validateSingleUseSignature(
	signaturePayload SignatureRegisteredPayload,
	certificatePayload CertificateIssuedPayload,
) error {
	if _, exists := chain.signaturesByCertHash[signaturePayload.CertHash]; exists {
		return ErrCertificateAlreadyUsed
	}

	if err := validateSignatureConsistency(signaturePayload, certificatePayload); err != nil {
		return err
	}

	return nil
}

func validateSignatureConsistency(
	signaturePayload SignatureRegisteredPayload,
	certificatePayload CertificateIssuedPayload,
) error {
	if certificatePayload.DocumentHash != signaturePayload.DocumentHash {
		return fmt.Errorf("%w: document hash mismatch with certificate", ErrInvalidPayload)
	}

	if certificatePayload.IssuerID != signaturePayload.IssuerID {
		return fmt.Errorf("%w: issuer mismatch with certificate", ErrInvalidPayload)
	}

	if certificatePayload.PolicyID != signaturePayload.PolicyID {
		return fmt.Errorf("%w: policy mismatch with certificate", ErrInvalidPayload)
	}

	return nil
}
