package localchain

import "fmt"

type blockApplier func(*ledgerState, Block) error

var blockAppliers = map[string]blockApplier{
	EventTypeGenesis:             func(s *ledgerState, b Block) error { return nil },
	EventTypeIssuerRegistered:    applyIssuerRegisteredBlock,
	EventTypeCertificateIssued:   applyCertificateIssuedBlock,
	EventTypeSignatureRegistered: applySignatureRegisteredBlock,
	EventTypeCertificateRevoked:  applyCertificateRevokedBlock,
	EventTypeSignatureRevoked:    applySignatureRevokedBlock,
}

func applyBlockToState(state *ledgerState, block Block) error {
	if applier, exists := blockAppliers[block.EventType]; exists {
		return applier(state, block)
	}
	return ErrUnknownEventType
}

func applyIssuerRegisteredBlock(state *ledgerState, block Block) error {
	issuerPayload, err := decodePayload[IssuerRegisteredPayload](block.Payload)
	if err != nil {
		return err
	}

	if issuerPayload.IssuerID == "" || issuerPayload.Name == "" {
		return fmt.Errorf("issuerId and name are required")
	}

	if _, exists := state.issuers[issuerPayload.IssuerID]; exists {
		return ErrIssuerAlreadyExists
	}

	state.issuers[issuerPayload.IssuerID] = issuerPayload
	return nil
}

func applyCertificateIssuedBlock(state *ledgerState, block Block) error {
	certificatePayload, err := decodePayload[CertificateIssuedPayload](block.Payload)
	if err != nil {
		return err
	}

	if err := validateCertificatePayload(certificatePayload); err != nil {
		return err
	}

	if _, exists := state.issuers[certificatePayload.IssuerID]; !exists {
		return ErrIssuerNotFound
	}

	if _, exists := state.certificates[certificatePayload.CertHash]; exists {
		return ErrCertificateAlreadyExists
	}

	state.certificates[certificatePayload.CertHash] = certificateState{
		Payload: certificatePayload,
	}
	return nil
}

func applySignatureRegisteredBlock(state *ledgerState, block Block) error {
	signaturePayload, err := decodePayload[SignatureRegisteredPayload](block.Payload)
	if err != nil {
		return err
	}

	if err := validateSignaturePayload(signaturePayload); err != nil {
		return err
	}

	certificateState, exists := state.certificates[signaturePayload.CertHash]
	if !exists {
		return ErrCertificateNotFound
	}

	if certificateState.Revoked {
		return ErrCertificateRevoked
	}

	if _, exists := state.signaturesByRecordID[signaturePayload.RecordID]; exists {
		return ErrSignatureAlreadyExists
	}

	if certificateState.Payload.SingleUse && state.usageCountByCertHash[signaturePayload.CertHash] > 0 {
		return ErrCertificateAlreadyUsed
	}

	if err := validateSignatureConsistency(signaturePayload, certificateState.Payload); err != nil {
		return err
	}

	state.signaturesByCertHash[signaturePayload.CertHash] = signatureState{Payload: signaturePayload}
	state.signaturesByRecordID[signaturePayload.RecordID] = signatureState{Payload: signaturePayload}
	state.usageCountByCertHash[signaturePayload.CertHash]++
	return nil
}

func applyCertificateRevokedBlock(state *ledgerState, block Block) error {
	revocationPayload, err := decodePayload[CertificateRevokedPayload](block.Payload)
	if err != nil {
		return err
	}

	if revocationPayload.CertHash == "" || revocationPayload.Reason == "" {
		return fmt.Errorf("certHash and reason are required")
	}

	certificateState, exists := state.certificates[revocationPayload.CertHash]
	if !exists {
		return ErrCertificateNotFound
	}

	if certificateState.Revoked {
		return ErrCertificateRevoked
	}

	certificateState.Revoked = true
	state.certificates[revocationPayload.CertHash] = certificateState
	state.revokedCertificates++
	return nil
}

func applySignatureRevokedBlock(state *ledgerState, block Block) error {
	revocationPayload, err := decodePayload[SignatureRevokedPayload](block.Payload)
	if err != nil {
		return err
	}

	if revocationPayload.RecordID == "" || revocationPayload.CertHash == "" || revocationPayload.Reason == "" {
		return fmt.Errorf("recordId, certHash and reason are required")
	}

	signatureStateByRecordID, exists := state.signaturesByRecordID[revocationPayload.RecordID]
	if !exists {
		return ErrSignatureNotFound
	}

	if signatureStateByRecordID.Payload.CertHash != revocationPayload.CertHash {
		return fmt.Errorf("%w: certHash mismatch with signature", ErrInvalidPayload)
	}

	if signatureStateByRecordID.Revoked {
		return ErrSignatureRevoked
	}

	signatureStateByRecordID.Revoked = true
	state.signaturesByRecordID[revocationPayload.RecordID] = signatureStateByRecordID

	signatureStateByCertificate := state.signaturesByCertHash[revocationPayload.CertHash]
	signatureStateByCertificate.Revoked = true
	state.signaturesByCertHash[revocationPayload.CertHash] = signatureStateByCertificate
	state.revokedSignatures++
	return nil
}
