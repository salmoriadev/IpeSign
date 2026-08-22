package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"ipesign/internal/authority"
	"ipesign/internal/cryptoutil"
	"ipesign/internal/ledger/localchain"
)

const SignatureMarkerStart = "\n%%IPESIGN_SIGNATURE_START%%\n"
const SignatureMarkerEnd = "\n%%IPESIGN_SIGNATURE_END%%\n"

func (service *Service) SignPDF(pdfBytes []byte, fileName string, policyID string, identity SignerIdentity) ([]byte, *SignResult, error) {
	if err := ValidatePDFBytes(pdfBytes); err != nil {
		return nil, nil, err
	}

	documentFileName := normalizeDocumentFileName(fileName)
	documentPolicyID := normalizePolicyID(policyID)
	documentDigest := cryptoutil.SHA256Digest(pdfBytes)
	documentHash := cryptoutil.SHA256Tagged(pdfBytes)

	// Step 1: Issue an ephemeral single-use certificate for this specific document.
	issuedCertificate, err := service.authority.IssueDocumentCertificate(documentHash, documentPolicyID, identity.toAuthorityIdentity())
	if err != nil {
		return nil, nil, fmt.Errorf("issue certificate: %w", err)
	}
	// Important: The ephemeral private key must be destroyed after signing.
	defer disposeIssuedPrivateKey(issuedCertificate)

	// Step 2: Produce the digital signature using the ephemeral private key.
	signatureBytes := ed25519.Sign(issuedCertificate.PrivateKey, documentDigest[:])
	signatureHash := cryptoutil.SHA256Tagged(signatureBytes)
	recordID := service.nextRecordID()

	signResult := newSignResult(
		service.authority.IssuerID(),
		documentFileName,
		documentPolicyID,
		documentHash,
		signatureBytes,
		signatureHash,
		recordID,
		identity,
		issuedCertificate,
	)
	signResult.Mode = "embedded"

	// Marshal the JSON sidecar to embed it
	sidecarJSON, err := json.MarshalIndent(signResult, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshal sidecar: %w", err)
	}

	// Inject the signature at the end of the PDF
	var combinedPDF []byte
	combinedPDF = append(combinedPDF, pdfBytes...)
	combinedPDF = append(combinedPDF, []byte(SignatureMarkerStart)...)
	combinedPDF = append(combinedPDF, sidecarJSON...)
	combinedPDF = append(combinedPDF, []byte(SignatureMarkerEnd)...)

	signedPDFHash := cryptoutil.SHA256Tagged(combinedPDF)
	signResult.SignedPDFHash = signedPDFHash // Return the final hash to caller

	// Step 3: Commit certificate issuance and use as one atomic ledger operation.
	if err := service.commitDocumentSignature(
		recordID,
		issuedCertificate,
		documentHash,
		signatureHash,
		documentPolicyID,
		signedPDFHash,
	); err != nil {
		return nil, nil, err
	}

	finalCombinedPDF := combinedPDF
	finalSignResult := signResult

	return finalCombinedPDF, finalSignResult, nil
}

func (service *Service) VerifyEmbeddedPDF(signedPdfBytes []byte) (*VerifyResult, error) {
	startIdx := bytes.LastIndex(signedPdfBytes, []byte(SignatureMarkerStart))
	endIdx := bytes.LastIndex(signedPdfBytes, []byte(SignatureMarkerEnd))

	if startIdx == -1 || endIdx == -1 || startIdx >= endIdx {
		return nil, fmt.Errorf("no embedded signature found in PDF")
	}

	originalPdf := signedPdfBytes[:startIdx]
	jsonBytes := signedPdfBytes[startIdx+len(SignatureMarkerStart) : endIdx]

	var sidecar SignResult
	if err := json.Unmarshal(jsonBytes, &sidecar); err != nil {
		return nil, fmt.Errorf("invalid embedded signature json: %w", err)
	}

	signedPdfHash := cryptoutil.SHA256Tagged(signedPdfBytes)

	verificationResult, err := service.verifySignatureInternal(originalPdf, sidecar, signedPdfHash)
	return verificationResult, err
}

func (service *Service) verifySignatureInternal(pdfBytes []byte, sidecar SignResult, signedPdfHash string) (*VerifyResult, error) {
	// Step 1: Validate input integrity.
	if err := validateVerifyInputs(pdfBytes, sidecar.CertificatePEM, sidecar.SignatureBase64); err != nil {
		return nil, err
	}

	certificate, err := authority.ParseCertificatePEM(sidecar.CertificatePEM)
	if err != nil {
		return nil, err
	}

	// Step 2: Verify the certificate chain is trusted by our Authority.
	// The ledger is the source of truth for single-use and post-issuance validity,
	// so verification must not fail only because an ephemeral certificate has expired.
	if err := service.authority.VerifyIssuedCertificateTrustOnly(certificate); err != nil {
		return nil, err
	}

	signatureBytes, err := decodeSignature(sidecar.SignatureBase64)
	if err != nil {
		return nil, err
	}

	documentHash := cryptoutil.SHA256Tagged(pdfBytes)
	documentDigest := cryptoutil.SHA256Digest(pdfBytes)

	// Step 3: Cryptographically verify the signature against the document and certificate.
	signatureValid, err := verifySignatureMath(certificate, documentDigest, signatureBytes)
	if err != nil {
		return nil, err
	}

	certificateHash := cryptoutil.SHA256Tagged(certificate.Raw)
	signatureHash := cryptoutil.SHA256Tagged(signatureBytes)

	// Step 4: Verify against the Ledger to guarantee non-repudiation and single-use enforcement.
	recordVerification, err := service.chain.VerifyRecord(localchain.VerifyRecordInput{
		CertHash:      certificateHash,
		DocumentHash:  documentHash,
		SignedPDFHash: signedPdfHash,
		SignatureHash: signatureHash,
	})
	if err != nil {
		return nil, fmt.Errorf("verify record: %w", err)
	}

	verifyResult := newVerifyResult(
		documentHash,
		sidecar.SignerName,
		sidecar.SignerEmail,
		authority.ExtractDocumentHash(certificate),
		authority.ExtractPolicyID(certificate),
		authority.ExtractSingleUse(certificate),
		signatureValid,
		certificateHash,
		signatureHash,
		recordVerification,
	)

	return verifyResult, nil
}

func validateVerifyInputs(pdfBytes []byte, certificatePEM string, signatureBase64 string) error {
	if err := ValidatePDFBytes(pdfBytes); err != nil {
		return err
	}
	if certificatePEM == "" || signatureBase64 == "" {
		return fmt.Errorf("certificate_pem and signature_base64 are required")
	}
	return nil
}

func verifySignatureMath(certificate *x509.Certificate, documentDigest [32]byte, signatureBytes []byte) (bool, error) {
	certificatePublicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok {
		return false, fmt.Errorf("certificate public key is not ed25519")
	}
	return ed25519.Verify(certificatePublicKey, documentDigest[:], signatureBytes), nil
}

func normalizeDocumentFileName(fileName string) string {
	if fileName == "" {
		return "document.pdf"
	}
	return strings.ReplaceAll(fileName, " ", "_")
}

func normalizePolicyID(policyID string) string {
	if policyID == "" {
		return DefaultPolicyID
	}
	return policyID
}

func disposeIssuedPrivateKey(issuedCertificate *authority.IssuedDocumentCertificate) {
	if issuedCertificate == nil {
		return
	}

	privateKeyBytes := issuedCertificate.PrivateKey
	cryptoutil.ZeroBytes(privateKeyBytes)
	cryptoutil.ZeroBytes(issuedCertificate.PrivateKey)
	issuedCertificate.PrivateKey = nil
}

func decodeSignature(signatureBase64 string) ([]byte, error) {
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	return signatureBytes, nil
}

func (service *Service) newIssuedCertificateEvent(
	issuedCertificate *authority.IssuedDocumentCertificate,
	documentHash string,
	policyID string,
) localchain.Event {
	certificateIssuedPayload := localchain.CertificateIssuedPayload{
		CertHash:      issuedCertificate.CertHash,
		PublicKeyHash: issuedCertificate.PublicKeyHash,
		IssuerID:      service.authority.IssuerID(),
		DocumentHash:  documentHash,
		PolicyID:      policyID,
		SingleUse:     true,
		ValidFrom:     issuedCertificate.Certificate.NotBefore.UTC().Format(time.RFC3339),
		ValidUntil:    issuedCertificate.Certificate.NotAfter.UTC().Format(time.RFC3339),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	return localchain.Event{
		Type:    localchain.EventTypeCertificateIssued,
		Payload: certificateIssuedPayload,
	}
}

func (service *Service) newDocumentSignatureEvent(
	recordID string,
	certificateHash string,
	documentHash string,
	signatureHash string,
	policyID string,
	signedPDFHash string,
) localchain.Event {
	signatureRegisteredPayload := localchain.SignatureRegisteredPayload{
		RecordID:      recordID,
		CertHash:      certificateHash,
		DocumentHash:  documentHash,
		SignedPDFHash: signedPDFHash,
		SignatureHash: signatureHash,
		IssuerID:      service.authority.IssuerID(),
		PolicyID:      policyID,
		SignedAt:      time.Now().UTC().Format(time.RFC3339),
		Status:        "VALID",
	}

	return localchain.Event{
		Type:    localchain.EventTypeSignatureRegistered,
		Payload: signatureRegisteredPayload,
	}
}

func (service *Service) commitDocumentSignature(
	recordID string,
	issuedCertificate *authority.IssuedDocumentCertificate,
	documentHash string,
	signatureHash string,
	policyID string,
	signedPDFHash string,
) error {
	events := []localchain.Event{
		service.newIssuedCertificateEvent(issuedCertificate, documentHash, policyID),
		service.newDocumentSignatureEvent(
			recordID,
			issuedCertificate.CertHash,
			documentHash,
			signatureHash,
			policyID,
			signedPDFHash,
		),
	}

	if err := service.chain.CommitEvents(events, service.store.AppendBlocks); err != nil {
		return fmt.Errorf("commit single-use signature: %w", err)
	}
	return nil
}

func (service *Service) nextRecordID() string {
	return "pdfsig-" + strconv.FormatUint(service.recordSeq.Add(1), 10)
}

func newSignResult(
	issuerID string,
	fileName string,
	policyID string,
	documentHash string,
	signatureBytes []byte,
	signatureHash string,
	recordID string,
	identity SignerIdentity,
	issuedCertificate *authority.IssuedDocumentCertificate,
) *SignResult {
	encodedSignature := base64.StdEncoding.EncodeToString(signatureBytes)

	return &SignResult{
		Mode:              "hash-only",
		FileName:          fileName,
		IssuerID:          issuerID,
		SignerName:        identity.CommonName,
		SignerEmail:       identity.EmailAddress,
		DocumentHash:      documentHash,
		SignedHashBase64:  encodedSignature,
		SignatureBase64:   encodedSignature,
		SignatureHash:     signatureHash,
		CertificatePEM:    issuedCertificate.CertificatePEM,
		CertHash:          issuedCertificate.CertHash,
		PublicKeyHash:     issuedCertificate.PublicKeyHash,
		PolicyID:          policyID,
		SingleUse:         true,
		RecordID:          recordID,
		SignedPDFHash:     documentHash,
		EphemeralDisposed: true,
	}
}

func newVerifyResult(
	documentHash string,
	signerName string,
	signerEmail string,
	certificateDocumentHash string,
	policyID string,
	singleUseEnabled bool,
	signatureValid bool,
	certificateHash string,
	signatureHash string,
	recordVerification *localchain.RecordVerificationResult,
) *VerifyResult {
	certificateMatchesDocument := certificateDocumentHash == documentHash
	verificationPassed := signatureValid &&
		certificateMatchesDocument &&
		singleUseEnabled &&
		recordVerification.Valid

	return &VerifyResult{
		Valid:                      verificationPassed,
		DocumentHash:               documentHash,
		SignerName:                 signerName,
		SignerEmail:                signerEmail,
		CertificateTrusted:         true,
		CertificateDocumentHash:    certificateDocumentHash,
		CertificateDocumentMatches: certificateMatchesDocument,
		PolicyID:                   policyID,
		SingleUseInCertificate:     singleUseEnabled,
		SignatureValid:             signatureValid,
		LedgerRecordValid:          recordVerification.Valid,
		SingleUseConfirmed:         recordVerification.SingleUseConfirmed,
		RecordID:                   recordVerification.RecordID,
		CertHash:                   certificateHash,
		SignatureHash:              signatureHash,
		CertificateRevoked:         recordVerification.CertificateRevoked,
		SignatureRevoked:           recordVerification.SignatureRevoked,
	}
}
