package localchain

import (
	"errors"
	"testing"
	"time"
)

func TestChainAppendTraversalAndVerify(t *testing.T) {
	pub, priv, err := GenerateSealer()
	if err != nil {
		t.Fatalf("GenerateSealer() error = %v", err)
	}

	clock := steppedClock(time.Date(2026, 4, 24, 14, 0, 0, 0, time.UTC), time.Second)
	chain, err := NewChain(Config{
		Signer:    priv,
		VerifyKey: pub,
		Clock:     clock,
	})
	if err != nil {
		t.Fatalf("NewChain() error = %v", err)
	}

	if _, err := chain.AppendEvent(EventTypeIssuerRegistered, IssuerRegisteredPayload{
		IssuerID: "ipe-city",
		Name:     "Ipê City",
	}); err != nil {
		t.Fatalf("AppendEvent(issuer) error = %v", err)
	}

	cert := CertificateIssuedPayload{
		CertHash:      "sha256:cert-001",
		PublicKeyHash: "sha256:pub-001",
		IssuerID:      "ipe-city",
		DocumentHash:  "sha256:doc-001",
		PolicyID:      "participation-v1",
		SingleUse:     true,
	}
	if _, err := chain.AppendEvent(EventTypeCertificateIssued, cert); err != nil {
		t.Fatalf("AppendEvent(cert) error = %v", err)
	}

	signature := SignatureRegisteredPayload{
		RecordID:      "pdfsig-001",
		CertHash:      cert.CertHash,
		DocumentHash:  cert.DocumentHash,
		SignedPDFHash: "sha256:signed-pdf-001",
		SignatureHash: "sha256:signature-001",
		IssuerID:      cert.IssuerID,
		PolicyID:      cert.PolicyID,
		Status:        "VALID",
	}
	if _, err := chain.AppendEvent(EventTypeSignatureRegistered, signature); err != nil {
		t.Fatalf("AppendEvent(signature) error = %v", err)
	}

	var forward []string
	if err := chain.TraverseForward(func(node *Node) error {
		forward = append(forward, node.Block.EventType)
		return nil
	}); err != nil {
		t.Fatalf("TraverseForward() error = %v", err)
	}

	wantForward := []string{
		EventTypeGenesis,
		EventTypeIssuerRegistered,
		EventTypeCertificateIssued,
		EventTypeSignatureRegistered,
	}
	assertStringSliceEqual(t, "forward traversal", forward, wantForward)

	var backward []string
	if err := chain.TraverseBackward(func(node *Node) error {
		backward = append(backward, node.Block.EventType)
		return nil
	}); err != nil {
		t.Fatalf("TraverseBackward() error = %v", err)
	}

	wantBackward := []string{
		EventTypeSignatureRegistered,
		EventTypeCertificateIssued,
		EventTypeIssuerRegistered,
		EventTypeGenesis,
	}
	assertStringSliceEqual(t, "backward traversal", backward, wantBackward)

	report, err := chain.Verify()
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !report.Valid {
		t.Fatalf("Verify() valid = false")
	}

	if report.BlocksVerified != 4 {
		t.Fatalf("Verify() blocks = %d, want 4", report.BlocksVerified)
	}

	result, err := chain.VerifyRecord(VerifyRecordInput{
		CertHash:      cert.CertHash,
		DocumentHash:  cert.DocumentHash,
		SignedPDFHash: signature.SignedPDFHash,
		SignatureHash: signature.SignatureHash,
	})
	if err != nil {
		t.Fatalf("VerifyRecord() error = %v", err)
	}

	if !result.Valid {
		t.Fatalf("VerifyRecord() valid = false")
	}

	if !result.SingleUseConfirmed {
		t.Fatalf("VerifyRecord() singleUseConfirmed = false")
	}
}

func TestChainRejectsDuplicateSingleUse(t *testing.T) {
	_, priv, err := GenerateSealer()
	if err != nil {
		t.Fatalf("GenerateSealer() error = %v", err)
	}

	chain, err := NewChain(Config{Signer: priv})
	if err != nil {
		t.Fatalf("NewChain() error = %v", err)
	}

	if _, err := chain.AppendEvent(EventTypeIssuerRegistered, IssuerRegisteredPayload{
		IssuerID: "ipe-city",
		Name:     "Ipê City",
	}); err != nil {
		t.Fatalf("AppendEvent(issuer) error = %v", err)
	}

	cert := CertificateIssuedPayload{
		CertHash:      "sha256:cert-unique",
		PublicKeyHash: "sha256:pub-unique",
		IssuerID:      "ipe-city",
		DocumentHash:  "sha256:doc-unique",
		PolicyID:      "participation-v1",
		SingleUse:     true,
	}
	if _, err := chain.AppendEvent(EventTypeCertificateIssued, cert); err != nil {
		t.Fatalf("AppendEvent(cert) error = %v", err)
	}

	firstSig := SignatureRegisteredPayload{
		RecordID:      "pdfsig-001",
		CertHash:      cert.CertHash,
		DocumentHash:  cert.DocumentHash,
		SignedPDFHash: "sha256:signed-1",
		SignatureHash: "sha256:sig-1",
		IssuerID:      cert.IssuerID,
		PolicyID:      cert.PolicyID,
	}
	if _, err := chain.AppendEvent(EventTypeSignatureRegistered, firstSig); err != nil {
		t.Fatalf("AppendEvent(first signature) error = %v", err)
	}

	secondSig := SignatureRegisteredPayload{
		RecordID:      "pdfsig-002",
		CertHash:      cert.CertHash,
		DocumentHash:  cert.DocumentHash,
		SignedPDFHash: "sha256:signed-2",
		SignatureHash: "sha256:sig-2",
		IssuerID:      cert.IssuerID,
		PolicyID:      cert.PolicyID,
	}
	_, err = chain.AppendEvent(EventTypeSignatureRegistered, secondSig)
	if !errors.Is(err, ErrCertificateAlreadyUsed) {
		t.Fatalf("AppendEvent(second signature) error = %v, want ErrCertificateAlreadyUsed", err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	pub, priv, err := GenerateSealer()
	if err != nil {
		t.Fatalf("GenerateSealer() error = %v", err)
	}

	chain, err := NewChain(Config{
		Signer:    priv,
		VerifyKey: pub,
	})
	if err != nil {
		t.Fatalf("NewChain() error = %v", err)
	}

	if _, err := chain.AppendEvent(EventTypeIssuerRegistered, IssuerRegisteredPayload{
		IssuerID: "ipe-city",
		Name:     "Ipê City",
	}); err != nil {
		t.Fatalf("AppendEvent(issuer) error = %v", err)
	}

	cert := CertificateIssuedPayload{
		CertHash:      "sha256:cert-001",
		PublicKeyHash: "sha256:pub-001",
		IssuerID:      "ipe-city",
		DocumentHash:  "sha256:doc-001",
		PolicyID:      "participation-v1",
		SingleUse:     true,
	}
	if _, err := chain.AppendEvent(EventTypeCertificateIssued, cert); err != nil {
		t.Fatalf("AppendEvent(cert) error = %v", err)
	}

	middle := chain.GetCertificateNode(cert.CertHash)
	if middle == nil {
		t.Fatalf("GetCertificateNode() returned nil")
	}

	middle.Block.Payload = []byte(`{"certHash":"sha256:cert-001","documentHash":"sha256:tampered"}`)

	if _, err := chain.Verify(); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("Verify() error = %v, want ErrVerificationFailed", err)
	}
}

func TestOpenChainFromSnapshotKeepsTraversal(t *testing.T) {
	pub, priv, err := GenerateSealer()
	if err != nil {
		t.Fatalf("GenerateSealer() error = %v", err)
	}

	chain, err := NewChain(Config{
		Signer:    priv,
		VerifyKey: pub,
	})
	if err != nil {
		t.Fatalf("NewChain() error = %v", err)
	}

	if _, err := chain.AppendEvent(EventTypeIssuerRegistered, IssuerRegisteredPayload{
		IssuerID: "ipe-city",
		Name:     "Ipê City",
	}); err != nil {
		t.Fatalf("AppendEvent(issuer) error = %v", err)
	}

	restored, err := OpenChain(Config{VerifyKey: pub}, chain.Snapshot())
	if err != nil {
		t.Fatalf("OpenChain() error = %v", err)
	}

	var count int
	if err := restored.TraverseForward(func(node *Node) error {
		count++
		return nil
	}); err != nil {
		t.Fatalf("TraverseForward() error = %v", err)
	}

	if count != 2 {
		t.Fatalf("TraverseForward() count = %d, want 2", count)
	}

	if _, err := restored.AppendEvent(EventTypeIssuerRegistered, IssuerRegisteredPayload{
		IssuerID: "other",
		Name:     "Other",
	}); !errors.Is(err, ErrChainReadOnly) {
		t.Fatalf("AppendEvent() error = %v, want ErrChainReadOnly", err)
	}
}

func steppedClock(start time.Time, step time.Duration) func() time.Time {
	current := start.Add(-step)
	return func() time.Time {
		current = current.Add(step)
		return current
	}
}

func assertStringSliceEqual(t *testing.T, name string, got, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("%s length = %d, want %d", name, len(got), len(want))
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s[%d] = %q, want %q", name, i, got[i], want[i])
		}
	}
}
