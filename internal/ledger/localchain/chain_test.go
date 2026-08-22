package localchain

import (
	"errors"
	"fmt"
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

func TestCommitEventsRollsBackWholeBatchWhenPersistenceFails(t *testing.T) {
	_, privateKey, err := GenerateSealer()
	if err != nil {
		t.Fatalf("GenerateSealer() error = %v", err)
	}

	chain, err := NewChain(Config{Signer: privateKey})
	if err != nil {
		t.Fatalf("NewChain() error = %v", err)
	}
	if _, err := chain.AppendEvent(EventTypeIssuerRegistered, IssuerRegisteredPayload{
		IssuerID: "ipe-city",
		Name:     "Ipe City",
	}); err != nil {
		t.Fatalf("AppendEvent(issuer) error = %v", err)
	}

	certificate := CertificateIssuedPayload{
		CertHash:      "sha256:atomic-cert",
		PublicKeyHash: "sha256:atomic-key",
		IssuerID:      "ipe-city",
		DocumentHash:  "sha256:atomic-document",
		PolicyID:      "participation-v1",
		SingleUse:     true,
	}
	signature := SignatureRegisteredPayload{
		RecordID:      "pdfsig-atomic",
		CertHash:      certificate.CertHash,
		DocumentHash:  certificate.DocumentHash,
		SignedPDFHash: "sha256:atomic-signed-pdf",
		SignatureHash: "sha256:atomic-signature",
		IssuerID:      certificate.IssuerID,
		PolicyID:      certificate.PolicyID,
	}
	events := []Event{
		{Type: EventTypeCertificateIssued, Payload: certificate},
		{Type: EventTypeSignatureRegistered, Payload: signature},
	}

	persistErr := errors.New("disk unavailable")
	err = chain.CommitEvents(events, func([]Block) error { return persistErr })
	if !errors.Is(err, persistErr) {
		t.Fatalf("CommitEvents() error = %v, want %v", err, persistErr)
	}
	if chain.Len() != 2 {
		t.Fatalf("chain length after rollback = %d, want 2", chain.Len())
	}
	if chain.GetCertificateNode(certificate.CertHash) != nil {
		t.Fatal("rolled-back certificate remained indexed")
	}
	if chain.GetSignatureNode(signature.CertHash) != nil {
		t.Fatal("rolled-back signature remained indexed")
	}

	var persisted []Block
	if err := chain.CommitEvents(events, func(blocks []Block) error {
		persisted = append(persisted, blocks...)
		return nil
	}); err != nil {
		t.Fatalf("CommitEvents(retry) error = %v", err)
	}
	if len(persisted) != 2 || chain.Len() != 4 {
		t.Fatalf("persisted blocks = %d, chain length = %d", len(persisted), chain.Len())
	}
}

func BenchmarkVerifyRecordIndexed(b *testing.B) {
	_, privateKey, err := GenerateSealer()
	if err != nil {
		b.Fatal(err)
	}
	chain, err := NewChain(Config{Signer: privateKey})
	if err != nil {
		b.Fatal(err)
	}
	if _, err := chain.AppendEvent(EventTypeIssuerRegistered, IssuerRegisteredPayload{
		IssuerID: "ipe-city",
		Name:     "Ipe City",
	}); err != nil {
		b.Fatal(err)
	}

	const records = 1_000
	for index := 0; index < records; index++ {
		suffix := fmt.Sprintf("%04d", index)
		certificate := CertificateIssuedPayload{
			CertHash:      "sha256:cert-" + suffix,
			PublicKeyHash: "sha256:key-" + suffix,
			IssuerID:      "ipe-city",
			DocumentHash:  "sha256:doc-" + suffix,
			PolicyID:      "participation-v1",
			SingleUse:     true,
		}
		if _, err := chain.AppendEvent(EventTypeCertificateIssued, certificate); err != nil {
			b.Fatal(err)
		}
		if _, err := chain.AppendEvent(EventTypeSignatureRegistered, SignatureRegisteredPayload{
			RecordID:      "pdfsig-" + suffix,
			CertHash:      certificate.CertHash,
			DocumentHash:  certificate.DocumentHash,
			SignedPDFHash: "sha256:signed-" + suffix,
			SignatureHash: "sha256:sig-" + suffix,
			IssuerID:      certificate.IssuerID,
			PolicyID:      certificate.PolicyID,
		}); err != nil {
			b.Fatal(err)
		}
	}

	input := VerifyRecordInput{
		CertHash:      "sha256:cert-0999",
		DocumentHash:  "sha256:doc-0999",
		SignedPDFHash: "sha256:signed-0999",
		SignatureHash: "sha256:sig-0999",
	}
	b.Run("IndexedRecord", func(b *testing.B) {
		for index := 0; index < b.N; index++ {
			result, err := chain.VerifyRecord(input)
			if err != nil || !result.Valid {
				b.Fatalf("VerifyRecord() result = %+v, error = %v", result, err)
			}
		}
	})
	b.Run("FullChainAudit", func(b *testing.B) {
		for index := 0; index < b.N; index++ {
			report, err := chain.Verify()
			if err != nil || !report.Valid {
				b.Fatalf("Verify() report = %+v, error = %v", report, err)
			}
		}
	})
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
