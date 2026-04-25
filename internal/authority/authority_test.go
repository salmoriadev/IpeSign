package authority

import (
	"testing"
	"time"
)

func TestAuthorityIssuesLeafThroughIssuingCAAndRejectsExpiredLeaf(t *testing.T) {
	now := time.Date(2026, 4, 24, 18, 0, 0, 0, time.UTC)
	clockNow := now
	clock := func() time.Time { return clockNow }

	auth, err := New(Config{
		IssuerID:   "ipe",
		IssuerName: "Ipe",
		Clock:      clock,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if auth.RootCertificatePEM() == "" {
		t.Fatalf("RootCertificatePEM() returned empty")
	}

	if auth.RootCertificateHash() == "" || auth.RootPublicKeyHash() == "" {
		t.Fatalf("root authority metadata should be populated")
	}

	issued, err := auth.IssueDocumentCertificate("sha256:doc-001", "participation-v1", CertificateIdentity{})
	if err != nil {
		t.Fatalf("IssueDocumentCertificate() error = %v", err)
	}

	if err := auth.VerifyIssuedCertificate(issued.Certificate); err != nil {
		t.Fatalf("VerifyIssuedCertificate() error = %v", err)
	}

	clockNow = now.Add(15 * time.Minute)
	if err := auth.VerifyIssuedCertificate(issued.Certificate); err == nil {
		t.Fatalf("VerifyIssuedCertificate() expected expiration error")
	}
}
