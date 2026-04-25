package core

import (
	"path/filepath"
	"testing"
)

func TestServiceSignsVerifiesAndLoadsRecord(t *testing.T) {
	t.Setenv("IPESIGN_MASTER_KEY", "test-master-key")

	service, err := NewService(Config{
		DataDir: filepath.Join(t.TempDir(), "data"),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	pdf := []byte("%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF")

	signedPdf, signResult, err := service.SignPDF(pdf, "sample.pdf", DefaultPolicyID, SignerIdentity{})
	if err != nil {
	        t.Fatalf("SignPDF() error = %v", err)
	}

	verifyResult, err := service.VerifyEmbeddedPDF(signedPdf)
	if err != nil {
	        t.Fatalf("VerifyEmbeddedPDF() error = %v", err)
	}
	if !verifyResult.Valid || !verifyResult.LedgerRecordValid || !verifyResult.SingleUseConfirmed {
		t.Fatalf("VerifyPDF() invalid result = %+v", verifyResult)
	}

	recordResult, err := service.GetRecord(signResult.RecordID)
	if err != nil {
		t.Fatalf("GetRecord() error = %v", err)
	}

	if !recordResult.Valid {
		t.Fatalf("record should be valid: %+v", recordResult)
	}

	if recordResult.RecordID != signResult.RecordID {
		t.Fatalf("record id = %q, want %q", recordResult.RecordID, signResult.RecordID)
	}

	if recordResult.CertHash != signResult.CertHash {
		t.Fatalf("cert hash = %q, want %q", recordResult.CertHash, signResult.CertHash)
	}

	if !recordResult.SingleUse || !recordResult.SingleUseConfirmed {
		t.Fatalf("single use not confirmed: %+v", recordResult)
	}
}
