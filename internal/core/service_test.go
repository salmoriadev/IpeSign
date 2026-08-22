package core

import (
	"fmt"
	"path/filepath"
	"sync"
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

func TestServiceSignsConcurrentlyWithoutBreakingSingleUseLedger(t *testing.T) {
	service, err := NewService(Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		MasterKey: "concurrency-master-key",
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	pdf := []byte("%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF")
	const signatures = 16

	errorsChannel := make(chan error, signatures)
	recordIDs := make(chan string, signatures)
	var waitGroup sync.WaitGroup
	for index := 0; index < signatures; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()

			signedPDF, result, err := service.SignPDF(
				pdf,
				fmt.Sprintf("document-%d.pdf", index),
				DefaultPolicyID,
				SignerIdentity{},
			)
			if err != nil {
				errorsChannel <- fmt.Errorf("sign %d: %w", index, err)
				return
			}
			verification, err := service.VerifyEmbeddedPDF(signedPDF)
			if err != nil {
				errorsChannel <- fmt.Errorf("verify %d: %w", index, err)
				return
			}
			if !verification.Valid || !verification.SingleUseConfirmed {
				errorsChannel <- fmt.Errorf("verify %d returned invalid result", index)
				return
			}
			recordIDs <- result.RecordID
		}(index)
	}

	waitGroup.Wait()
	close(errorsChannel)
	close(recordIDs)
	for err := range errorsChannel {
		t.Error(err)
	}

	seenRecordIDs := make(map[string]struct{}, signatures)
	for recordID := range recordIDs {
		if _, exists := seenRecordIDs[recordID]; exists {
			t.Errorf("duplicate record id %q", recordID)
		}
		seenRecordIDs[recordID] = struct{}{}
	}
	if len(seenRecordIDs) != signatures {
		t.Fatalf("record ids = %d, want %d", len(seenRecordIDs), signatures)
	}

	report, err := service.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain() error = %v", err)
	}
	wantBlocks := 2 + signatures*2 // genesis + issuer + certificate/signature pairs
	if report.BlocksVerified != wantBlocks {
		t.Fatalf("verified blocks = %d, want %d", report.BlocksVerified, wantBlocks)
	}
}

func BenchmarkServiceSignPDF(b *testing.B) {
	service, err := NewService(Config{
		DataDir:   filepath.Join(b.TempDir(), "data"),
		MasterKey: "benchmark-master-key",
	})
	if err != nil {
		b.Fatalf("NewService() error = %v", err)
	}

	pdf := []byte("%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF")
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, _, err := service.SignPDF(pdf, "benchmark.pdf", DefaultPolicyID, SignerIdentity{}); err != nil {
			b.Fatalf("SignPDF() error = %v", err)
		}
	}
}
