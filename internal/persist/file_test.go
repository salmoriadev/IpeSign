package persist

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"crypto/ed25519"

	"ipesign/internal/cryptoutil"
	"ipesign/internal/ledger/localchain"
)

type countingPrivateBlobCodec struct {
	sealCalls int
}

func (codec *countingPrivateBlobCodec) Seal(plaintext []byte) ([]byte, error) {
	codec.sealCalls++
	return append([]byte("sealed:"), plaintext...), nil
}

func (codec *countingPrivateBlobCodec) Open(raw []byte) ([]byte, error) {
	return append([]byte(nil), bytes.TrimPrefix(raw, []byte("sealed:"))...), nil
}

func (codec *countingPrivateBlobCodec) IsSealed(raw []byte) bool {
	return bytes.HasPrefix(raw, []byte("sealed:"))
}

func TestFileStoreSealsPrivateKeysAtRest(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir, "test-master-key")

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(root) error = %v", err)
	}

	_ = rootPub

	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(ca) error = %v", err)
	}

	_ = caPub

	ledgerPub, ledgerPriv, err := localchain.GenerateSealer()
	if err != nil {
		t.Fatalf("GenerateSealer() error = %v", err)
	}

	_ = ledgerPub

	rootKeyPEM, err := cryptoutil.MarshalEd25519PrivateKeyPEM(rootPriv)
	if err != nil {
		t.Fatalf("MarshalEd25519PrivateKeyPEM(root) error = %v", err)
	}

	caKeyPEM, err := cryptoutil.MarshalEd25519PrivateKeyPEM(caPriv)
	if err != nil {
		t.Fatalf("MarshalEd25519PrivateKeyPEM(ca) error = %v", err)
	}

	state := &State{
		RootCACertPEM: []byte("root-cert"),
		RootCAKeyPEM:  rootKeyPEM,
		CACertPEM:     []byte("ca-cert"),
		CAKeyPEM:      caKeyPEM,
		LedgerKey:     ledgerPriv,
		Blocks:        []localchain.Block{{Index: 0, EventType: localchain.EventTypeGenesis}},
	}

	if err := store.Save(state); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	for _, name := range []string{rootCAKeyFilename, caKeyFilename, ledgerKeyFilename} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", name, err)
		}

		if cryptoutil.LooksLikeSealedBlob(raw) == false {
			t.Fatalf("%s should be stored as sealed blob", name)
		}

		if string(raw) == string(rootKeyPEM) || string(raw) == string(caKeyPEM) {
			t.Fatalf("%s should not be stored as plaintext PEM", name)
		}
	}
}

func TestFileStoreAppendsLedgerWithoutResealingAuthorityKeys(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir, "unused-by-test-codec")
	codec := &countingPrivateBlobCodec{}
	store.privateBlobCodec = codec

	_, authorityKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorityKeyPEM, err := cryptoutil.MarshalEd25519PrivateKeyPEM(authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	_, ledgerKey, err := localchain.GenerateSealer()
	if err != nil {
		t.Fatal(err)
	}
	chain, err := localchain.NewChain(localchain.Config{Signer: ledgerKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.AppendEvent(localchain.EventTypeIssuerRegistered, localchain.IssuerRegisteredPayload{
		IssuerID: "ipe",
		Name:     "Ipe",
	}); err != nil {
		t.Fatal(err)
	}

	initialBlocks := chain.Snapshot()
	state := &State{
		RootCACertPEM: []byte("root-cert"),
		RootCAKeyPEM:  authorityKeyPEM,
		CACertPEM:     []byte("ca-cert"),
		CAKeyPEM:      authorityKeyPEM,
		LedgerKey:     ledgerKey,
		Blocks:        initialBlocks,
	}
	if err := store.Save(state); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if codec.sealCalls != 3 {
		t.Fatalf("seal calls after initialization = %d, want 3", codec.sealCalls)
	}
	// Simulate the pre-append-only format to exercise automatic migration on
	// the first new write.
	if err := os.Rename(
		filepath.Join(dir, chainFilename),
		filepath.Join(dir, legacyChainFilename),
	); err != nil {
		t.Fatalf("prepare legacy ledger: %v", err)
	}

	if _, err := chain.AppendEvent(localchain.EventTypeCertificateIssued, localchain.CertificateIssuedPayload{
		CertHash:      "sha256:cert",
		PublicKeyHash: "sha256:key",
		IssuerID:      "ipe",
		DocumentHash:  "sha256:document",
		PolicyID:      "participation-v1",
		SingleUse:     true,
	}); err != nil {
		t.Fatal(err)
	}
	allBlocks := chain.Snapshot()
	if err := store.AppendBlocks(allBlocks[len(initialBlocks):]); err != nil {
		t.Fatalf("AppendBlocks() error = %v", err)
	}
	if codec.sealCalls != 3 {
		t.Fatalf("append resealed authority keys: seal calls = %d", codec.sealCalls)
	}
	if _, err := os.Stat(filepath.Join(dir, chainFilename)); err != nil {
		t.Fatalf("append-only ledger was not migrated: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(loaded.Blocks) != len(allBlocks) {
		t.Fatalf("loaded blocks = %d, want %d", len(loaded.Blocks), len(allBlocks))
	}
}
