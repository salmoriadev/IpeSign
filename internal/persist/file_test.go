package persist

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"crypto/ed25519"

	"ipesign/internal/cryptoutil"
	"ipesign/internal/ledger/localchain"
)

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
