package persist

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"ipesign/internal/cryptoutil"
)

const (
	caCertFilename    = "ca-cert.pem"
	caKeyFilename     = "ca-key.pem"
	ledgerKeyFilename = "ledger-key.pem"
	chainFilename     = "chain.json"
)

type FileStore struct {
	dir string
}

func NewFileStore(dir string) *FileStore {
	if dir == "" {
		dir = DefaultDir
	}

	return &FileStore{dir: dir}
}

func (s *FileStore) Backend() string {
	return "file"
}

func (s *FileStore) Exists() (bool, error) {
	required := []string{
		filepath.Join(s.dir, caCertFilename),
		filepath.Join(s.dir, caKeyFilename),
		filepath.Join(s.dir, ledgerKeyFilename),
		filepath.Join(s.dir, chainFilename),
	}

	for _, path := range required {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}

			return false, err
		}
	}

	return true, nil
}

func (s *FileStore) Load() (*State, error) {
	caCertPEM, err := os.ReadFile(filepath.Join(s.dir, caCertFilename))
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}

	caKeyPEM, err := os.ReadFile(filepath.Join(s.dir, caKeyFilename))
	if err != nil {
		return nil, fmt.Errorf("read CA private key: %w", err)
	}

	ledgerKeyPEM, err := os.ReadFile(filepath.Join(s.dir, ledgerKeyFilename))
	if err != nil {
		return nil, fmt.Errorf("read ledger private key: %w", err)
	}

	ledgerKey, err := cryptoutil.ParseEd25519PrivateKeyPEM(ledgerKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse ledger private key: %w", err)
	}

	rawBlocks, err := os.ReadFile(filepath.Join(s.dir, chainFilename))
	if err != nil {
		return nil, fmt.Errorf("read chain snapshot: %w", err)
	}

	state := &State{
		CACertPEM: caCertPEM,
		CAKeyPEM:  caKeyPEM,
		LedgerKey: ledgerKey,
	}
	if err := json.Unmarshal(rawBlocks, &state.Blocks); err != nil {
		return nil, fmt.Errorf("decode chain snapshot: %w", err)
	}

	return state, nil
}

func (s *FileStore) Save(state *State) error {
	if err := validateState(state); err != nil {
		return err
	}

	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	ledgerKeyPEM, err := cryptoutil.MarshalEd25519PrivateKeyPEM(state.LedgerKey)
	if err != nil {
		return fmt.Errorf("encode ledger private key: %w", err)
	}

	rawBlocks, err := json.MarshalIndent(state.Blocks, "", "  ")
	if err != nil {
		return fmt.Errorf("encode chain snapshot: %w", err)
	}

	if err := writeFileAtomic(filepath.Join(s.dir, caCertFilename), state.CACertPEM, 0o644); err != nil {
		return err
	}

	if err := writeFileAtomic(filepath.Join(s.dir, caKeyFilename), state.CAKeyPEM, 0o600); err != nil {
		return err
	}

	if err := writeFileAtomic(filepath.Join(s.dir, ledgerKeyFilename), ledgerKeyPEM, 0o600); err != nil {
		return err
	}

	if err := writeFileAtomic(filepath.Join(s.dir, chainFilename), rawBlocks, 0o644); err != nil {
		return err
	}

	return nil
}

func writeFileAtomic(path string, content []byte, mode os.FileMode) error {
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, content, mode); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}

	if err := os.Chmod(tempPath, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", filepath.Base(path), err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("rename %s: %w", filepath.Base(path), err)
	}

	return nil
}
