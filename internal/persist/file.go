package persist

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"ipesign/internal/ledger/localchain"
)

const (
	rootCACertFilename  = "root-ca-cert.pem"
	rootCAKeyFilename   = "root-ca-key"
	caCertFilename      = "ca-cert.pem"
	caKeyFilename       = "ca-key.pem"
	ledgerKeyFilename   = "ledger-key.pem"
	chainFilename       = "chain.jsonl"
	legacyChainFilename = "chain.json"
)

type FileStore struct {
	dir              string
	privateBlobCodec PrivateBlobCodec
	mu               sync.Mutex
}

func NewFileStore(dir string, masterKey string) *FileStore {
	if dir == "" {
		dir = DefaultDir
	}

	return &FileStore{
		dir:              dir,
		privateBlobCodec: NewPassphrasePrivateBlobCodec(masterKey),
	}
}

func (s *FileStore) Backend() string {
	return "file"
}

func (s *FileStore) Exists() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	required := []string{
		filepath.Join(s.dir, caCertFilename),
		filepath.Join(s.dir, caKeyFilename),
		filepath.Join(s.dir, ledgerKeyFilename),
	}

	for _, path := range required {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}

			return false, err
		}
	}

	if _, err := os.Stat(filepath.Join(s.dir, chainFilename)); err == nil {
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}

	if _, err := os.Stat(filepath.Join(s.dir, legacyChainFilename)); err == nil {
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}

	return false, nil
}

func (s *FileStore) Load() (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rootCACertPEM, err := readOptionalFile(filepath.Join(s.dir, rootCACertFilename))
	if err != nil {
		return nil, fmt.Errorf("read root CA certificate: %w", err)
	}

	rootCAKeyRaw, err := readOptionalFile(filepath.Join(s.dir, rootCAKeyFilename))
	if err != nil {
		return nil, fmt.Errorf("read root CA private key: %w", err)
	}

	rootCAKeyPEM, err := s.decodePrivateBlob(rootCAKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("decode root CA private key: %w", err)
	}

	caCertPEM, err := os.ReadFile(filepath.Join(s.dir, caCertFilename))
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}

	caKeyRaw, err := os.ReadFile(filepath.Join(s.dir, caKeyFilename))
	if err != nil {
		return nil, fmt.Errorf("read CA private key: %w", err)
	}

	caKeyPEM, err := s.decodePrivateBlob(caKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("decode CA private key: %w", err)
	}

	ledgerKeyRaw, err := os.ReadFile(filepath.Join(s.dir, ledgerKeyFilename))
	if err != nil {
		return nil, fmt.Errorf("read ledger private key: %w", err)
	}

	ledgerKeyPEM, err := s.decodePrivateBlob(ledgerKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("decode ledger private key: %w", err)
	}

	ledgerKey, err := decodeEd25519PrivateKeyPEM(ledgerKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse ledger private key: %w", err)
	}

	state := &State{
		RootCACertPEM: rootCACertPEM,
		RootCAKeyPEM:  rootCAKeyPEM,
		CACertPEM:     caCertPEM,
		CAKeyPEM:      caKeyPEM,
		LedgerKey:     ledgerKey,
	}
	state.Blocks, err = s.loadBlocks()
	if err != nil {
		return nil, err
	}

	return state, nil
}

func (s *FileStore) Save(state *State) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validateState(state); err != nil {
		return err
	}

	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	ledgerKeyPEM, err := encodeEd25519PrivateKeyPEM(state.LedgerKey)
	if err != nil {
		return fmt.Errorf("encode ledger private key: %w", err)
	}

	sealedCAKey, err := s.privateBlobCodec.Seal(state.CAKeyPEM)
	if err != nil {
		return fmt.Errorf("seal CA private key: %w", err)
	}

	sealedLedgerKey, err := s.privateBlobCodec.Seal(ledgerKeyPEM)
	if err != nil {
		return fmt.Errorf("seal ledger private key: %w", err)
	}

	var sealedRootCAKey []byte
	if len(state.RootCAKeyPEM) > 0 {
		sealedRootCAKey, err = s.privateBlobCodec.Seal(state.RootCAKeyPEM)
		if err != nil {
			return fmt.Errorf("seal root CA private key: %w", err)
		}
	}

	rawBlocks, err := marshalBlockBatch(state.Blocks)
	if err != nil {
		return fmt.Errorf("encode chain snapshot: %w", err)
	}

	if len(state.RootCACertPEM) > 0 {
		if err := writeFileAtomic(filepath.Join(s.dir, rootCACertFilename), state.RootCACertPEM, 0o644); err != nil {
			return err
		}
	}

	if len(sealedRootCAKey) > 0 {
		if err := writeFileAtomic(filepath.Join(s.dir, rootCAKeyFilename), sealedRootCAKey, 0o600); err != nil {
			return err
		}
	}

	if err := writeFileAtomic(filepath.Join(s.dir, caCertFilename), state.CACertPEM, 0o644); err != nil {
		return err
	}

	if err := writeFileAtomic(filepath.Join(s.dir, caKeyFilename), sealedCAKey, 0o600); err != nil {
		return err
	}

	if err := writeFileAtomic(filepath.Join(s.dir, ledgerKeyFilename), sealedLedgerKey, 0o600); err != nil {
		return err
	}

	if err := writeFileAtomic(filepath.Join(s.dir, chainFilename), rawBlocks, 0o644); err != nil {
		return err
	}

	return nil
}

// AppendBlocks persists a complete domain operation as one append-only batch.
// Authority keys are intentionally not rewritten or re-encrypted here.
func (s *FileStore) AppendBlocks(blocks []localchain.Block) error {
	if len(blocks) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureAppendOnlyLedger(); err != nil {
		return err
	}

	raw, err := marshalBlockBatch(blocks)
	if err != nil {
		return err
	}

	path := filepath.Join(s.dir, chainFilename)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open ledger for append: %w", err)
	}

	written, writeErr := file.Write(raw)
	if writeErr == nil && written != len(raw) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()

	if writeErr != nil {
		return fmt.Errorf("append ledger batch: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close ledger: %w", closeErr)
	}

	return nil
}

func (s *FileStore) loadBlocks() ([]localchain.Block, error) {
	path := filepath.Join(s.dir, chainFilename)
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()

		decoder := json.NewDecoder(file)
		var blocks []localchain.Block
		for {
			var batch []localchain.Block
			if err := decoder.Decode(&batch); err != nil {
				if err == io.EOF {
					break
				}
				return nil, fmt.Errorf("decode append-only ledger: %w", err)
			}
			blocks = append(blocks, batch...)
		}

		return blocks, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("open append-only ledger: %w", err)
	}

	raw, err := os.ReadFile(filepath.Join(s.dir, legacyChainFilename))
	if err != nil {
		return nil, fmt.Errorf("read legacy chain snapshot: %w", err)
	}

	var blocks []localchain.Block
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return nil, fmt.Errorf("decode legacy chain snapshot: %w", err)
	}

	return blocks, nil
}

func (s *FileStore) ensureAppendOnlyLedger() error {
	path := filepath.Join(s.dir, chainFilename)
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	legacyRaw, err := os.ReadFile(filepath.Join(s.dir, legacyChainFilename))
	if err != nil {
		return fmt.Errorf("read legacy chain snapshot: %w", err)
	}

	var blocks []localchain.Block
	if err := json.Unmarshal(legacyRaw, &blocks); err != nil {
		return fmt.Errorf("decode legacy chain snapshot: %w", err)
	}

	raw, err := marshalBlockBatch(blocks)
	if err != nil {
		return err
	}

	return writeFileAtomic(path, raw, 0o644)
}

func marshalBlockBatch(blocks []localchain.Block) ([]byte, error) {
	raw, err := json.Marshal(blocks)
	if err != nil {
		return nil, fmt.Errorf("encode ledger batch: %w", err)
	}

	return append(raw, '\n'), nil
}

func (s *FileStore) decodePrivateBlob(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	if s.privateBlobCodec.IsSealed(raw) {
		return s.privateBlobCodec.Open(raw)
	}

	return raw, nil
}

func readOptionalFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, err
	}

	return raw, nil
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
