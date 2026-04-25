package persist

import (
	"crypto/ed25519"
	"fmt"
	"os"

	"ipesign/internal/ledger/localchain"
)

const DefaultDir = "./data"
const masterKeyEnv = "IPESIGN_MASTER_KEY"

type State struct {
	RootCACertPEM []byte
	RootCAKeyPEM  []byte
	CACertPEM     []byte
	CAKeyPEM      []byte
	LedgerKey     ed25519.PrivateKey
	Blocks        []localchain.Block
}

type StateStore interface {
	Backend() string
	Exists() (bool, error)
	Load() (*State, error)
	Save(*State) error
}

type Config struct {
	DataDir     string
	DatabaseURL string
	MasterKey   string
}

func NewStateStore(cfg Config) (StateStore, error) {
	if cfg.MasterKey == "" {
		cfg.MasterKey = os.Getenv(masterKeyEnv)
	}

	if cfg.MasterKey == "" {
		return nil, fmt.Errorf("%s is required", masterKeyEnv)
	}

	if cfg.DatabaseURL != "" {
		return NewPostgresStore(cfg.DatabaseURL, cfg.MasterKey)
	}

	return NewFileStore(cfg.DataDir, cfg.MasterKey), nil
}

func validateState(state *State) error {
	if state == nil {
		return fmt.Errorf("state is required")
	}

	if len(state.CACertPEM) == 0 {
		return fmt.Errorf("CA certificate is required")
	}

	if len(state.CAKeyPEM) == 0 {
		return fmt.Errorf("CA private key is required")
	}

	if len(state.LedgerKey) == 0 {
		return fmt.Errorf("ledger private key is required")
	}

	if len(state.Blocks) == 0 {
		return fmt.Errorf("chain snapshot is required")
	}

	if (len(state.RootCACertPEM) == 0) != (len(state.RootCAKeyPEM) == 0) {
		return fmt.Errorf("root CA certificate and key must be both present or both absent")
	}

	return nil
}
