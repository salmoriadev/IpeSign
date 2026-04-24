package persist

import (
	"crypto/ed25519"
	"fmt"

	"ipesign/internal/ledger/localchain"
)

const DefaultDir = "./data"

type State struct {
	CACertPEM []byte
	CAKeyPEM  []byte
	LedgerKey ed25519.PrivateKey
	Blocks    []localchain.Block
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
}

func NewStateStore(cfg Config) (StateStore, error) {
	if cfg.DatabaseURL != "" {
		return NewPostgresStore(cfg.DatabaseURL)
	}

	return NewFileStore(cfg.DataDir), nil
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

	return nil
}
