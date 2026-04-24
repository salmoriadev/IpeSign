package persist

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"ipesign/internal/cryptoutil"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const createStateTableSQL = `
CREATE TABLE IF NOT EXISTS ipesign_state (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    ca_cert_pem BYTEA NOT NULL,
    ca_key_pem BYTEA NOT NULL,
    ledger_key_pem BYTEA NOT NULL,
    chain_snapshot JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(databaseURL string) (*PostgresStore, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("database URL is required")
	}

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	store := &PostgresStore{db: db}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *PostgresStore) Backend() string {
	return "postgres"
}

func (s *PostgresStore) Exists() (bool, error) {
	var exists bool
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM ipesign_state WHERE id = 1)`).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("query state existence: %w", err)
	}

	return exists, nil
}

func (s *PostgresStore) Load() (*State, error) {
	var (
		caCertPEM    []byte
		caKeyPEM     []byte
		ledgerKeyPEM []byte
		rawBlocks    []byte
	)

	err := s.db.QueryRow(`
		SELECT ca_cert_pem, ca_key_pem, ledger_key_pem, chain_snapshot
		FROM ipesign_state
		WHERE id = 1
	`).Scan(&caCertPEM, &caKeyPEM, &ledgerKeyPEM, &rawBlocks)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("postgres state not initialized")
		}

		return nil, fmt.Errorf("load postgres state: %w", err)
	}

	ledgerKey, err := cryptoutil.ParseEd25519PrivateKeyPEM(ledgerKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse ledger private key: %w", err)
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

func (s *PostgresStore) Save(state *State) error {
	if err := validateState(state); err != nil {
		return err
	}

	ledgerKeyPEM, err := cryptoutil.MarshalEd25519PrivateKeyPEM(state.LedgerKey)
	if err != nil {
		return fmt.Errorf("encode ledger private key: %w", err)
	}

	rawBlocks, err := json.Marshal(state.Blocks)
	if err != nil {
		return fmt.Errorf("encode chain snapshot: %w", err)
	}

	_, err = s.db.Exec(`
		INSERT INTO ipesign_state (id, ca_cert_pem, ca_key_pem, ledger_key_pem, chain_snapshot, updated_at)
		VALUES (1, $1, $2, $3, $4::jsonb, NOW())
		ON CONFLICT (id) DO UPDATE SET
			ca_cert_pem = EXCLUDED.ca_cert_pem,
			ca_key_pem = EXCLUDED.ca_key_pem,
			ledger_key_pem = EXCLUDED.ledger_key_pem,
			chain_snapshot = EXCLUDED.chain_snapshot,
			updated_at = NOW()
	`, state.CACertPEM, state.CAKeyPEM, ledgerKeyPEM, rawBlocks)
	if err != nil {
		return fmt.Errorf("save postgres state: %w", err)
	}

	return nil
}

func (s *PostgresStore) migrate() error {
	if _, err := s.db.Exec(createStateTableSQL); err != nil {
		return fmt.Errorf("migrate postgres state: %w", err)
	}

	return nil
}
