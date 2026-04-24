package persist

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"ipesign/internal/cryptoutil"
)

const createStateTableSQL = `
CREATE TABLE IF NOT EXISTS ipesign_state (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    ca_cert_pem_b64 TEXT NOT NULL,
    ca_key_pem_b64 TEXT NOT NULL,
    ledger_key_pem_b64 TEXT NOT NULL,
    chain_snapshot_b64 TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`

type PostgresStore struct {
	databaseURL string
}

func NewPostgresStore(databaseURL string) (*PostgresStore, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("database URL is required")
	}

	if _, err := exec.LookPath("psql"); err != nil {
		return nil, fmt.Errorf("psql not found in PATH")
	}

	store := &PostgresStore{databaseURL: databaseURL}
	if err := store.migrate(); err != nil {
		return nil, err
	}

	return store, nil
}

func (s *PostgresStore) Backend() string {
	return "postgres"
}

func (s *PostgresStore) Exists() (bool, error) {
	output, err := s.runPSQL(`SELECT EXISTS(SELECT 1 FROM ipesign_state WHERE id = 1);`)
	if err != nil {
		return false, err
	}

	return strings.TrimSpace(output) == "t", nil
}

func (s *PostgresStore) Load() (*State, error) {
	query := `
SELECT
  ca_cert_pem_b64,
  ca_key_pem_b64,
  ledger_key_pem_b64,
  chain_snapshot_b64
FROM ipesign_state
WHERE id = 1;`

	output, err := s.runPSQL(query)
	if err != nil {
		return nil, err
	}

	lines := splitPSQLFields(output)
	if len(lines) != 4 {
		return nil, fmt.Errorf("unexpected postgres state shape")
	}

	caCertPEM, err := base64.StdEncoding.DecodeString(lines[0])
	if err != nil {
		return nil, fmt.Errorf("decode CA certificate: %w", err)
	}

	caKeyPEM, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil {
		return nil, fmt.Errorf("decode CA private key: %w", err)
	}

	ledgerKeyPEM, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return nil, fmt.Errorf("decode ledger private key: %w", err)
	}

	rawBlocks, err := base64.StdEncoding.DecodeString(lines[3])
	if err != nil {
		return nil, fmt.Errorf("decode chain snapshot: %w", err)
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

	caCertPEMB64 := base64.StdEncoding.EncodeToString(state.CACertPEM)
	caKeyPEMB64 := base64.StdEncoding.EncodeToString(state.CAKeyPEM)
	ledgerKeyPEMB64 := base64.StdEncoding.EncodeToString(ledgerKeyPEM)
	chainSnapshotB64 := base64.StdEncoding.EncodeToString(rawBlocks)

	query := fmt.Sprintf(`
INSERT INTO ipesign_state (
  id,
  ca_cert_pem_b64,
  ca_key_pem_b64,
  ledger_key_pem_b64,
  chain_snapshot_b64,
  updated_at
) VALUES (
  1,
  $ipesign$%s$ipesign$,
  $ipesign$%s$ipesign$,
  $ipesign$%s$ipesign$,
  $ipesign$%s$ipesign$,
  NOW()
)
ON CONFLICT (id) DO UPDATE SET
  ca_cert_pem_b64 = EXCLUDED.ca_cert_pem_b64,
  ca_key_pem_b64 = EXCLUDED.ca_key_pem_b64,
  ledger_key_pem_b64 = EXCLUDED.ledger_key_pem_b64,
  chain_snapshot_b64 = EXCLUDED.chain_snapshot_b64,
  updated_at = NOW();
`, caCertPEMB64, caKeyPEMB64, ledgerKeyPEMB64, chainSnapshotB64)

	_, err = s.runPSQL(query)
	return err
}

func (s *PostgresStore) migrate() error {
	_, err := s.runPSQL(createStateTableSQL)
	return err
}

func (s *PostgresStore) runPSQL(sql string) (string, error) {
	cmd := exec.Command("psql", s.databaseURL, "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1", "-c", sql)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("psql command failed: %w: %s", err, strings.TrimSpace(string(output)))
	}

	return strings.TrimSpace(string(output)), nil
}

func splitPSQLFields(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}

	lines := strings.Split(trimmed, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		out = append(out, line)
	}

	return out
}
