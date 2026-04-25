package persist

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

const createStateTableSQL = `
CREATE TABLE IF NOT EXISTS ipesign_state (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    root_ca_cert_pem_b64 TEXT,
    root_ca_key_blob_b64 TEXT,
    ca_cert_pem_b64 TEXT NOT NULL,
    ca_key_pem_b64 TEXT,
    ca_key_blob_b64 TEXT NOT NULL,
    ledger_key_pem_b64 TEXT,
    ledger_key_blob_b64 TEXT NOT NULL,
    chain_snapshot_b64 TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE ipesign_state ADD COLUMN IF NOT EXISTS root_ca_cert_pem_b64 TEXT;
ALTER TABLE ipesign_state ADD COLUMN IF NOT EXISTS root_ca_key_blob_b64 TEXT;
ALTER TABLE ipesign_state ADD COLUMN IF NOT EXISTS ca_key_pem_b64 TEXT;
ALTER TABLE ipesign_state ADD COLUMN IF NOT EXISTS ca_key_blob_b64 TEXT;
ALTER TABLE ipesign_state ADD COLUMN IF NOT EXISTS ledger_key_pem_b64 TEXT;
ALTER TABLE ipesign_state ADD COLUMN IF NOT EXISTS ledger_key_blob_b64 TEXT;`

type PostgresStore struct {
	databaseURL      string
	privateBlobCodec PrivateBlobCodec
}

func NewPostgresStore(databaseURL string, masterKey string) (*PostgresStore, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("database URL is required")
	}

	if _, err := exec.LookPath("psql"); err != nil {
		return nil, fmt.Errorf("psql not found in PATH")
	}

	store := &PostgresStore{
		databaseURL:      databaseURL,
		privateBlobCodec: NewPassphrasePrivateBlobCodec(masterKey),
	}
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
  COALESCE(root_ca_cert_pem_b64, ''),
  COALESCE(root_ca_key_blob_b64, ''),
  ca_cert_pem_b64,
  COALESCE(ca_key_blob_b64, ca_key_pem_b64),
  COALESCE(ledger_key_blob_b64, ledger_key_pem_b64),
  chain_snapshot_b64
FROM ipesign_state
WHERE id = 1;`

	output, err := s.runPSQL(query)
	if err != nil {
		return nil, err
	}

	lines := splitPSQLFields(output)
	if len(lines) != 6 {
		return nil, fmt.Errorf("unexpected postgres state shape")
	}

	rootCACertPEM, err := decodeOptionalB64(lines[0])
	if err != nil {
		return nil, fmt.Errorf("decode root CA certificate: %w", err)
	}

	rootCAKeyRaw, err := decodeOptionalB64(lines[1])
	if err != nil {
		return nil, fmt.Errorf("decode root CA private key: %w", err)
	}

	rootCAKeyPEM, err := s.decodePrivateBlob(rootCAKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("decode root CA private key: %w", err)
	}

	caCertPEM, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return nil, fmt.Errorf("decode CA certificate: %w", err)
	}

	caKeyRaw, err := base64.StdEncoding.DecodeString(lines[3])
	if err != nil {
		return nil, fmt.Errorf("decode CA private key: %w", err)
	}

	caKeyPEM, err := s.decodePrivateBlob(caKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("decrypt CA private key: %w", err)
	}

	ledgerKeyRaw, err := base64.StdEncoding.DecodeString(lines[4])
	if err != nil {
		return nil, fmt.Errorf("decode ledger private key: %w", err)
	}

	ledgerKeyPEM, err := s.decodePrivateBlob(ledgerKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("decrypt ledger private key: %w", err)
	}

	rawBlocks, err := base64.StdEncoding.DecodeString(lines[5])
	if err != nil {
		return nil, fmt.Errorf("decode chain snapshot: %w", err)
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
	if err := json.Unmarshal(rawBlocks, &state.Blocks); err != nil {
		return nil, fmt.Errorf("decode chain snapshot: %w", err)
	}

	return state, nil
}

func (s *PostgresStore) Save(state *State) error {
	if err := validateState(state); err != nil {
		return err
	}

	ledgerKeyPEM, err := encodeEd25519PrivateKeyPEM(state.LedgerKey)
	if err != nil {
		return fmt.Errorf("encode ledger private key: %w", err)
	}

	rawBlocks, err := json.Marshal(state.Blocks)
	if err != nil {
		return fmt.Errorf("encode chain snapshot: %w", err)
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

	rootCACertPEMB64 := base64.StdEncoding.EncodeToString(state.RootCACertPEM)
	rootCAKeyBlobB64 := base64.StdEncoding.EncodeToString(sealedRootCAKey)
	caCertPEMB64 := base64.StdEncoding.EncodeToString(state.CACertPEM)
	caKeyBlobB64 := base64.StdEncoding.EncodeToString(sealedCAKey)
	ledgerKeyBlobB64 := base64.StdEncoding.EncodeToString(sealedLedgerKey)
	chainSnapshotB64 := base64.StdEncoding.EncodeToString(rawBlocks)

	query := fmt.Sprintf(`
INSERT INTO ipesign_state (
  id,
  root_ca_cert_pem_b64,
  root_ca_key_blob_b64,
  ca_cert_pem_b64,
  ca_key_pem_b64,
  ca_key_blob_b64,
  ledger_key_pem_b64,
  ledger_key_blob_b64,
  chain_snapshot_b64,
  updated_at
) VALUES (
  1,
  $ipesign$%s$ipesign$,
  $ipesign$%s$ipesign$,
  $ipesign$%s$ipesign$,
  $ipesign$%s$ipesign$,
  $ipesign$%s$ipesign$,
  $ipesign$%s$ipesign$,
  $ipesign$%s$ipesign$,
  $ipesign$%s$ipesign$,
  NOW()
)
ON CONFLICT (id) DO UPDATE SET
  root_ca_cert_pem_b64 = EXCLUDED.root_ca_cert_pem_b64,
  root_ca_key_blob_b64 = EXCLUDED.root_ca_key_blob_b64,
  ca_cert_pem_b64 = EXCLUDED.ca_cert_pem_b64,
  ca_key_pem_b64 = EXCLUDED.ca_key_pem_b64,
  ca_key_blob_b64 = EXCLUDED.ca_key_blob_b64,
  ledger_key_pem_b64 = EXCLUDED.ledger_key_pem_b64,
  ledger_key_blob_b64 = EXCLUDED.ledger_key_blob_b64,
  chain_snapshot_b64 = EXCLUDED.chain_snapshot_b64,
  updated_at = NOW();
`, rootCACertPEMB64, rootCAKeyBlobB64, caCertPEMB64, caKeyBlobB64, caKeyBlobB64, ledgerKeyBlobB64, ledgerKeyBlobB64, chainSnapshotB64)

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

func (s *PostgresStore) decodePrivateBlob(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	if s.privateBlobCodec.IsSealed(raw) {
		return s.privateBlobCodec.Open(raw)
	}

	return raw, nil
}

func decodeOptionalB64(value string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}

	return base64.StdEncoding.DecodeString(value)
}
