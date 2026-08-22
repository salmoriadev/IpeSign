package persist

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"ipesign/internal/ledger/localchain"
)

const ledgerAdvisoryLockID int64 = 0x4950455349474e

var ErrLedgerConflict = errors.New("persisted ledger changed concurrently")

type PostgresStore struct {
	pool             *pgxpool.Pool
	privateBlobCodec PrivateBlobCodec
}

func NewPostgresStore(databaseURL string, masterKey string) (*PostgresStore, error) {
	if strings.TrimSpace(databaseURL) == "" {
		return nil, fmt.Errorf("database URL is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	adminConfig, err := postgresPoolConfig(databaseURL, false)
	if err != nil {
		return nil, err
	}
	adminPool, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		return nil, fmt.Errorf("configure postgres migration pool")
	}
	if err := adminPool.Ping(ctx); err != nil {
		adminPool.Close()
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	if err := applyMigrations(ctx, adminPool); err != nil {
		adminPool.Close()
		return nil, err
	}
	adminPool.Close()

	runtimeConfig, err := postgresPoolConfig(databaseURL, true)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, runtimeConfig)
	if err != nil {
		return nil, fmt.Errorf("configure postgres runtime pool")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to postgres runtime role: %w", err)
	}

	store := &PostgresStore{
		pool:             pool,
		privateBlobCodec: NewPassphrasePrivateBlobCodec(masterKey),
	}
	return store, nil
}

func postgresPoolConfig(databaseURL string, runtimeRole bool) (*pgxpool.Config, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		// pgx parse errors can contain the full credential-bearing URL.
		return nil, fmt.Errorf("configure postgres pool: invalid DATABASE_URL")
	}
	config.MaxConns = 4
	config.MinConns = 0
	config.MaxConnIdleTime = 5 * time.Minute
	config.MaxConnLifetime = 30 * time.Minute
	config.HealthCheckPeriod = time.Minute
	config.ConnConfig.RuntimeParams["application_name"] = "ipesign"
	if runtimeRole {
		config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			for _, statement := range []string{
				"SET ROLE ipesign_runtime",
				"SET search_path TO ipesign, pg_catalog",
				"SET statement_timeout TO '30s'",
				"SET idle_in_transaction_session_timeout TO '15s'",
			} {
				if _, err := conn.Exec(ctx, statement); err != nil {
					return err
				}
			}
			return nil
		}
	}
	return config, nil
}

func (s *PostgresStore) Backend() string {
	return "postgres"
}

func (s *PostgresStore) Exists() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ipesign.ipesign_state WHERE id = 1)`).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check postgres state: %w", err)
	}

	return exists, nil
}

func (s *PostgresStore) Load() (*State, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var rootCACertB64, rootCAKeyB64, caCertB64, caKeyB64, ledgerKeyB64, legacySnapshotB64 string
	err := s.pool.QueryRow(ctx, `
SELECT
  COALESCE(root_ca_cert_pem_b64, ''),
  COALESCE(root_ca_key_blob_b64, ''),
  ca_cert_pem_b64,
  COALESCE(ca_key_blob_b64, ca_key_pem_b64, ''),
  COALESCE(ledger_key_blob_b64, ledger_key_pem_b64, ''),
  COALESCE(chain_snapshot_b64, '')
FROM ipesign.ipesign_state
WHERE id = 1`).Scan(
		&rootCACertB64,
		&rootCAKeyB64,
		&caCertB64,
		&caKeyB64,
		&ledgerKeyB64,
		&legacySnapshotB64,
	)
	if err != nil {
		return nil, fmt.Errorf("load postgres state: %w", err)
	}

	rootCACertPEM, err := decodeOptionalB64(rootCACertB64)
	if err != nil {
		return nil, fmt.Errorf("decode root CA certificate: %w", err)
	}
	rootCAKeyPEM, err := s.decodePrivateB64(rootCAKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode root CA private key: %w", err)
	}
	caCertPEM, err := base64.StdEncoding.DecodeString(caCertB64)
	if err != nil {
		return nil, fmt.Errorf("decode CA certificate: %w", err)
	}
	caKeyPEM, err := s.decodePrivateB64(caKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decrypt CA private key: %w", err)
	}
	ledgerKeyPEM, err := s.decodePrivateB64(ledgerKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decrypt ledger private key: %w", err)
	}
	ledgerKey, err := decodeEd25519PrivateKeyPEM(ledgerKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse ledger private key: %w", err)
	}

	blocks, err := s.loadBlocks(ctx)
	if err != nil {
		return nil, err
	}
	if len(blocks) == 0 && legacySnapshotB64 != "" {
		blocks, err = decodeLegacySnapshot(legacySnapshotB64)
		if err != nil {
			return nil, err
		}
		if err := s.AppendBlocks(blocks); err != nil {
			return nil, fmt.Errorf("migrate legacy postgres ledger: %w", err)
		}
		if _, err := s.pool.Exec(ctx, `UPDATE ipesign.ipesign_state SET chain_snapshot_b64 = NULL WHERE id = 1`); err != nil {
			return nil, fmt.Errorf("finish legacy postgres migration: %w", err)
		}
	}

	return &State{
		RootCACertPEM: rootCACertPEM,
		RootCAKeyPEM:  rootCAKeyPEM,
		CACertPEM:     caCertPEM,
		CAKeyPEM:      caKeyPEM,
		LedgerKey:     ledgerKey,
		Blocks:        blocks,
	}, nil
}

// Save initializes the singleton authority state. Normal signing operations
// use AppendBlocks and never re-encrypt these long-lived secrets.
func (s *PostgresStore) Save(state *State) error {
	if err := validateState(state); err != nil {
		return err
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin postgres initialization: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, ledgerAdvisoryLockID); err != nil {
		return fmt.Errorf("lock postgres ledger: %w", err)
	}

	_, err = tx.Exec(ctx, `
INSERT INTO ipesign.ipesign_state (
  id, root_ca_cert_pem_b64, root_ca_key_blob_b64, ca_cert_pem_b64,
  ca_key_pem_b64, ca_key_blob_b64, ledger_key_pem_b64,
  ledger_key_blob_b64, chain_snapshot_b64, updated_at
) VALUES (1, $1, $2, $3, NULL, $4, NULL, $5, NULL, NOW())
ON CONFLICT (id) DO UPDATE SET
  root_ca_cert_pem_b64 = EXCLUDED.root_ca_cert_pem_b64,
  root_ca_key_blob_b64 = EXCLUDED.root_ca_key_blob_b64,
  ca_cert_pem_b64 = EXCLUDED.ca_cert_pem_b64,
  ca_key_pem_b64 = NULL,
  ca_key_blob_b64 = EXCLUDED.ca_key_blob_b64,
  ledger_key_pem_b64 = NULL,
  ledger_key_blob_b64 = EXCLUDED.ledger_key_blob_b64,
  chain_snapshot_b64 = NULL,
  updated_at = NOW()`,
		base64.StdEncoding.EncodeToString(state.RootCACertPEM),
		base64.StdEncoding.EncodeToString(sealedRootCAKey),
		base64.StdEncoding.EncodeToString(state.CACertPEM),
		base64.StdEncoding.EncodeToString(sealedCAKey),
		base64.StdEncoding.EncodeToString(sealedLedgerKey),
	)
	if err != nil {
		return fmt.Errorf("save postgres authority: %w", err)
	}

	var blockCount int64
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM ipesign.ipesign_ledger_blocks`).Scan(&blockCount); err != nil {
		return fmt.Errorf("count postgres ledger: %w", err)
	}
	if blockCount != 0 {
		return fmt.Errorf("initialize postgres ledger: %w", ErrLedgerConflict)
	}
	if err := insertBlocks(ctx, tx, state.Blocks); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit postgres initialization: %w", err)
	}

	return nil
}

func (s *PostgresStore) AppendBlocks(blocks []localchain.Block) error {
	if len(blocks) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin postgres ledger append: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, ledgerAdvisoryLockID); err != nil {
		return fmt.Errorf("lock postgres ledger: %w", err)
	}

	var lastIndex int64
	var lastHash string
	err = tx.QueryRow(ctx, `
SELECT block_index, block_hash
FROM ipesign.ipesign_ledger_blocks
ORDER BY block_index DESC
LIMIT 1`).Scan(&lastIndex, &lastHash)
	if errors.Is(err, pgx.ErrNoRows) {
		if blocks[0].Index != 0 || blocks[0].PrevHash != "" {
			return ErrLedgerConflict
		}
	} else if err != nil {
		return fmt.Errorf("read postgres ledger tip: %w", err)
	} else if blocks[0].Index != uint64(lastIndex+1) || blocks[0].PrevHash != lastHash {
		return ErrLedgerConflict
	}

	for index := 1; index < len(blocks); index++ {
		if blocks[index].Index != blocks[index-1].Index+1 || blocks[index].PrevHash != blocks[index-1].BlockHash {
			return fmt.Errorf("invalid ledger batch at block %d", blocks[index].Index)
		}
	}

	if err := insertBlocks(ctx, tx, blocks); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit postgres ledger append: %w", err)
	}

	return nil
}

func (s *PostgresStore) loadBlocks(ctx context.Context) ([]localchain.Block, error) {
	rows, err := s.pool.Query(ctx, `
SELECT block_index, prev_hash, block_hash, occurred_at, event_type,
       payload, payload_hash, ledger_signature
FROM ipesign.ipesign_ledger_blocks
ORDER BY block_index`)
	if err != nil {
		return nil, fmt.Errorf("query postgres ledger: %w", err)
	}
	defer rows.Close()

	var blocks []localchain.Block
	for rows.Next() {
		var block localchain.Block
		var blockIndex int64
		if err := rows.Scan(
			&blockIndex,
			&block.PrevHash,
			&block.BlockHash,
			&block.Timestamp,
			&block.EventType,
			&block.Payload,
			&block.PayloadHash,
			&block.LedgerSignature,
		); err != nil {
			return nil, fmt.Errorf("scan postgres ledger block: %w", err)
		}
		if blockIndex < 0 {
			return nil, fmt.Errorf("invalid negative postgres ledger index %d", blockIndex)
		}
		block.Index = uint64(blockIndex)
		blocks = append(blocks, block)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read postgres ledger: %w", err)
	}

	return blocks, nil
}

func insertBlocks(ctx context.Context, tx pgx.Tx, blocks []localchain.Block) error {
	for _, block := range blocks {
		var searchableFields struct {
			CertHash string `json:"certHash"`
			RecordID string `json:"recordId"`
		}
		if err := json.Unmarshal(block.Payload, &searchableFields); err != nil {
			return fmt.Errorf("decode ledger block %d search fields: %w", block.Index, err)
		}

		_, err := tx.Exec(ctx, `
INSERT INTO ipesign.ipesign_ledger_blocks (
  block_index, prev_hash, block_hash, occurred_at, event_type,
	payload, payload_hash, ledger_signature, cert_hash, record_id
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), NULLIF($10, ''))`,
			int64(block.Index),
			block.PrevHash,
			block.BlockHash,
			block.Timestamp,
			block.EventType,
			[]byte(block.Payload),
			block.PayloadHash,
			block.LedgerSignature,
			searchableFields.CertHash,
			searchableFields.RecordID,
		)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return fmt.Errorf("ledger uniqueness violation: %w", ErrLedgerConflict)
			}
			return fmt.Errorf("insert postgres ledger block %d: %w", block.Index, err)
		}
	}

	return nil
}

func (s *PostgresStore) decodePrivateB64(value string) ([]byte, error) {
	raw, err := decodeOptionalB64(value)
	if err != nil {
		return nil, err
	}
	return s.decodePrivateBlob(raw)
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

func decodeLegacySnapshot(value string) ([]localchain.Block, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode legacy chain snapshot: %w", err)
	}

	var blocks []localchain.Block
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return nil, fmt.Errorf("parse legacy chain snapshot: %w", err)
	}
	return blocks, nil
}

func decodeOptionalB64(value string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(value)
}
