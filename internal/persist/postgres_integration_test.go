package persist

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ipesign/internal/cryptoutil"
	"ipesign/internal/ledger/localchain"
)

func TestPostgresMigrationsAndRuntimePrivileges(t *testing.T) {
	databaseURL := os.Getenv("IPESIGN_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("IPESIGN_TEST_DATABASE_URL is not configured")
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal("invalid test database URL")
	}
	if config.ConnConfig.Database != "ipesign_test" {
		t.Fatalf("refusing to alter non-test database %q", config.ConnConfig.Database)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, `
DROP SCHEMA IF EXISTS ipesign CASCADE;
DROP TABLE IF EXISTS public.ipesign_state;
DROP TABLE IF EXISTS public.ipesign_ledger_blocks;

CREATE TABLE public.ipesign_state (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    root_ca_cert_pem_b64 TEXT,
    root_ca_key_blob_b64 TEXT,
    ca_cert_pem_b64 TEXT NOT NULL,
    ca_key_pem_b64 TEXT,
    ca_key_blob_b64 TEXT NOT NULL,
    ledger_key_pem_b64 TEXT,
    ledger_key_blob_b64 TEXT NOT NULL,
    chain_snapshot_b64 TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE public.ipesign_ledger_blocks (
    block_index BIGINT PRIMARY KEY CHECK (block_index >= 0),
    prev_hash TEXT NOT NULL,
    block_hash TEXT NOT NULL UNIQUE,
    occurred_at TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL,
    payload BYTEA NOT NULL,
    cert_hash TEXT,
    record_id TEXT,
    payload_hash TEXT NOT NULL,
    ledger_signature TEXT NOT NULL
);`); err != nil {
		t.Fatal(err)
	}

	store, err := NewPostgresStore(databaseURL, "integration-master-key")
	if err != nil {
		t.Fatal(err)
	}
	defer store.pool.Close()

	var currentUser string
	if err := store.pool.QueryRow(ctx, `SELECT current_user`).Scan(&currentUser); err != nil {
		t.Fatal(err)
	}
	if currentUser != "ipesign_runtime" {
		t.Fatalf("runtime database role = %q", currentUser)
	}

	var publicStateExists bool
	if err := admin.QueryRow(ctx, `SELECT to_regclass('public.ipesign_state') IS NOT NULL`).Scan(&publicStateExists); err != nil {
		t.Fatal(err)
	}
	if publicStateExists {
		t.Fatal("ledger state remains in the public schema")
	}
	var rlsEnabled, rlsForced bool
	if err := admin.QueryRow(ctx, `
SELECT relrowsecurity, relforcerowsecurity
FROM pg_class
WHERE oid = 'ipesign.ipesign_ledger_blocks'::regclass`).Scan(&rlsEnabled, &rlsForced); err != nil {
		t.Fatal(err)
	}
	if !rlsEnabled || !rlsForced {
		t.Fatalf("ledger RLS enabled=%v forced=%v", rlsEnabled, rlsForced)
	}

	state := postgresTestState(t)
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Blocks) != len(state.Blocks) {
		t.Fatalf("loaded blocks = %d, want %d", len(loaded.Blocks), len(state.Blocks))
	}
	if _, err := store.pool.Exec(ctx, `UPDATE ipesign.ipesign_ledger_blocks SET event_type = 'tampered'`); err == nil {
		t.Fatal("runtime role unexpectedly updated append-only ledger rows")
	}
	if _, err := admin.Exec(ctx, `DELETE FROM ipesign.ipesign_ledger_blocks`); err == nil {
		t.Fatal("append-only trigger unexpectedly allowed owner deletion")
	}
	if err := store.AppendBlocks(state.Blocks); !errors.Is(err, ErrLedgerConflict) {
		t.Fatalf("duplicate append error = %v", err)
	}
}

func postgresTestState(t *testing.T) *State {
	t.Helper()
	_, authorityKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorityPEM, err := cryptoutil.MarshalEd25519PrivateKeyPEM(authorityKey)
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
	return &State{
		RootCACertPEM: []byte("root-cert"),
		RootCAKeyPEM:  authorityPEM,
		CACertPEM:     []byte("ca-cert"),
		CAKeyPEM:      authorityPEM,
		LedgerKey:     ledgerKey,
		Blocks:        chain.Snapshot(),
	}
}
