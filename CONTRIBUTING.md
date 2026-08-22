# Contributing to IpeSign

Thank you for helping improve IpeSign. Contributions must preserve the single-use certificate model, the append-only ledger, and the security boundaries documented in `docs/SECURITY_ARCHITECTURE.md`.

## Development setup

Requirements:

- Go 1.26 or newer
- Node.js 24 or newer
- PostgreSQL 17 for integration tests

```bash
npm ci --ignore-scripts
npm run build:web
export IPESIGN_MASTER_KEY='local-development-only'
go test ./...
go run ./apps/api/cmd/server
```

Never commit `.env` files, database URLs, tokens, passwords, private keys, generated ledgers, or signed documents containing private data.

## Before submitting a pull request

```bash
gofmt -w ./apps ./cmd ./internal
go mod tidy
go vet ./...
go test -race ./...
go build ./...
npm ci --ignore-scripts
npm run build:web
npm audit --audit-level=high
govulncheck ./...
```

PostgreSQL integration tests run when `IPESIGN_TEST_DATABASE_URL` points to a database named exactly `ipesign_test`.

Database changes must be versioned in `internal/persist/migrations/`, transactional and backward-compatible. Do not weaken RLS, schema isolation, append-only grants or unique single-use indexes.

## Pull requests

- Keep changes focused and explain security or compatibility tradeoffs.
- Add tests for behavior changes and regressions.
- Update the API contract and documentation when public behavior changes.
- Do not use user-editable Supabase metadata as authorization or cryptographic identity.
