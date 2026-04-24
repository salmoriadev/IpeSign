# IpeSign

IpeSign already has a working Go core for:

- ephemeral per-document certificates
- hash signing for real PDFs
- local append-only ledger
- persistence to file or PostgreSQL
- CLI signing and verification

The repository is also prepared for web development with dedicated folders for:

- `apps/api`
- `apps/web`
- `packages/contracts`

## Current Status

What works today:

- sign a real PDF by path
- verify the same PDF by path
- persist the CA and ledger between executions
- expose the same flow over HTTP

What does not exist yet:

- embedded PDF signature
- PAdES
- production auth
- admin UI
- final frontend

## Fastest Demo

Sign a PDF:

```bash
go run ./cmd/ipesign sign /path/file.pdf
```

Verify the same PDF:

```bash
go run ./cmd/ipesign verify /path/file.pdf
```

This creates a sidecar next to the PDF:

```text
/path/file.pdf.ipesign.json
```

If verification is successful, the command returns a JSON result containing:

- `valid: true`
- `signatureValid: true`
- `ledgerRecordValid: true`
- `singleUseConfirmed: true`

## HTTP Demo

Run the API:

```bash
go run ./apps/api/cmd/server
```

Health:

```bash
curl -s http://localhost:8080/v1/health | jq
```

Sign:

```bash
curl -s \
  -F pdf=@/path/file.pdf \
  -F policy_id=participation-v1 \
  http://localhost:8080/v1/sign | jq
```

Verify:

```bash
CERT=$(jq -r '.certificatePem' sign.json)
SIG=$(jq -r '.signatureBase64' sign.json)

curl -s \
  -F pdf=@/path/file.pdf \
  --form-string certificate_pem="$CERT" \
  -F signature_base64="$SIG" \
  http://localhost:8080/v1/verify | jq
```

## Persistence

Default behavior:

- file-based persistence in `./data`

Optional behavior:

- PostgreSQL if `DATABASE_URL` is set

Examples:

```bash
export DATABASE_URL='postgresql://USER:PASSWORD@HOST:5432/DBNAME?sslmode=disable'
go run ./cmd/ipesign sign /path/file.pdf
```

## Context Docs

Team context files:

- [CONTEXT.md](/home/arthursalmoria/IpeSign/CONTEXT.md)
- [apps/api/CONTEXT.md](/home/arthursalmoria/IpeSign/apps/api/CONTEXT.md)
- [apps/web/CONTEXT.md](/home/arthursalmoria/IpeSign/apps/web/CONTEXT.md)

## Repository Layout

```text
apps/
  api/
    cmd/server/           web API entrypoint
    http/
      handlers/           HTTP handlers by feature
      middleware/         auth, logging, limits, CORS
      router/             route registration
    openapi/              API contract for frontend/backend alignment
  web/
    public/               static assets
    src/
      app/                app shell, routes, providers
      components/         shared UI components
      features/           sign, verify, admin feature folders
      lib/                API client, env, utils
      styles/             global styles and tokens
packages/
  contracts/
    http/                 request/response shapes
    schemas/              JSON schema, zod, or validation contracts

cmd/ipesign/              current CLI
internal/                 current Go core implementation
data/                     persisted CA and ledger state
```

## Current Recommendation

- keep the cryptographic and ledger core in `internal/`
- build the future web API in `apps/api/`
- build the future frontend in `apps/web/`
- place shared request/response contracts in `packages/contracts/`

## Repository Notes

- `cmd/ipesign` is the current operator-friendly CLI
- `apps/api/cmd/server` is the web API entrypoint
- `internal/api` is still the current HTTP implementation reused by both CLI and API entrypoint
- `internal/authority`, `internal/ledger`, and `internal/persist` are the main backend core packages
