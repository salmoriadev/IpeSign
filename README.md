# IpeSign

IpeSign signs PDFs with an ephemeral Ed25519 certificate created for one document and records certificate issuance and use in an append-only, tamper-evident ledger. It is not a distributed blockchain: one IpeSign deployment is the authority and the ledger operator.

The repository contains a Go API and CLI, a static web interface served by the same API process, PostgreSQL/Supabase persistence, Supabase Auth integration, tests, migrations, CI and a non-root container image.

## Security model

- A `root CA -> issuing CA -> one-document certificate` chain binds each signature to the original PDF hash and policy.
- The ephemeral document private key is zeroed after signing and is never persisted.
- The certificate and signature are each registered once. PostgreSQL partial unique indexes enforce non-reuse even under concurrent requests.
- Authority and ledger private keys are sealed with `IPESIGN_MASTER_KEY` before persistence.
- When Supabase Auth is enabled, the backend derives the certificate name and email only from verified JWT claims. Multipart fields and user-editable profile metadata cannot override that identity.
- Browser access and refresh tokens remain in `HttpOnly`, `SameSite=Strict` cookies; the frontend does not store them in JavaScript storage.
- The PostgreSQL ledger lives in the private `ipesign` schema with forced RLS and an append-only runtime role.
- The API applies a strict nonce-based CSP, security headers, request limits, rate limits, same-origin CORS by default and explicit HTTP timeouts.

Read [Security architecture](docs/SECURITY_ARCHITECTURE.md) before a production deployment. This project does not implement PAdES or claim the legal status of a qualified electronic signature.

## Requirements

- Go 1.26+
- Node.js 24+ (only to build bundled frontend assets)
- PostgreSQL 17 for persistence/integration tests (optional)

## Local development

```bash
npm ci --ignore-scripts
npm run build:web
export IPESIGN_MASTER_KEY='use-a-long-random-development-secret'
go run ./apps/api/cmd/server
```

Open `http://localhost:8080`. Without Supabase variables, local signing is intentionally available without login. Do not expose that mode to the internet.

Run the checks:

```bash
go test ./...
go vet ./...
go build ./...
npm audit --audit-level=high
```

## Production configuration

| Variable | Required | Purpose |
| --- | --- | --- |
| `IPESIGN_MASTER_KEY` | Yes | Long random secret used to seal persisted private keys. |
| `DATABASE_URL` | Recommended | PostgreSQL connection URI. If omitted, state is stored under `IPESIGN_DATA_DIR`. |
| `SUPABASE_URL` | For auth | Project URL, for example `https://project-ref.supabase.co`. |
| `SUPABASE_PUBLISHABLE_KEY` | For password auth | Supabase publishable key; legacy `SUPABASE_ANON_KEY` is also accepted. |
| `SUPABASE_JWT_SECRET` | Legacy only | Enables verification of legacy HS256 access tokens. Prefer Supabase JWKS. |
| `CORS_ALLOW_ORIGIN` | No | Comma-separated extra trusted origins. Empty or `*` keeps the secure same-origin-only default. |
| `IPESIGN_DATA_DIR` | No | File persistence directory; defaults to `./data`. |
| `IPESIGN_ADDR` / `PORT` | No | Listen address or platform-provided port. |

Copy the complete PostgreSQL URI from Supabase **Connect > Connection string**. Do not concatenate two URIs. A pooler URI normally looks like:

```text
postgresql://postgres.PROJECT_REF:URL_ENCODED_PASSWORD@aws-0-REGION.pooler.supabase.com:5432/postgres?sslmode=require
```

If the password contains `@`, `:`, `/`, `?`, `#` or `%`, URL-encode it. `DATABASE_URL`, tokens, keys and `.env` files are ignored and must never be committed.

At startup, the API applies the embedded, versioned migrations from `internal/persist/migrations/`. The database login therefore needs migration privileges. Runtime connections immediately `SET ROLE ipesign_runtime` and receive no `UPDATE` or `DELETE` grant on ledger blocks; an append-only trigger also rejects row mutation.

## HTTP API

Main routes:

- `GET /v1/health`
- `GET /v1/ca`
- `POST /v1/auth/signup`
- `POST /v1/auth/login`
- `POST /v1/auth/logout`
- `GET /v1/auth/me`
- `POST /v1/documents/sign`
- `POST /v1/documents/verify`
- `GET /v1/records/{recordId}`
- `GET /v1/chain/verify`

PDF requests use `multipart/form-data` with exactly one `pdf` file and a maximum PDF size of 20 MiB. Signing returns the signed PDF; verification reads the embedded IpeSign record. See [OpenAPI](apps/api/openapi/openapi.yaml).

## CLI

```bash
export IPESIGN_MASTER_KEY='use-a-long-random-development-secret'
go run ./cmd/ipesign sign --common-name 'Local User' document.pdf
go run ./cmd/ipesign verify document_signed.pdf
go run ./cmd/ipesign walk
```

CLI-provided identity is suitable only for trusted local operation. Hosted identity comes from verified Supabase claims.

## Container and Render

```bash
docker build -t ipesign .
docker run --rm -p 8080:8080 \
  -e IPESIGN_MASTER_KEY='replace-me' \
  -e DATABASE_URL='postgresql://...' \
  -e SUPABASE_URL='https://project-ref.supabase.co' \
  -e SUPABASE_PUBLISHABLE_KEY='sb_publishable_...' \
  ipesign
```

The final image runs as UID/GID `10001`, not root. `render.yaml` declares the web service and its secret variables. Render still requires the actual values to be entered in the service environment.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). IpeSign is licensed under the [Apache License 2.0](LICENSE).
