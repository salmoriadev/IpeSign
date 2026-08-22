# IpeSign API

`cmd/server` starts the production HTTP API and serves the built static frontend from `apps/web/public`. Domain logic remains in `internal/core`; transport, auth, request limits, CORS and security headers are in `internal/api`.

## Development

```bash
npm ci --ignore-scripts
npm run build:web
export IPESIGN_MASTER_KEY='local-development-only'
go run ./apps/api/cmd/server
```

The process reads configuration from environment variables; it does not automatically load `.env` files. See the root [README](../../README.md) for production variables, persistence and the security model.

When Supabase Auth is enabled, use the same-origin `/v1/auth/*` routes. The backend stores tokens in secure `HttpOnly` cookies and ignores client-provided signer identity during hosted signing.

The API contract is in [openapi/openapi.yaml](openapi/openapi.yaml).
