# apps/api

This folder is prepared for the web-facing backend.

## Intended Structure

- `cmd/server/`: process entrypoint
- `http/handlers/`: handlers by feature
- `http/middleware/`: auth, request IDs, logging, CORS, limits
- `http/router/`: route registration
- `openapi/`: API contract consumed by frontend

## Suggested Split

- keep signing, certificate, and ledger logic in root `internal/`
- add transport/web concerns here
- call into the core instead of rewriting the domain

## Suggested Near-Term Endpoints

- `POST /v1/documents/sign`
- `POST /v1/documents/verify`
- `GET /v1/records/:recordId`
- `GET /v1/ca`
- `GET /v1/health`
- `GET /v1/chain/verify`

## Environment

See `.env.example`.
