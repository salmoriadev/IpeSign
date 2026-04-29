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

Deploy-oriented notes:

- `DATABASE_URL`: use the Supabase Postgres connection string
- `SUPABASE_URL`: enables bearer-token auth for `POST /v1/sign`
- `SUPABASE_JWT_SECRET`: optional fallback for projects still using legacy symmetric JWT signing

When `SUPABASE_URL` is set, the API exposes:

- `GET /v1/auth/me`
- authenticated signing via `Authorization: Bearer <supabase_access_token>`
