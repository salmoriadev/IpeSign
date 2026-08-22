# Security architecture

## Trust and non-goals

IpeSign is a centralized signing service with a cryptographically linked, signed, append-only ledger. It is tamper-evident, but it is not a distributed blockchain and does not remove trust from the service operator or database administrator. It currently embeds an IpeSign JSON envelope into a PDF; it is not a PAdES implementation or a qualified trust service.

Protecting the signing host, Supabase project, PostgreSQL owner credentials and `IPESIGN_MASTER_KEY` remains an operator responsibility.

## Signing flow

1. The browser sends one PDF to the same origin as the web interface.
2. If Supabase is configured, the API verifies the access token signature, issuer, `authenticated` audience, role, expiration and issued-at time. Expired cookie sessions are refreshed server-side.
3. The signer identity used in the document certificate is derived from trusted JWT claims. `user_metadata`, profile form values and multipart identity values are presentation-only and cannot select the certificate subject.
4. The authority creates an Ed25519 certificate and private key bound to that document hash and policy.
5. The document hash is signed, the result is embedded in the PDF, and certificate issuance plus signature use are committed as one ledger operation.
6. Persistence succeeds before the in-memory chain commit is retained. The ephemeral private key is then zeroed and discarded.

The public profile name and Ipe address originate in Supabase user metadata. They are deliberately not treated as verified identity. The verified email is the current certificate identity.

## Browser and HTTP boundary

- Password exchange and token refresh are proxied through the Go backend.
- Access and refresh tokens are set as `HttpOnly`, `SameSite=Strict` cookies and are never returned to frontend JavaScript.
- Cookies are `Secure` outside localhost/loopback development.
- The default CORS policy accepts only the exact request origin, including scheme and host. `CORS_ALLOW_ORIGIN` can add explicit origins; `*` does not enable wildcard CORS.
- A per-response CSP nonce permits only bundled same-origin scripts. Third-party CDN scripts and styles are not loaded.
- Uploads accept exactly one PDF, limit the whole multipart request to 21 MiB and validate the PDF itself at 20 MiB.
- Auth, signing and verification routes use service rate limits. The HTTP server limits headers and applies read, write and idle timeouts.

Rate limiting is an application safeguard, not a substitute for Render/edge DDoS protection. A multi-instance deployment should replace the in-memory limiter with a shared edge or Redis-backed limiter.

## Persistence

With no `DATABASE_URL`, encrypted authority state and an append-only ledger log are stored in the configured data directory. A legacy full-ledger snapshot is migrated automatically on the first append. This is intended for local/single-instance operation; ephemeral container disks are not durable.

With PostgreSQL, the authority state is one encrypted singleton row and every ledger block is a separate append-only row. The database is therefore not a snapshot-only model. Versioned migrations:

- move legacy public tables into the non-exposed `ipesign` schema;
- enable and force RLS;
- revoke `PUBLIC`, `anon`, `authenticated` and `service_role` access;
- create a `NOLOGIN`, `NOINHERIT` runtime role;
- grant ledger `SELECT` and `INSERT`, but not `UPDATE`, `DELETE` or `TRUNCATE`;
- install a trigger that rejects ledger row updates and deletions, including accidental owner operations;
- enforce unique certificate-use and record IDs with partial indexes;
- apply statement and idle-transaction timeouts and a small connection pool.

The configured PostgreSQL owner connection applies migrations and grants itself the runtime role. Runtime pool connections execute `SET ROLE ipesign_runtime`. For stronger production separation, run migrations as an owner during deployment and provide the service with a dedicated login that can only assume `ipesign_runtime`.

RLS and grants limit the application role, but a PostgreSQL/Supabase owner can still alter data. The signed hash chain makes such changes detectable by full ledger verification; it cannot prevent an owner from destroying data. Backups and external checkpoints of the latest ledger hash are recommended.

## Secrets and incident response

Never put these values in Git, frontend code, logs, screenshots or issue reports:

- `DATABASE_URL`;
- `IPESIGN_MASTER_KEY`;
- `SUPABASE_JWT_SECRET`;
- access/refresh tokens;
- private key material.

The Supabase publishable/anon key is designed for public clients, but IpeSign keeps it server-side because authentication is proxied. It is not a replacement for RLS.

If a credential may have appeared in Git history or a public screenshot, rotation is required; deleting the current file is insufficient. Rotate the database password, JWT secret when applicable, master key according to a planned state re-encryption procedure, and user sessions. Purging Git history is a separate destructive operation that must be coordinated with all contributors.

## Production checklist

- Use HTTPS only and keep Render/Supabase projects in compatible regions.
- Set a long random `IPESIGN_MASTER_KEY`; retain it in a secret manager and backup procedure.
- Copy `DATABASE_URL` directly from Supabase, URL-encode the password and require TLS.
- Configure `SUPABASE_URL` plus the publishable key; prefer asymmetric JWT/JWKS verification.
- Leave `CORS_ALLOW_ORIGIN` empty when frontend and API share this server.
- Enable email confirmation and appropriate password/session policies in Supabase Auth.
- Preserve database backups and periodically call `/v1/chain/verify`.
- Monitor 401, 413, 429 and migration failures without logging credentials or document bodies.
- Run CI, dependency audits and container rebuilds before releases.
- Do not expose the unauthenticated local mode to the internet.
