# Security Policy

## Reporting a vulnerability

Please do not open a public issue for an undisclosed vulnerability. Use GitHub's private vulnerability reporting or open a private security advisory for this repository.

Include the affected commit, reproduction steps, impact and any suggested mitigation. Do not include real credentials, private keys, personal documents or production database contents.

You should receive an initial acknowledgement within seven days. A coordinated disclosure date will be agreed after impact and remediation are understood.

## Supported versions

Security fixes are currently provided for the latest commit on `master`. The project has not yet published a stable release series.

## Operational responsibilities

Deployers are responsible for protecting `IPESIGN_MASTER_KEY`, PostgreSQL credentials and Supabase configuration; enabling TLS; rotating exposed credentials; monitoring logs; and keeping dependencies updated. See `docs/SECURITY_ARCHITECTURE.md` for the trust model and deployment checklist.
