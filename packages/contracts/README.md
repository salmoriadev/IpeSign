# packages/contracts

Shared contracts between API and frontend should live here.

Recommended split:

- `http/`: request and response DTOs
- `schemas/`: JSON Schema, zod, or validation contracts

Keep this folder free of transport implementation details.
