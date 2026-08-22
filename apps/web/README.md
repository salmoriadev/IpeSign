# IpeSign web interface

The frontend is a static same-origin interface served by the Go API. It contains no database credential, Supabase key or access token. Authentication calls `/v1/auth/*`; the backend owns the Supabase exchange and stores sessions in `HttpOnly` cookies.

Build the pinned local assets:

```bash
npm ci --ignore-scripts
npm run build:web
```

Generated files under `public/assets/` are ignored by Git and produced in CI and the Docker build. Source styles are in `src/styles.css`; the application markup and JavaScript are in `public/index.html`.
