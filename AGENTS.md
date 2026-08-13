# AGENTS.md

## Cursor Cloud specific instructions

This repo is a single **Cloudflare Worker** (`index.js`) that serves a file-share UI (`index.html`, imported as text) backed by a **Cloudflare R2** bucket. There is no separate frontend build — the HTML is bundled into the Worker. Managed with `wrangler` (npm scripts in `package.json`).

### Running locally (dev)

- Start the dev server with `npx wrangler dev` (or `npm run dev`). It runs via Miniflare with the R2 bucket **simulated locally** — no real Cloudflare account/credentials are required. It listens on `http://127.0.0.1:8787`.
- `npm run deploy` / `wrangler deploy` are for **production** and require Cloudflare auth; do not use them for local development.
- Miniflare does not fire the Cron trigger automatically. To exercise the scheduled sync task locally, run `wrangler dev --test-scheduled` and hit `http://127.0.0.1:8787/__scheduled`.

### Secrets for local dev (required for login / signed links)

- Runtime secrets (`AUTH_PASSWORD`, `SECRET_KEY`, `CERT_PUSH_TOKEN`) are **not** in `wrangler.toml`; in production they come from `wrangler secret`. For local dev, `wrangler dev` reads them from a **`.dev.vars`** file in the repo root.
- `.dev.vars` is git-ignored and is **not** recreated by the update script, so it will be absent on a fresh VM. Create it before testing anything that needs auth:
  ```
  AUTH_PASSWORD="admin"
  SECRET_KEY="local-dev-secret-key-please-change"
  CERT_PUSH_TOKEN="local-dev-cert-push-token"
  ```
- Without `.dev.vars`, the server still starts but `POST /api/auth` rejects every password (the admin UI can't be entered).

### Testing / smoke checks

- There is no automated test suite and no lint config in this repo (`upload_test.py` is a manual helper script, and `*.py` is git-ignored).
- Quick API smoke test (server must be running with `.dev.vars` above):
  - Login: `curl -X POST http://127.0.0.1:8787/api/auth -H 'Content-Type: application/json' -d '{"password":"admin"}'` → `{"success":true}`
  - List files: `curl http://127.0.0.1:8787/api/list -H 'Authorization: admin'`
  - Upload is a 3-step chunked flow: `POST /api/upload-init` → `POST /api/upload-part?...&partNumber=N` → `POST /api/upload-complete`. See `upload_test.py` for a worked example.
- Admin-only API routes expect the header `Authorization: <AUTH_PASSWORD>` (the raw password, not a Bearer token).
- `POST /api/public-toggle` body uses the field name `isPublic` (boolean), e.g. `{"key":"hello.txt","isPublic":true}`; public files are then served at `GET /f/<key>` with no auth.
