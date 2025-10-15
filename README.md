### Secure File Sharing App
This repository contains a secure web-based file sharing platform built with Flask (frontend + backend + APIs) and Cloudflare R2 for object storage. The design focuses on end-to-end encryption (HTTPS), safe handling of uploads (sanitization and malware scanning), secure storage, and robust audit logging.

## Architecture Overview

High-level components:

- Client (browser) — React/Vanilla HTML served by Flask or static SPA using the API.
- Flask app — handles authentication, file metadata, upload/download/delete endpoints, scanning orchestration, and audit logging.
- Database — PostgreSQL for user accounts, file metadata, and audit records.
- Object storage — Cloudflare R2 (S3-compatible) for file blobs. Use per-object metadata to store scan status and owner.
- Malware scanner — ClamAV (containerized) or a cloud scanning API. Files are scanned before being accepted; flagged files are quarantined.
- Reverse proxy / TLS — Nginx (optional) at origin or Cloudflare-managed TLS for public fronting. Let's Encrypt instructions are provided for origin certs if you prefer full control.

Sequence for an upload (secure flow):

1. Client (authenticated) POSTs multipart/form-data to `/api/upload` with file and optional metadata.
2. Flask validates the session/JWT, enforces rate limits and file size limits.
3. Server sanitizes filename, checks content-type via content sniffing, and streams file to a temporary quarantine store (local or R2 with quarantine prefix).
4. Server invokes ClamAV (local socket or HTTP API) to scan the file stream. If scan fails or returns malicious, mark as quarantined and log the event.
5. If clean, compute a content hash (SHA-256), store metadata in Postgres, and move the file to permanent R2 location (or make the R2 object accessible via a short-lived presigned URL).
6. Emit an audit log entry (user, action, file id/key, timestamp, IP, scan result).

Download flow:

1. Authenticated client requests `/api/files/<id>`.
2. Server checks authorization (owner or allowed share), logs the request, and returns a short-lived presigned URL from R2 or streams the object via the backend.

Delete flow:

1. Authenticated owner requests delete.
2. Server marks record deleted in database and either soft-deletes the R2 object (move to tombstone prefix) or permanently deletes it after retention policy.

## Security considerations / hardening

- Use Argon2 or bcrypt for password hashing.
- Use secure, HttpOnly, SameSite cookies for sessions or signed JWTs with short expiry and refresh tokens.
- Enforce per-user or per-bucket access policies in R2 using service tokens; keep keys out of client-side.
- Always sanitize filenames and never trust client-provided Content-Type headers; use `python-magic` or similar for content sniffing.
- Limit upload sizes and streaming to avoid memory bloat; enforce timeouts and connection limits.
- Scan every upload with ClamAV (or cloud scanning) and quarantine flagged files.
- Implement rate-limiting (per-IP and per-user) for auth and upload endpoints.
- Use Content Security Policy (CSP), X-Frame-Options, HSTS, and other headers to secure the frontend.
- Audit logs should never include raw file contents or credentials.

## Tech Stack (suggested)

- Backend & frontend server: Flask
- Auth: Flask-Login or JWT + Argon2/bcrypt
- DB: PostgreSQL (psycopg2 / SQLAlchemy)
- Storage: Cloudflare R2 (S3-compatible API, use boto3 with custom endpoint)
- Malware scanning: ClamAV (clamd) in a container or external API
- Proxy/TLS: Cloudflare in front (recommended) + origin TLS (Let's Encrypt or self-signed for dev)
- Dev environment: Docker Compose (Flask + Postgres + MinIO for local testing or R2-compatible mock + ClamAV)
- CI: GitHub Actions

## Environment variables (example)

The app expects the following environment variables (example names):

- `DATABASE_URL=postgresql://user:pass@db:5432/sfs`
- `SECRET_KEY=your-flask-secret`
- `R2_ENDPOINT=https://<account_id>.r2.cloudflarestorage.com`
- `R2_ACCESS_KEY_ID=...`
- `R2_SECRET_ACCESS_KEY=...`
- `R2_BUCKET=your-bucket`
- `CLAMAV_HOST=clamd`
- `CLAMAV_PORT=3310`
- `SENTRY_DSN=(optional)`

## Deployment notes

Production recommendations:

- Use Cloudflare in front of your origin. Enable Full (strict) TLS mode which requires a valid cert on your origin. You can use Cloudflare-managed certificates or issue a Let's Encrypt certificate on the origin server.
- Use R2 with scoped API tokens and RBAC. Do not expose R2 keys to the browser. Keep R2 access server-side and use presigned URLs for client downloads.
- Enable server-side encryption on R2 objects if required by your policies, or apply envelope encryption at the application layer (encrypt before upload with a KMS-managed key).
- Run ClamAV in a dedicated container or use a managed scanning API. For high throughput, use async scanning with a message queue (RabbitMQ/SQS) and background workers.
- Configure logging to a centralized system (Cloudflare Logs, ELK, or CloudWatch). Send exceptions to Sentry.

Origin TLS options:

- Cloudflare-managed certificates: Simplest. Cloudflare presents public certs to clients and handles TLS termination; origin certs can be Cloudflare-issued or Let's Encrypt for Full (strict) mode.
- Let's Encrypt on origin: Use certbot to issue certificates on your origin server, renew via cron/systemd timers or `certbot renew`. Place Nginx as reverse proxy terminating TLS and forwarding to Flask (gunicorn) on localhost.

## Local development

- Use Docker Compose with services: `web` (Flask), `db` (Postgres), `clamav` (clamd+freshclam), and `minio` (S3-compatible for local testing). Use `mkcert` or a self-signed cert for TLS locally if needed.
- Example compose hints (not included here): map ports for Postgres, set environment variables, mount a tmp directory for quarantine files.

## Running locally (quick start)

Create a `.env` file with the environment variables above and run (if using Docker Compose):

```bash
docker compose up --build
```

Then visit `https://localhost:8000` (or the mapped port) and use the web UI.

## Next steps / roadmap

- Implement authentication (Argon2 + secure sessions) and account management.
- Build file upload API with streaming, sanitization, and ClamAV scanning.
- Wire Cloudflare R2 for storage and implement presigned download URLs.
- Add structured audit logging and error tracking.
- Add automated tests and GitHub Actions CI.

If you'd like, I can scaffold an initial Flask project in this repo now with the proposed pieces (auth, DB models, R2 client wiring, simple upload endpoint with mocked scanning). Tell me if you want ClamAV run in the prototype or mocked and whether to use MinIO locally or call R2 directly.

---

*This README is intentionally detailed to serve as both documentation and a deployment runbook.*
### Secure File Sharing App


