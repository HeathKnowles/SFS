Quick Docker Compose notes

This repository includes a minimal `docker-compose.yml` for local development. It brings up:

- `web` — your Flask app (binds port 5000)
- `clamav` — ClamAV daemon (listens on 3310)
- `minio` — S3-compatible storage for local testing (console on 9001, S3 on 9000)

Local dev tips

- The compose file mounts your project into the container so code changes are live.
- It provides volumes for `uploads` and `quarantine` so data persists across runs.

Environment variables

- For production you should use Cloudflare R2 and set the env values in a secure manner.
- For local MinIO testing, set these variables in `.env` (or export in your shell):

CLOUDFLARE_S3_ENDPOINT=http://minio:9000
CLOUDFLARE_ACCESS_KEY_ID=minioadmin
CLOUDFLARE_SECRET_ACCESS_KEY=minioadmin
CLOUDFLARE_R2_BUCKET=sfs

Running

Start services:

    docker compose up --build

Then visit http://localhost:5000 in your browser.

Notes

- This compose file is intended for development only. For production, use a proper WSGI server (gunicorn/uvicorn), secure secrets, persistent Postgres, and Cloudflare R2.
