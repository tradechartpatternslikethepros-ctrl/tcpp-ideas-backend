# TCPP Ideas Backend (Express)

Single-file Node backend.

- Endpoints: Ideas CRUD, Likes, Comments, Uploads, SSE `/events`
- Auth: `Authorization: Bearer <API_TOKEN>`; `/events` also accepts `?token=`
- Storage: JSON in `DATA_DIR` (Railway volume `/data`)
- Uploads: POST `/upload` field `file` → `{ "url": "/uploads/<name>" }`

## Run local
```bash
npm i
API_TOKEN=devtoken DATA_DIR=./data node server.cjs
```

## Railway
1) Deploy from GitHub
2) Add Volume at `/data`
3) Variables:
   - API_TOKEN (required for writes)
   - CORS_ORIGINS (e.g. https://www.tradechartpatternslikethepros.com)
   - DATA_DIR=/data
   - UPLOAD_DIR=/data/uploads
   - MAX_UPLOAD_MB=8
