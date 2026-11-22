# Collaborative Task Tracking API

A Node.js and Express REST API for managing team projects, assigned tasks, comments, and file attachments. It uses SQLite for persistence, bcrypt for password hashing, and JWT bearer tokens backed by revocable database sessions.

## Requirements

- Node.js 18 or newer
- npm

## Run locally

```powershell
npm install
Copy-Item .env.example .env
```

Set `JWT_SECRET` in `.env` to a private random value of at least 32 characters, then run:

```powershell
npm start
```

The API listens on `http://localhost:3000`. SQLite data and uploaded files are stored under `data/` and `uploads/` by default. Those directories are created automatically. For development, `npm run dev` restarts the server when source files change.

## Tests

```powershell
npm test
npm run check
```

The tests use a separate SQLite database and remove their test database and uploaded files when they finish.

## Authentication

Register or log in to receive a bearer token. Include it on protected routes:

```http
Authorization: Bearer <token>
```

Logging out revokes that session immediately. Passwords are hashed with bcrypt; the password hash is never returned by the API.

## API overview

All request and response bodies use JSON except attachment uploads, which use `multipart/form-data` with a `file` field. Protected routes are under `/api`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/api/auth/register` | Register and create a session |
| POST | `/api/auth/login` | Log in |
| POST | `/api/auth/logout` | Revoke the current session |
| GET, PATCH | `/api/users/me` | View or update the current profile |
| GET, POST | `/api/projects` | List projects or create a project |
| GET, POST | `/api/projects/:projectId/members` | List members or (owner only) add a registered user by email |
| GET, POST, DELETE | `/api/projects/:projectId/invitations` | List, create, or revoke project invitations (owner only) |
| POST | `/api/invitations/accept` | Accept an invitation using its token |
| GET, POST | `/api/tasks` | List or create tasks |
| GET, PATCH, DELETE | `/api/tasks/:taskId` | Read, update, or delete a task |
| GET, POST | `/api/tasks/:taskId/comments` | List or add task comments |
| GET, POST | `/api/tasks/:taskId/attachments` | List or upload task attachments |
| GET | `/api/attachments/:attachmentId` | Download an attachment |
| GET | `/api/notifications` | List notifications (`unreadOnly=true`, `limit`) |
| PATCH | `/api/notifications/:notificationId/read` | Mark one notification as read |
| POST | `/api/notifications/read-all` | Mark all current-user notifications as read |
| GET | `/api/notifications/stream` | Receive live notification events over Server-Sent Events |
| POST | `/api/ai/generate` | Generate a task description or summarize supplied text |

Task listing supports `projectId`, `status` (`open`, `in_progress`, `completed`), `assignedTo=me` or a user UUID, `q` (title/description substring search), `sortBy` (`createdAt`, `dueDate`, `title`, `priority`, `status`), `order` (`asc`, `desc`), `limit` (maximum 100), and `offset`.

Task creation accepts `projectId`, `title`, optional `description`, `assigneeId`, `status`, `priority` (`low`, `medium`, `high`) and `dueDate` (`YYYY-MM-DD`). A task assignee must belong to its project. Project resources and tasks are visible only to members. The project creator is its owner and the only role allowed to add members or issue/revoke invitations; the task creator or project owner can delete tasks.

Invitations are addressed to an email and expire after seven days. Creating an invitation returns its opaque one-time token; pass it securely to the invitee (for example, through the client application's email service). The invited user must sign in with the matching email and post the token to `/api/invitations/accept`. Only a SHA-256 hash of the invitation token is stored.

Attachments are limited to 10 MB per file and accepted MIME types are PDF, common image formats, plain text/CSV, DOCX, and XLSX. Uploads are stored under generated names outside the public web root, and downloads require project membership.

## Notifications and AI

Task assignments, task updates, task creation, task comments, and accepted invitations create persistent in-app notifications. Clients can list unread notifications and connect to `/api/notifications/stream` with the bearer token in the `Authorization` header to receive live `notification` SSE events. The stream is process-local; a horizontally scaled deployment should use a shared pub/sub adapter. Avoid putting access tokens in query strings.

AI generation uses an OpenAI-compatible chat-completions API. Set `AI_API_KEY` in `.env`; `AI_BASE_URL` and `AI_MODEL` can be changed for a compatible provider. Without a key, the endpoint responds with HTTP 503 rather than silently returning generated content. Generate a description with:

```json
{ "kind": "description", "title": "Prepare the release", "context": "Verify deployment and rollback steps." }
```

Summarize supplied text with:

```json
{ "kind": "summary", "text": "Release checklist and current task notes..." }
```

Both use `POST /api/ai/generate` and return `{ "kind": "...", "text": "..." }`. Requests are authenticated and rate limited. The supplied text is sent to the configured AI provider; only send content your team is permitted to share with that provider.

Errors use JSON in the form `{ "error": "..." }`. Request validation errors return HTTP 400; unauthenticated requests return 401; forbidden operations return 403; inaccessible or missing resources return 404; duplicate accounts/members return 409.

## Configuration

See [.env.example](./.env.example). `CLIENT_ORIGIN` may contain a comma-separated list of allowed browser origins. AI settings are optional until `/api/ai/generate` is used. Do not commit `.env`, secrets, database files, or uploaded files.

## Deployment

Run `npm install --omit=dev` and `npm start` in an environment with persistent storage for `DATABASE_FILE` and `UPLOAD_DIR`. Set a strong `JWT_SECRET`, configure `CLIENT_ORIGIN` for the deployed client, and terminate TLS at a trusted HTTPS proxy or load balancer.
