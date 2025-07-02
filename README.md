# Web Task Tracker

This is a simple Express-based task tracker.
Tasks are persisted in a local SQLite database (`tasks.db`).
Each user has their own task list after logging in. Tasks can optionally be assigned to another user as well as given a category label so they can be filtered and grouped.
You can also search your tasks by keyword using the search bar at the top of the task list or by sending a `search` query parameter to the `/api/tasks` endpoint.

Tasks can be assigned to another user using `POST /api/tasks/:id/assign` with a `username` in the request body. Assigned tasks will appear in that user's task list.
You can also discuss tasks by adding comments using `POST /api/tasks/:taskId/comments` and view them with `GET /api/tasks/:taskId/comments`.
Tasks may optionally repeat on a daily, weekly or monthly schedule by including a `repeatInterval` when creating them. Completing a repeating task automatically schedules the next occurrence.

## Installation

Before starting the server, install dependencies:

```bash
npm install
```

This will install `sqlite3` which is used for persistence. The database file
`tasks.db` will be created automatically on first run.
Session data is also stored in this database so it survives server restarts.
Session cookies are configured with `httpOnly`, `sameSite=lax` and
`secure` (enabled when `NODE_ENV` is set to `production`) to help protect
your session from client-side access and CSRF attacks.

## Usage

You **must** set the `SESSION_SECRET` environment variable to a random string or the server will refuse to start. Start the application with:

```bash
export SESSION_SECRET=your_secret_here
npm start
```

The server will run on port 3000 by default if no `PORT` variable is set.
You can configure the bcrypt work factor with the `BCRYPT_ROUNDS` environment
variable (default `12`). Higher values provide stronger hashing but increase CPU
usage.

## Authentication

Create an account by sending a POST request to `/api/register` with a `username`
and `password`. Log in via `/api/login` and log out with `/api/logout`. The
frontend includes a simple form for these actions. Tasks are only accessible
when logged in.

Passwords must be at least 8 characters long and include upper and lower case
letters and a number.

## Password Reset

If you forget your password, request a reset token by sending a POST request to
`/api/request-password-reset` with your `username` in the body. The server
responds with a one-time `token` (in a real deployment this would be emailed to
you). Submit the token together with a new password to `/api/reset-password`:

```
POST /api/reset-password
{ "token": "token_from_request", "password": "NewPass1" }
```

The same password strength rules apply when setting a new password.

## CSRF Tokens

The application uses CSRF protection on all non-GET requests. Obtain a token
from `/api/csrf-token` and send it in the `CSRF-Token` header whenever you make
POST, PUT or DELETE requests.

Changing the session (for example by registering, logging in or logging out)
invalidates the previous token. Always fetch a fresh token from the same
endpoint before sending another state-changing request.

## Testing

Automated tests are provided using Jest. Run them with:

```bash
npm test
```

## Import/Export

Export all of your tasks in JSON or CSV format using:

```
GET /api/tasks/export?format=json|csv
```

Import tasks by sending a POST request to `/api/tasks/import`. Send a JSON array
of task objects or CSV data (set `Content-Type: text/csv`). Imported tasks are
added to the currently authenticated user's list.
