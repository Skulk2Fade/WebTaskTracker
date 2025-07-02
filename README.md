# Web Task Tracker

This is a simple Express-based task tracker.
Tasks are persisted in a local SQLite database (`tasks.db`).
Each user has their own task list after logging in. Tasks can optionally be assigned a category label so they can be filtered and grouped.
You can also search your tasks by keyword using the search bar at the top of the task list or by sending a `search` query parameter to the `/api/tasks` endpoint.

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
