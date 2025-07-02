# Web Task Tracker

This is a simple Express-based task tracker.
Tasks are persisted in a local SQLite database (`tasks.db`).
Each user has their own task list after logging in.

## Installation

Before starting the server, install dependencies:

```bash
npm install
```

This will install `sqlite3` which is used for persistence. The database file
`tasks.db` will be created automatically on first run.
Session data is also stored in this database so it survives server restarts.

## Usage

You **must** set the `SESSION_SECRET` environment variable to a random string or the server will refuse to start. Start the application with:

```bash
export SESSION_SECRET=your_secret_here
npm start
```

The server will run on port 3000 by default if no `PORT` variable is set.

## Authentication

Create an account by sending a POST request to `/api/register` with a `username`
and `password`. Log in via `/api/login` and log out with `/api/logout`. The
frontend includes a simple form for these actions. Tasks are only accessible
when logged in.

## Testing

Automated tests are provided using Jest. Run them with:

```bash
npm test
```
