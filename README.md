# Web Task Tracker

This is a simple Express-based task tracker.
Tasks are now persisted in a local SQLite database (`tasks.db`).

## Installation

Before starting the server, install dependencies:

```bash
npm install
```

This will install `sqlite3` which is used for persistence. The database file
`tasks.db` will be created automatically on first run.

## Usage

Start the application with:

```bash
npm start
```

The server will run on port 3000 by default.
