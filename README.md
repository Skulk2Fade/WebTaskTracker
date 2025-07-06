# Web Task Tracker

This is a simple Express-based task tracker.
Tasks are persisted in a local SQLite database (`tasks.db`).
Each user has their own task list after logging in. Tasks can optionally be assigned to another user as well as given a category label so they can be filtered and grouped.
You can also search your tasks by keyword across both task text and comments using the search bar or by sending a `search` query parameter to the `/api/tasks` endpoint. The task list endpoint additionally supports filtering by multiple categories with the `categories` query parameter and limiting results to a due date range via `startDate` and `endDate`.
Results can be paginated with `page` and `pageSize` query parameters to more easily navigate large task lists.

Tasks can be assigned to another user using `POST /api/tasks/:id/assign` with a `username` in the request body. Assigned tasks will appear in that user's task list.
You can also discuss tasks by adding comments using `POST /api/tasks/:taskId/comments` and view them with `GET /api/tasks/:taskId/comments`.
Tasks may optionally repeat on a daily, weekly or monthly schedule by including a `repeatInterval` when creating them. Completing a repeating task automatically schedules the next occurrence.

Users have roles of either `admin` or `member`. The first account created becomes the admin. Once an admin exists, only admins can create additional users, assign tasks or delete tasks.

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

If Google or GitHub OAuth credentials are configured via environment variables
(`GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` and `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET`),
you can also log in using those providers from the login screen.

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

## Reminders

Calling `GET /api/reminders` will send reminder emails for any tasks that are
due or overdue. Tasks that remain incomplete will continue to trigger a reminder
once per day until they are marked done.

## Real-time Notifications

Connect to the `/api/events` endpoint with Server-Sent Events to receive
instant updates when tasks are assigned to you, commented on or become due.
Each event payload includes a `type` field of `task_assigned`, `task_commented`
or `task_due` along with basic task information.

## Notification Preferences

Each user can control whether they receive email reminders or notification
emails for comments and task assignments. Retrieve your current settings with:

```
GET /api/preferences
```

Update them by sending:

```
PUT /api/preferences
{ "emailReminders": false, "emailNotifications": true }
```

## Groups

Create a team with:

```
POST /api/groups
{ "name": "Team A" }
```

Join an existing group:

```
POST /api/groups/:id/join
```

List your groups:

```
GET /api/groups
```

When creating a task you can specify `groupId` so it is shared with all group members.

## Attachments

You can attach files to tasks or comments. By default the body should contain
base64 encoded `content` which is stored directly in the database. If the
`ATTACHMENT_DIR` environment variable is set, you can also stream raw file
data to disk using the `/upload` endpoints.

```
POST /api/tasks/:taskId/attachments
{ "filename": "info.txt", "mimeType": "text/plain", "content": "base64data" }

POST /api/tasks/:taskId/attachments/upload  (binary body with X-Filename header)
POST /api/comments/:commentId/attachments/upload  (binary body with X-Filename header)

GET /api/tasks/:taskId/attachments
GET /api/comments/:commentId/attachments
GET /api/attachments/:id
```

Streaming uploads require `ATTACHMENT_DIR` to point to a writable directory.

## Markdown Formatting

Task text and comment bodies support basic Markdown formatting. When viewing
tasks or comments in the web interface, any Markdown syntax will be rendered
as HTML for improved readability.

```
**bold**, *italic*, `code`
```

Markdown is not processed on the server; raw text is stored and sanitized in the
browser before being inserted into the page.

## Calendar View

Open `calendar.html` in the `public` directory to see tasks on a monthly calendar. Use the Prev and Next buttons to navigate between months.

### Calendar Integrations

Subscribe to your tasks in any calendar application using the iCalendar feed:

```
GET /api/tasks/ics
```

The endpoint returns a standard `.ics` file that can be imported into clients
like Google Calendar so your tasks appear alongside other events. Each entry now
includes `PRIORITY` and `STATUS` fields so you can see task importance and
whether it has been completed directly in your calendar.

## Webhooks

You can configure outgoing webhooks by setting the `WEBHOOK_URLS` environment
variable to one or more comma separated URLs. The application will POST a JSON
payload whenever a task is assigned, completed or commented on so you can
integrate with services like Slack or Microsoft Teams.
