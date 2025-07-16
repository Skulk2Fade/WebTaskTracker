# Web Task Tracker

This is a simple Express-based task tracker.
Tasks are persisted in a local SQLite database (`tasks.db`).
Each user has their own task list after logging in. Tasks can optionally be assigned to another user as well as given a category label so they can be filtered and grouped.
You can also search your tasks by keyword across both task text and comments using the search bar or by sending a `search` query parameter to the `/api/tasks` endpoint. Search strings may include simple boolean expressions using `AND`, `OR` and `NOT` to match complex queries. In addition to filtering by multiple categories with the `categories` parameter and limiting results with `startDate`/`endDate`, you can filter by tags using either a comma separated `tags` list or a boolean expression with `tagQuery`.
Results can be paginated with `page` and `pageSize` query parameters to more easily navigate large task lists.

Tasks can be assigned to another user using `POST /api/tasks/:id/assign` with a `username` in the request body. Assigned tasks will appear in that user's task list.
You can also discuss tasks by adding comments using `POST /api/tasks/:taskId/comments` and view them with `GET /api/tasks/:taskId/comments`.
Tasks may optionally repeat on a daily, weekly, monthly, weekday or last-day schedule by including a `repeatInterval` when creating them. Completing a repeating task automatically schedules the next occurrence.

Users have roles of `admin`, `group_admin`, `member` or `observer`. The first account created becomes the admin. Only admins can create additional users and may specify any of the roles when doing so. Observers cannot modify tasks and group creation is limited to admins or group admins.
For a full list of endpoints see the [API reference](docs/api-reference.md) and the machine-readable [OpenAPI specification](docs/openapi.yaml).

## Installation

Before starting the server, install dependencies:

```bash
npm install
```

This will install `sqlite3` which is used for persistence. The database file
`tasks.db` will be created automatically on first run.
Indexes on the `dueDate`, `userId` and `assignedTo` columns are created to keep
common task queries fast.
Session data is also stored in this database so it survives server restarts.
Rate limit counters are persisted as well so limits continue to apply even after a restart.
Session cookies are configured with `httpOnly`, `sameSite=lax` and
`secure` (enabled when `NODE_ENV` is set to `production`) to help protect
your session from client-side access and CSRF attacks. Additional HTTP
security headers like HSTS and XSS protection are set using the
`helmet` middleware.
A Content Security Policy further restricts resource loading to this server and cdn.jsdelivr.net.
## Linting and Formatting

Run ESLint to check for coding issues and Prettier to automatically format files:

```bash
npm run lint
npm run format
```


## Usage

You **must** set the `SESSION_SECRET` environment variable to a random string or the server will refuse to start. Start the application with:

```bash
export SESSION_SECRET=your_secret_here
npm start
```

An `.env.example` file lists all environment variables used by the application.
Copy it to `.env`, edit the values and `source .env` (or otherwise export the
variables) before starting the server.

The server will run on port 3000 by default if no `PORT` variable is set.
You can configure the bcrypt work factor with the `BCRYPT_ROUNDS` environment
variable (default `12`). Higher values provide stronger hashing but increase CPU
usage. The frequency of automatic reminder checks can be changed with the
`DUE_SOON_CHECK_INTERVAL` environment variable (milliseconds, default `60000`).
To avoid overloading the server when many clients are connected, the number of
connections processed in each reminder cycle can be controlled with
`DUE_SOON_BATCH_SIZE` (default `50`).
Two-factor secrets expire according to `TWO_FA_SECRET_TTL` (milliseconds,
default `600000`) and the TOTP step size can be set with `TOTP_STEP`
(seconds, default `30`).

## Authentication

Create an account by sending a POST request to `/api/register` with a `username`
and `password`. Log in via `/api/login` and log out with `/api/logout`. The
frontend includes a simple form for these actions. Tasks are only accessible
when logged in.

If Google or GitHub OAuth credentials are configured via environment variables
(`GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` and `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET`),
you can also log in using those providers from the login screen. The server only
initializes the required Passport strategies when these variables are present.
When OAuth credentials are set all required Passport modules must be installed.
If any are missing the server will exit at startup rather than silently disabling
OAuth routes. Remove the credentials or install the missing dependencies to
proceed.

Passwords must be at least 8 characters long and include upper and lower case
letters, a number and a special character.

## Two-Factor Authentication

Strengthen account security by enabling time-based one-time passwords.
While logged in, send:

```
POST /api/enable-2fa
```

The response contains a `secret` in base32 format, a `qr` URL that can be
used to generate a QR code for your authenticator app and an `expiresAt`
timestamp. The server encrypts the secret before storing it and the secret is
only valid for a short time. The lifetime defaults to 10 minutes but can be
adjusted with the `TWO_FA_SECRET_TTL` environment variable. When
2FA is enabled you must include a `token` field with the current code alongside
your username and password when calling `/api/login`.
The step size for generating codes defaults to 30 seconds and can be changed
with the `TOTP_STEP` environment variable.

Disable two-factor authentication at any time with:

```
POST /api/disable-2fa
```

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

For security, reset tokens are hashed before being stored in the database so
only the one-time value you receive can be used to change your password.

## CSRF Tokens

The application uses CSRF protection on all non-GET requests. Obtain a token
from `/api/csrf-token` and send it in the `CSRF-Token` header whenever you make
POST, PUT or DELETE requests.

Changing the session (for example by registering, logging in or logging out)
invalidates the previous token. Always fetch a fresh token from the same
endpoint before sending another state-changing request.

Tokens are stored server-side and can be kept in a cookie or fetched
dynamically from JavaScript. The included frontend retrieves a fresh value via
`/api/csrf-token` and stores it in a variable before making API calls. A basic
pattern looks like:

```js
const res = await fetch('/api/csrf-token');
const { csrfToken } = await res.json();
await fetch('/api/tasks', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
  body: JSON.stringify({ text: 'Example task' })
});
```

## Testing

Automated tests are provided using Jest. Make sure all dependencies, including
the Jest test runner, are installed first:

```bash
npm install
```

Run the suite with:

```bash
npm test
```

Jest is listed in `package.json` under `devDependencies`:

```json
  "devDependencies": {
    "jest": "^29.6.1",
    "supertest": "^6.3.3"
  }
```

## Import/Export

Export all of your tasks in JSON or CSV format using:

```
GET /api/tasks/export?format=json|csv
```

Import tasks by sending a POST request to `/api/tasks/import`. Send a JSON array
of task objects, CSV data (`Content-Type: text/csv`), or an iCalendar file
(`Content-Type: text/calendar`). Events within the calendar are converted to
tasks and added to the currently authenticated user's list.

## Reminders

Calling `GET /api/reminders` will send reminder emails for any tasks that are
due or overdue. Tasks that remain incomplete will continue to trigger a reminder
once per day until they are marked done.

## Real-time Notifications

Connect to the `/api/events` endpoint with Server-Sent Events to receive
instant updates when tasks are assigned to you, commented on or become due.
Each event payload includes a `type` field of `task_assigned`, `task_commented`
or `task_due` along with basic task information.

If you grant notification permission in your browser, the service worker will
display a push notification whenever a new event is received, even when the
tab is not focused.

## Notification Preferences

Each user can control whether they receive email reminders or notification
emails for comments and task assignments. You can also enable SMS alerts,
push notifications through a mobile app and direct Slack or Microsoft Teams messages.
Provide a custom template used for all notifications. Retrieve your current settings with:

```
GET /api/preferences
```

Update them by sending:

```
PUT /api/preferences
{ "emailReminders": false, "emailNotifications": true,
  "notifySms": true, "phoneNumber": "+15551234567",
  "pushToken": "abc123",
  "slackId": "U123456",
  "teamsId": "19:xyz@thread.v2",
  "notificationTemplate": "Task '{{text}}' - {{event}}" }
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
data to disk using the `/upload` endpoints. Ensure the directory is **outside**
the `public` folder so uploads are not accessible directly.

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
Uploaded files are validated against a small list of safe MIME types and are
written with `0600` permissions for your user only. The maximum allowed size can
be configured with the `MAX_ATTACHMENT_SIZE` environment variable (bytes,
default `10485760`). Requests exceeding the limit return a `413` response.
If you set `ATTACHMENT_MIN_SPACE`, the server will warn at startup when less
than that many bytes are free in the directory. `ATTACHMENT_QUOTA` limits the
total size of files stored and uploads will fail with `507` once exceeded.

## Time Tracking

Track how long tasks take by logging minutes spent.

```
POST /api/tasks/:taskId/time
{ "minutes": 30 }

GET /api/tasks/:taskId/time
```

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
like Google Calendar so your tasks appear alongside other events. The feed is
generated using a small library module to handle the required escaping and line
folding rules of the specification. Each entry now
includes `PRIORITY` and `STATUS` fields so you can see task importance and
whether it has been completed directly in your calendar.

## Webhooks

You can configure outgoing webhooks by setting the `WEBHOOK_URLS` environment
variable to one or more comma separated URLs. The application will POST a JSON
payload whenever a task is assigned, completed or commented on so you can
integrate with services like Slack or Microsoft Teams.

## Email and SMS Providers

During testing the server merely records outgoing emails and text messages. To
deliver real notifications in production, configure SendGrid and Twilio
credentials via environment variables and install the corresponding packages.

```
SENDGRID_API_KEY=your_key
SENDGRID_FROM_EMAIL=no-reply@example.com
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_FROM_NUMBER=+15551234567
FCM_SERVER_KEY=your_fcm_key
SLACK_BOT_TOKEN=xoxb-your-token
TEAMS_BOT_TOKEN=your_teams_token
```

Install the provider modules:

```bash
npm install @sendgrid/mail twilio
```

FCM, Slack and Teams integration use the built-in `fetch` API so no extra
packages are required.

Create `.env` from the included template if needed and supply your credentials.
You can also run the helper script to automate this step:

```bash
scripts/setup-providers.sh
```


When these variables are present and `@sendgrid/mail` or `twilio` are available,
notifications will be sent through those services instead of being stored in
memory for tests.
