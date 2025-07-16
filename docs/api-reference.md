# API Reference

This document provides a consolidated overview of the HTTP endpoints exposed by the Web Task Tracker application.
For a machine-readable specification you can view [`openapi.yaml`](openapi.yaml).

## Authentication

### `POST /api/register`
Create a new user account.

### `POST /api/login`
Authenticate and start a session. If two-factor authentication is enabled for
the account, include the one-time `token` field in the request body.

### `POST /api/logout`
Terminate the current session.

## Tasks

### `GET /api/tasks`
Retrieve all tasks for the authenticated user. Supports query parameters for
pagination and filtering by date range or categories. The `search` parameter now
accepts simple boolean expressions using `AND`, `OR` and `NOT` for matching task
text or comment content. Tags can be filtered with a comma separated `tags`
parameter or a boolean `tagQuery` expression.

### `POST /api/tasks`
Create a new task. See the schema in the OpenAPI file for available fields.

### `GET /api/tasks/{id}`
Fetch a single task along with any related subtasks, dependencies and comments.

### `PUT /api/tasks/{id}`
Update fields on an existing task.

### `DELETE /api/tasks/{id}`
Remove a task. Requires admin privileges.

### `POST /api/tasks/{id}/time`
Log minutes spent on a task by the current user.

### `GET /api/tasks/{id}/time`
List all recorded time entries for a task.

### `GET /api/tasks/gantt`
Return tasks formatted for a basic Gantt chart. Each entry includes a
`startDate`, `dueDate` and list of `dependencies`.

### `POST /api/tasks/import/github`
Import open issues from a GitHub repository as tasks. Provide an `owner` and
`repo` in the request body. The server uses the `GITHUB_API_TOKEN` environment
variable for authentication with GitHub.

## Reminders

### `GET /api/reminders`
Send reminder emails for tasks that are due or overdue.

## Preferences

### `GET /api/preferences`
Retrieve the current user's notification settings.

### `PUT /api/preferences`
Update email reminder and notification preferences.
You can also enable SMS notifications and provide a custom template using
placeholders like `{{text}}`, `{{due}}`, `{{event}}` and `{{comment}}`.

## Reports

### `GET /api/reports`
Return summary information for the authenticated user including recently
completed task counts and time tracked per group.

For additional routes such as groups, attachments and administrative
endpoints refer to the [OpenAPI specification](openapi.yaml).
