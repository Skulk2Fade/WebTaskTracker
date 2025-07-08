const request = require('supertest');
const fs = require('fs');
const path = require('path');

const email = require('../email');
const webhooks = require('../webhooks');

process.env.WEBHOOK_URLS = 'http://example.com/hook';

const TEST_DB = path.join(__dirname, 'test.db');
process.env.DB_FILE = TEST_DB;
process.env.SESSION_SECRET = 'testsecret';
const UPLOAD_DIR = path.join(__dirname, 'uploads');
process.env.ATTACHMENT_DIR = UPLOAD_DIR;
process.env.MAX_ATTACHMENT_SIZE = '20';

let app;

beforeAll(() => {
  if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
  if (fs.existsSync(UPLOAD_DIR)) fs.rmSync(UPLOAD_DIR, { recursive: true });
  app = require('../server');
});

afterAll(() => {
  if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
  if (fs.existsSync(UPLOAD_DIR)) fs.rmSync(UPLOAD_DIR, { recursive: true });
});

test('register user and CRUD tasks', async () => {
  const agent = request.agent(app);
  // get csrf token
  let res = await agent.get('/api/csrf-token');
  let token = res.body.csrfToken;

  // weak password should fail
  res = await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'alice', password: 'pass' });
  expect(res.status).toBe(400);

  // new token
  res = await agent.get('/api/csrf-token');
  token = res.body.csrfToken;

  // register with strong password
  res = await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'alice', password: 'Passw0rd!' });
  expect(res.status).toBe(200);
  expect(res.body.username).toBe('alice');

  // new csrf token
  res = await agent.get('/api/csrf-token');
  token = res.body.csrfToken;

  // invalid due date (past)
  res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'Past', dueDate: '2000-01-01' });
  expect(res.status).toBe(400);

  // invalid due date format
  res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'Bad', dueDate: '2020/01/01' });
  expect(res.status).toBe(400);

  // invalid due time
  res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'BadTime', dueDate: '2099-01-01', dueTime: '25:00' });
  expect(res.status).toBe(400);

  // create task
  res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'Test Task', priority: 'high', dueDate: '2099-12-31', dueTime: '12:30', category: 'work' });
  expect(res.status).toBe(201);
  expect(res.body.status).toBe('todo');
  const taskId = res.body.id;

  // list tasks
  res = await agent.get('/api/tasks');
  expect(res.status).toBe(200);
  expect(res.body.length).toBe(1);
  expect(res.body[0].text).toBe('Test Task');
  expect(res.body[0].category).toBe('work');
  expect(res.body[0].dueTime).toBe('12:30');
  expect(res.body[0].status).toBe('todo');

  // create subtask
  res = await agent
    .post(`/api/tasks/${taskId}/subtasks`)
    .set('CSRF-Token', token)
    .send({ text: 'Step 1' });
  expect(res.status).toBe(201);
  const subId = res.body.id;

  // list subtasks
  res = await agent.get(`/api/tasks/${taskId}/subtasks`);
  expect(res.status).toBe(200);
  expect(res.body.length).toBe(1);

  // create comment
  res = await agent
    .post(`/api/tasks/${taskId}/comments`)
    .set('CSRF-Token', token)
    .send({ text: 'Nice task' });
  expect(res.status).toBe(201);
  const commentId = res.body.id;

  // list comments
  res = await agent.get(`/api/tasks/${taskId}/comments`);
  expect(res.status).toBe(200);
  expect(res.body.length).toBe(1);

  // delete comment
  res = await agent
    .delete(`/api/comments/${commentId}`)
    .set('CSRF-Token', token);
  expect(res.status).toBe(200);

  // filter by category
  res = await agent.get('/api/tasks?category=work');
  expect(res.status).toBe(200);
  expect(res.body.length).toBe(1);

  // search by keyword
  res = await agent.get('/api/tasks?search=Test');
  expect(res.status).toBe(200);
  expect(res.body.length).toBe(1);

  // update subtask
  res = await agent
    .put(`/api/subtasks/${subId}`)
    .set('CSRF-Token', token)
    .send({ done: true });
  expect(res.body.done).toBe(true);

  // update task
  res = await agent
    .put(`/api/tasks/${taskId}`)
    .set('CSRF-Token', token)
    .send({ done: true });
  expect(res.body.done).toBe(true);
  expect(res.body.status).toBe('completed');

  // delete subtask
  res = await agent
    .delete(`/api/subtasks/${subId}`)
    .set('CSRF-Token', token);
  expect(res.status).toBe(200);

  // delete task
  res = await agent
    .delete(`/api/tasks/${taskId}`)
    .set('CSRF-Token', token);
  expect(res.status).toBe(200);

  res = await agent.get('/api/tasks');
  expect(res.body.length).toBe(0);
});

test('advanced filtering', async () => {
  const agent = request.agent(app);

  let token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'filter', password: 'Passw0rd!' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  let res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'A', dueDate: '2099-01-02', category: 'work' });
  const id1 = res.body.id;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'B', dueDate: '2099-01-05', category: 'home' });
  const id2 = res.body.id;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post(`/api/tasks/${id2}/comments`)
    .set('CSRF-Token', token)
    .send({ text: 'keyword' });

  res = await agent.get('/api/tasks?startDate=2099-01-01&endDate=2099-01-03');
  expect(res.body.length).toBe(1);
  expect(res.body[0].id).toBe(id1);

  res = await agent.get('/api/tasks?categories=work,home');
  expect(res.body.length).toBe(2);

  res = await agent.get('/api/tasks?search=keyword');
  expect(res.body.length).toBe(1);
  expect(res.body[0].id).toBe(id2);
});

test('filter by tags', async () => {
  const agent = request.agent(app);

  let token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'taguser', password: 'Passw0rd!' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'T1', tags: ['a', 'b'] });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'T2', tags: ['b'] });

  let res = await agent.get('/api/tasks?tags=a');
  expect(res.body.length).toBe(1);
  expect(res.body[0].text).toBe('T1');

  res = await agent.get('/api/tasks?tags=a,b');
  expect(res.body.length).toBe(1);
  expect(res.body[0].text).toBe('T1');
});

test('assign task to another user', async () => {
  const alice = request.agent(app);
  const bob = request.agent(app);

  let token = (await alice.get('/api/csrf-token')).body.csrfToken;
  await alice
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'alice', password: 'Passw0rd!' });

  // register second user while logged in as admin alice
  token = (await alice.get('/api/csrf-token')).body.csrfToken;
  await alice
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'bob', password: 'Passw0rd!' });

  // bob logs in
  token = (await bob.get('/api/csrf-token')).body.csrfToken;
  await bob
    .post('/api/login')
    .set('CSRF-Token', token)
    .send({ username: 'bob', password: 'Passw0rd!' });

  token = (await alice.get('/api/csrf-token')).body.csrfToken;
  let res = await alice
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'Shared Task' });
  const taskId = res.body.id;

  token = (await alice.get('/api/csrf-token')).body.csrfToken;
  res = await alice
    .post(`/api/tasks/${taskId}/assign`)
    .set('CSRF-Token', token)
    .send({ username: 'bob' });
  expect(res.status).toBe(200);

  res = await bob.get('/api/tasks');
  expect(res.body.length).toBe(1);
  expect(res.body[0].text).toBe('Shared Task');
});

test('recurring task creates next occurrence when completed', async () => {
  const agent = request.agent(app);

  let token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'carol', password: 'Passw0rd!' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  let res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'Repeat', dueDate: '2099-01-01', repeatInterval: 'daily' });
  const taskId = res.body.id;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  res = await agent
    .put(`/api/tasks/${taskId}`)
    .set('CSRF-Token', token)
    .send({ done: true });
  expect(res.body.done).toBe(true);

  res = await agent.get('/api/tasks?sort=dueDate');
  expect(res.body.length).toBe(2);
  const dates = res.body.map(t => t.dueDate).sort();
  expect(dates).toContain('2099-01-01');
  expect(dates).toContain('2099-01-02');
});

test('weekday recurring task skips weekends', async () => {
  const agent = request.agent(app);

  let token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'week', password: 'Passw0rd!' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  let res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'WD', dueDate: '2099-01-02', repeatInterval: 'weekday' });
  const taskId = res.body.id;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .put(`/api/tasks/${taskId}`)
    .set('CSRF-Token', token)
    .send({ done: true });

  res = await agent.get('/api/tasks?sort=dueDate');
  const dates = res.body.map(t => t.dueDate).sort();
  expect(dates).toContain('2099-01-02');
  expect(dates).toContain('2099-01-05');
});

test('last day recurring task uses last day of next month', async () => {
  const agent = request.agent(app);

  let token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'month', password: 'Passw0rd!' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  let res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'LD', dueDate: '2099-01-31', repeatInterval: 'last_day' });
  const taskId = res.body.id;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .put(`/api/tasks/${taskId}`)
    .set('CSRF-Token', token)
    .send({ done: true });

  res = await agent.get('/api/tasks?sort=dueDate');
  const dates = res.body.map(t => t.dueDate).sort();
  expect(dates).toContain('2099-01-31');
  expect(dates).toContain('2099-02-28');
});

test('bulk update and delete', async () => {
  const agent = request.agent(app);

  let token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'dan', password: 'Passw0rd!' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  let res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'A' });
  const id1 = res.body.id;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'B' });
  const id2 = res.body.id;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  res = await agent
    .put('/api/tasks/bulk')
    .set('CSRF-Token', token)
    .send({ ids: [id1, id2], done: true });
  expect(res.status).toBe(200);
  expect(res.body.length).toBe(2);
  expect(res.body.every(t => t.done)).toBe(true);

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  res = await agent
    .post('/api/tasks/bulk-delete')
    .set('CSRF-Token', token)
    .send({ ids: [id1, id2] });
  expect(res.status).toBe(200);

  res = await agent.get('/api/tasks');
  expect(res.body.length).toBe(0);
});

test('export and import tasks as JSON and CSV', async () => {
  const agent = request.agent(app);

  let token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'eve', password: 'Passw0rd!' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'T1' });

  let res = await agent.get('/api/tasks/export?format=json');
  expect(res.status).toBe(200);
  expect(Array.isArray(res.body)).toBe(true);
  expect(res.body.length).toBe(1);
  const jsonData = res.body;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  res = await agent
    .post('/api/tasks/import')
    .set('CSRF-Token', token)
    .send(jsonData);
  expect(res.status).toBe(201);

  res = await agent.get('/api/tasks');
  expect(res.body.length).toBe(2);

  res = await agent.get('/api/tasks/export?format=csv');
  expect(res.status).toBe(200);
  expect(res.headers['content-type']).toMatch(/text\/csv/);
  const csv = res.text;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  res = await agent
    .post('/api/tasks/import')
    .set('CSRF-Token', token)
    .set('Content-Type', 'text/csv')
    .send(csv);
  expect(res.status).toBe(201);

  res = await agent.get('/api/tasks');
  expect(res.body.length).toBe(4);
});

test('ICS feed returns calendar data', async () => {
  const agent = request.agent(app);

  let token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'ical', password: 'Passw0rd!' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'ICS Task', dueDate: '2099-12-31' });

  const res = await agent.get('/api/tasks/ics');
  expect(res.status).toBe(200);
  expect(res.headers['content-type']).toMatch(/text\/calendar/);
  expect(res.text).toMatch(/BEGIN:VCALENDAR/);
  expect(res.text).toMatch(/SUMMARY:ICS Task/);
});

test('ICS uses user timezone', async () => {
  const agent = request.agent(app);

  let token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'tzuser', password: 'Passw0rd!' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .put('/api/preferences')
    .set('CSRF-Token', token)
    .send({ timezone: 'America/Los_Angeles' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'TZ Task', dueDate: '2099-12-31', dueTime: '12:00' });

  const res = await agent.get('/api/tasks/ics');
  expect(res.status).toBe(200);
  expect(res.text).toMatch(/DUE:20991231T200000Z/);
});

test('email notifications on assign, comment and reminder', async () => {
  const alice = request.agent(app);
  const bob = request.agent(app);

  let token = (await alice.get('/api/csrf-token')).body.csrfToken;
  await alice
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'alice', password: 'Passw0rd!' });

  token = (await alice.get('/api/csrf-token')).body.csrfToken;
  await alice
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'bob', password: 'Passw0rd!' });

  token = (await bob.get('/api/csrf-token')).body.csrfToken;
  await bob
    .post('/api/login')
    .set('CSRF-Token', token)
    .send({ username: 'bob', password: 'Passw0rd!' });

  email.clearEmails();
  token = (await alice.get('/api/csrf-token')).body.csrfToken;
  let res = await alice
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'Notify Task' });
  const taskId = res.body.id;

  token = (await alice.get('/api/csrf-token')).body.csrfToken;
  await alice
    .post(`/api/tasks/${taskId}/assign`)
    .set('CSRF-Token', token)
    .send({ username: 'bob' });
  expect(email.sentEmails.some(e => e.to === 'bob@example.com')).toBe(true);

  email.clearEmails();
  token = (await bob.get('/api/csrf-token')).body.csrfToken;
  await bob
    .post(`/api/tasks/${taskId}/comments`)
    .set('CSRF-Token', token)
    .send({ text: 'hello' });
  expect(email.sentEmails.some(e => e.to === 'alice@example.com')).toBe(true);

  email.clearEmails();
  const today = new Date().toISOString().slice(0, 10);
  token = (await bob.get('/api/csrf-token')).body.csrfToken;
  await bob
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'Due Soon', dueDate: today });

  await bob.get('/api/reminders');
  expect(email.sentEmails.some(e => e.to === 'bob@example.com')).toBe(true);
});

test('task history records actions', async () => {
  const admin = request.agent(app);
  const user = request.agent(app);

  let token = (await admin.get('/api/csrf-token')).body.csrfToken;
  await admin
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'henry', password: 'Passw0rd!' });

  token = (await admin.get('/api/csrf-token')).body.csrfToken;
  await admin
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'ida', password: 'Passw0rd!' });

  token = (await user.get('/api/csrf-token')).body.csrfToken;
  await user
    .post('/api/login')
    .set('CSRF-Token', token)
    .send({ username: 'ida', password: 'Passw0rd!' });

  token = (await admin.get('/api/csrf-token')).body.csrfToken;
  let res = await admin
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'History Task' });
  const taskId = res.body.id;

  token = (await admin.get('/api/csrf-token')).body.csrfToken;
  await admin
    .post(`/api/tasks/${taskId}/assign`)
    .set('CSRF-Token', token)
    .send({ username: 'ida' });

  token = (await user.get('/api/csrf-token')).body.csrfToken;
  await user
    .post(`/api/tasks/${taskId}/comments`)
    .set('CSRF-Token', token)
    .send({ text: 'hello' });

  token = (await user.get('/api/csrf-token')).body.csrfToken;
  await user
    .put(`/api/tasks/${taskId}`)
    .set('CSRF-Token', token)
    .send({ done: true });

  res = await user.get(`/api/tasks/${taskId}/history`);
  expect(res.status).toBe(200);
  const actions = res.body.map(e => e.action);
  expect(actions).toContain('created');
  expect(actions).toContain('assigned');
  expect(actions).toContain('commented');
  expect(actions).toContain('updated');
});

test('task and comment attachments', async () => {
  const agent = request.agent(app);

  let token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'attach', password: 'Passw0rd!' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  let res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'With file' });
  const taskId = res.body.id;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  res = await agent
    .post(`/api/tasks/${taskId}/attachments`)
    .set('CSRF-Token', token)
    .send({
      filename: 'a.txt',
      mimeType: 'text/plain',
      content: Buffer.from('hello').toString('base64')
    });
  expect(res.status).toBe(201);
  const attachId = res.body.id;

  res = await agent.get(`/api/tasks/${taskId}/attachments`);
  expect(res.body.length).toBe(1);

  res = await agent.get(`/api/attachments/${attachId}`);
  expect(res.text).toBe('hello');

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  res = await agent
    .post(`/api/tasks/${taskId}/comments`)
    .set('CSRF-Token', token)
    .send({ text: 'c1' });
  const commentId = res.body.id;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  res = await agent
    .post(`/api/comments/${commentId}/attachments`)
    .set('CSRF-Token', token)
    .send({
      filename: 'c.txt',
      mimeType: 'text/plain',
      content: Buffer.from('comment').toString('base64')
    });
  expect(res.status).toBe(201);

  res = await agent.get(`/api/comments/${commentId}/attachments`);
  expect(res.body.length).toBe(1);
});

test('streaming attachment upload', async () => {
  const agent = request.agent(app);

  let token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'stream', password: 'Passw0rd!' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  let res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'stream' });
  const taskId = res.body.id;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  res = await agent
    .post(`/api/tasks/${taskId}/attachments/upload`)
    .set('CSRF-Token', token)
    .set('X-Filename', 'b.txt')
    .set('Content-Type', 'application/octet-stream')
    .send('world');
  expect(res.status).toBe(201);
  const attachId = res.body.id;

  res = await agent.get(`/api/attachments/${attachId}`);
  expect(res.text).toBe('world');
});

test('attachment size limit enforced', async () => {
  const agent = request.agent(app);

  let token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'limit', password: 'Passw0rd!' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  let res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'limit' });
  const taskId = res.body.id;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  const big = 'x'.repeat(25);
  res = await agent
    .post(`/api/tasks/${taskId}/attachments/upload`)
    .set('CSRF-Token', token)
    .set('X-Filename', 'big.txt')
    .set('Content-Type', 'application/octet-stream')
    .send(big);
  expect(res.status).toBe(413);
});

test('notification preferences disable emails', async () => {
  const alice = request.agent(app);
  const bob = request.agent(app);

  let token = (await alice.get('/api/csrf-token')).body.csrfToken;
  await alice
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'alice', password: 'Passw0rd!' });

  token = (await alice.get('/api/csrf-token')).body.csrfToken;
  await alice
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'bob', password: 'Passw0rd!' });

  token = (await bob.get('/api/csrf-token')).body.csrfToken;
  await bob
    .post('/api/login')
    .set('CSRF-Token', token)
    .send({ username: 'bob', password: 'Passw0rd!' });

  // Bob disables notifications
  token = (await bob.get('/api/csrf-token')).body.csrfToken;
  await bob
    .put('/api/preferences')
    .set('CSRF-Token', token)
    .send({ emailReminders: false, emailNotifications: false });

  email.clearEmails();
  token = (await alice.get('/api/csrf-token')).body.csrfToken;
  let res = await alice
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'Pref Task' });
  const taskId = res.body.id;

  token = (await alice.get('/api/csrf-token')).body.csrfToken;
  await alice
    .post(`/api/tasks/${taskId}/assign`)
    .set('CSRF-Token', token)
    .send({ username: 'bob' });
  expect(email.sentEmails.some(e => e.to === 'bob@example.com')).toBe(false);

  email.clearEmails();
  token = (await bob.get('/api/csrf-token')).body.csrfToken;
  await bob
    .post(`/api/tasks/${taskId}/comments`)
    .set('CSRF-Token', token)
    .send({ text: 'hello' });
  expect(email.sentEmails.some(e => e.to === 'alice@example.com')).toBe(true);

  email.clearEmails();
  const today = new Date().toISOString().slice(0, 10);
  token = (await bob.get('/api/csrf-token')).body.csrfToken;
  await bob
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'Due', dueDate: today });

  await bob.get('/api/reminders');
  expect(email.sentEmails.length).toBe(0);
});

test('task dependencies enforcement', async () => {
  const agent = request.agent(app);

  let token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'deps', password: 'Passw0rd!' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  let res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'First' });
  const firstId = res.body.id;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'Second' });
  const secondId = res.body.id;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post(`/api/tasks/${firstId}/dependencies`)
    .set('CSRF-Token', token)
    .send({ dependsOn: secondId });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  res = await agent
    .put(`/api/tasks/${firstId}`)
    .set('CSRF-Token', token)
    .send({ done: true });
  expect(res.status).toBe(400);

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .put(`/api/tasks/${secondId}`)
    .set('CSRF-Token', token)
    .send({ done: true });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  res = await agent
    .put(`/api/tasks/${firstId}`)
    .set('CSRF-Token', token)
    .send({ done: true });
  expect(res.body.done).toBe(true);
});

test('tasks endpoint supports pagination', async () => {
  const agent = request.agent(app);

  let token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'pager', password: 'Passw0rd!' });

  for (let i = 0; i < 3; i++) {
    token = (await agent.get('/api/csrf-token')).body.csrfToken;
    await agent
      .post('/api/tasks')
      .set('CSRF-Token', token)
      .send({ text: `Task ${i}` });
  }

  let res = await agent.get('/api/tasks?page=1&pageSize=2');
  expect(res.status).toBe(200);
  expect(res.body.length).toBe(2);

  res = await agent.get('/api/tasks?page=2&pageSize=2');
  expect(res.status).toBe(200);
  expect(res.body.length).toBe(1);
});

test('admin endpoints require admin role', async () => {
  const adminAgent = request.agent(app);
  let token = (await adminAgent.get('/api/csrf-token')).body.csrfToken;
  await adminAgent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'admin', password: 'Passw0rd!' });

  const userAgent = request.agent(app);
  token = (await userAgent.get('/api/csrf-token')).body.csrfToken;
  await userAgent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'user', password: 'Passw0rd!' });

  token = (await userAgent.get('/api/csrf-token')).body.csrfToken;
  await userAgent
    .post('/api/login')
    .set('CSRF-Token', token)
    .send({ username: 'user', password: 'Passw0rd!' });

  let res = await userAgent.get('/api/admin/stats');
  expect(res.status).toBe(403);

  token = (await adminAgent.get('/api/csrf-token')).body.csrfToken;
  await adminAgent
    .post('/api/login')
    .set('CSRF-Token', token)
    .send({ username: 'admin', password: 'Passw0rd!' });

  res = await adminAgent.get('/api/admin/stats');
  expect(res.status).toBe(200);
  expect(res.body.users).toBeDefined();

  res = await adminAgent.get('/api/admin/reports');
  expect(res.status).toBe(200);
  expect(res.body.overdue).toBeDefined();
});

test('webhooks triggered on task actions', async () => {
  const admin = request.agent(app);
  const user = request.agent(app);

  let token = (await admin.get('/api/csrf-token')).body.csrfToken;
  await admin
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'hookadmin', password: 'Passw0rd!' });

  token = (await admin.get('/api/csrf-token')).body.csrfToken;
  await admin
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'hookuser', password: 'Passw0rd!' });

  token = (await user.get('/api/csrf-token')).body.csrfToken;
  await user
    .post('/api/login')
    .set('CSRF-Token', token)
    .send({ username: 'hookuser', password: 'Passw0rd!' });

  webhooks.clearWebhooks();
  token = (await admin.get('/api/csrf-token')).body.csrfToken;
  let res = await admin
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'Hook Task' });
  const taskId = res.body.id;

  token = (await admin.get('/api/csrf-token')).body.csrfToken;
  await admin
    .post(`/api/tasks/${taskId}/assign`)
    .set('CSRF-Token', token)
    .send({ username: 'hookuser' });
  expect(webhooks.sentWebhooks.some(h => h.payload.event === 'task_assigned')).toBe(true);

  webhooks.clearWebhooks();
  token = (await user.get('/api/csrf-token')).body.csrfToken;
  await user
    .post(`/api/tasks/${taskId}/comments`)
    .set('CSRF-Token', token)
    .send({ text: 'hi' });
  expect(webhooks.sentWebhooks.some(h => h.payload.event === 'task_commented')).toBe(true);

  webhooks.clearWebhooks();
  token = (await user.get('/api/csrf-token')).body.csrfToken;
  await user
    .put(`/api/tasks/${taskId}`)
    .set('CSRF-Token', token)
    .send({ done: true });
  expect(webhooks.sentWebhooks.some(h => h.payload.event === 'task_completed')).toBe(true);
});


test('get single task with related data', async () => {
  const agent = request.agent(app);

  let token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'single', password: 'Passw0rd!' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  let res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'Main' });
  const mainId = res.body.id;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'Dep' });
  const depId = res.body.id;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post(`/api/tasks/${mainId}/subtasks`)
    .set('CSRF-Token', token)
    .send({ text: 'Sub' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post(`/api/tasks/${mainId}/dependencies`)
    .set('CSRF-Token', token)
    .send({ dependsOn: depId });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post(`/api/tasks/${mainId}/comments`)
    .set('CSRF-Token', token)
    .send({ text: 'hello' });

  res = await agent.get(`/api/tasks/${mainId}`);
  expect(res.status).toBe(200);
  expect(res.body.id).toBe(mainId);
  expect(res.body.subtasks.length).toBe(1);
  expect(res.body.dependencies).toContain(depId);
  expect(res.body.comments.length).toBe(1);
});

test('custom task statuses', async () => {
  const agent = request.agent(app);

  let token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'statususer', password: 'Passw0rd!' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  let res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'Status Task', status: 'in progress' });
  expect(res.status).toBe(201);
  const taskId = res.body.id;
  expect(res.body.status).toBe('in progress');

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  res = await agent
    .put(`/api/tasks/${taskId}`)
    .set('CSRF-Token', token)
    .send({ status: 'blocked' });
  expect(res.status).toBe(200);
  expect(res.body.status).toBe('blocked');
});

test('task time tracking', async () => {
  const agent = request.agent(app);

  let token = (await agent.get('/api/csrf-token')).body.csrfToken;
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'timer', password: 'Passw0rd!' });

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  let res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'Timed' });
  const taskId = res.body.id;

  token = (await agent.get('/api/csrf-token')).body.csrfToken;
  res = await agent
    .post(`/api/tasks/${taskId}/time`)
    .set('CSRF-Token', token)
    .send({ minutes: 15 });
  expect(res.status).toBe(201);

  res = await agent.get(`/api/tasks/${taskId}/time`);
  expect(res.status).toBe(200);
  expect(res.body.length).toBe(1);
  expect(res.body[0].minutes).toBe(15);
});

