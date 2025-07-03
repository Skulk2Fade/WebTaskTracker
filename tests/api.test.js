const request = require('supertest');
const fs = require('fs');
const path = require('path');

const email = require('../email');

const TEST_DB = path.join(__dirname, 'test.db');
process.env.DB_FILE = TEST_DB;
process.env.SESSION_SECRET = 'testsecret';

let app;

beforeAll(() => {
  if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
  app = require('../server');
});

afterAll(() => {
  if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
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

  // create task
  res = await agent
    .post('/api/tasks')
    .set('CSRF-Token', token)
    .send({ text: 'Test Task', priority: 'high', dueDate: '2099-12-31', category: 'work' });
  expect(res.status).toBe(201);
  const taskId = res.body.id;

  // list tasks
  res = await agent.get('/api/tasks');
  expect(res.status).toBe(200);
  expect(res.body.length).toBe(1);
  expect(res.body[0].text).toBe('Test Task');
  expect(res.body[0].category).toBe('work');

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

