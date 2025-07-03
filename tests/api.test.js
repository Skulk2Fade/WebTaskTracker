const request = require('supertest');
const fs = require('fs');
const path = require('path');

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

  // update task
  res = await agent
    .put(`/api/tasks/${taskId}`)
    .set('CSRF-Token', token)
    .send({ done: true });
  expect(res.body.done).toBe(true);

  // update subtask
  res = await agent
    .put(`/api/subtasks/${subId}`)
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
