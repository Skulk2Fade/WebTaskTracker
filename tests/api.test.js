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
