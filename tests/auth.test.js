const request = require('supertest');
const fs = require('fs');
const path = require('path');

const TEST_DB = path.join(__dirname, 'auth_test.db');
process.env.DB_FILE = TEST_DB;
process.env.SESSION_SECRET = 'testsecret';

let app;

const getCsrfToken = async agent => {
  const res = await agent.get('/api/csrf-token');
  return res.body.csrfToken;
};

beforeEach(() => {
  if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
  jest.resetModules();
  app = require('../server');
});

afterAll(() => {
  if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
});


test('login and logout flow', async () => {
  const agent = request.agent(app);

  let token = await getCsrfToken(agent);
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'alice', password: 'Passw0rd!' });

  // logout after registration
  token = await getCsrfToken(agent);
  await agent.post('/api/logout').set('CSRF-Token', token);

  // login
  token = await getCsrfToken(agent);
  let res = await agent
    .post('/api/login')
    .set('CSRF-Token', token)
    .send({ username: 'alice', password: 'Passw0rd!' });
  expect(res.status).toBe(200);
  expect(res.body.username).toBe('alice');

  // verify session
  res = await agent.get('/api/me');
  expect(res.body.user.username).toBe('alice');

  // logout
  token = await getCsrfToken(agent);
  res = await agent.post('/api/logout').set('CSRF-Token', token);
  expect(res.body.ok).toBe(true);

  res = await agent.get('/api/me');
  expect(res.body.user).toBeNull();
});


test('login fails with wrong password', async () => {
  const registerAgent = request.agent(app);
  let token = await getCsrfToken(registerAgent);
  await registerAgent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'bob', password: 'Passw0rd!' });

  const agent = request.agent(app);
  token = await getCsrfToken(agent);
  const res = await agent
    .post('/api/login')
    .set('CSRF-Token', token)
    .send({ username: 'bob', password: 'WrongPass1' });
  expect(res.status).toBe(400);
});


test('login fails for unknown user', async () => {
  const agent = request.agent(app);
  const token = await getCsrfToken(agent);
  const res = await agent
    .post('/api/login')
    .set('CSRF-Token', token)
    .send({ username: 'nosuch', password: 'Passw0rd!' });
  expect(res.status).toBe(400);
});

test('two factor authentication flow', async () => {
  const agent = request.agent(app);

  let token = await getCsrfToken(agent);
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'twofa', password: 'Passw0rd!' });

  token = await getCsrfToken(agent);
  let res = await agent
    .post('/api/enable-2fa')
    .set('CSRF-Token', token);
  expect(res.status).toBe(200);
  const secret = res.body.secret;
  const qr = res.body.qr;
  const expiresAt = res.body.expiresAt;
  expect(secret).toBeTruthy();
  expect(qr).toMatch(/^https:\/\//);
  expect(new Date(expiresAt).getTime()).toBeGreaterThan(Date.now());

  token = await getCsrfToken(agent);
  await agent.post('/api/logout').set('CSRF-Token', token);

  token = await getCsrfToken(agent);
  res = await agent
    .post('/api/login')
    .set('CSRF-Token', token)
    .send({ username: 'twofa', password: 'Passw0rd!' });
  expect(res.status).toBe(400);

  const totp = require('../totp');
  const hexSecret = totp.base32Decode(secret).toString('hex');
  const otp = totp.generateToken(hexSecret);

  token = await getCsrfToken(agent);
  res = await agent
    .post('/api/login')
    .set('CSRF-Token', token)
    .send({ username: 'twofa', password: 'Passw0rd!', token: otp });
  expect(res.status).toBe(200);
});

test('password reset flow', async () => {
  const agent = request.agent(app);

  let token = await getCsrfToken(agent);
  await agent
    .post('/api/register')
    .set('CSRF-Token', token)
    .send({ username: 'resetuser', password: 'OldPass1' });

  token = await getCsrfToken(agent);
  let res = await agent
    .post('/api/request-password-reset')
    .set('CSRF-Token', token)
    .send({ username: 'resetuser' });
  expect(res.status).toBe(200);
  const resetToken = res.body.token;
  expect(resetToken).toBeTruthy();

  token = await getCsrfToken(agent);
  res = await agent
    .post('/api/reset-password')
    .set('CSRF-Token', token)
    .send({ token: resetToken, password: 'NewPass1' });
  expect(res.status).toBe(200);

  token = await getCsrfToken(agent);
  res = await agent
    .post('/api/login')
    .set('CSRF-Token', token)
    .send({ username: 'resetuser', password: 'NewPass1' });
  expect(res.status).toBe(200);
});

