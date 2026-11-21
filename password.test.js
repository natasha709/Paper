'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const Module = require('node:module');

// server.js loads dotenv by absolute project path; suppress it before any server starts.
if (!process.env.TIS_PASSWORD_TEST_DOTENV_BLOCKED) {
  const originalLoad = Module._load;
  Module._load = function(request, parent, isMain) {
    if (request === 'dotenv') return { config: () => ({ parsed: {} }) };
    return originalLoad.apply(this, arguments);
  };
  process.env.TIS_PASSWORD_TEST_DOTENV_BLOCKED = '1';
}

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const invitationToken = 'a'.repeat(64);
const sharedPassword = 'synthetic-shared-password';
const testKey = Buffer.alloc(32, 7).toString('base64');
const secrets = new Set([
  sharedPassword, 'synthetic-admin-password', 'synthetic-hash-password',
  'synthetic-student-password', 'synthetic-plain-password', 'synthetic-stale-password',
  'synthetic-scrypt-password', 'pending-new-password', 'teacher-new-password',
  'synthetic-reset-password', 'synthetic-reset', '123'
]);

function scryptHash(password) {
  const salt = Buffer.alloc(16, 3);
  const derived = crypto.scryptSync(password, salt, 32, { N: 32768, r: 8, p: 3, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${salt.toString('hex')}$${derived.toString('hex')}`;
}

function encryptFixture(password, id) {
  const iv = Buffer.alloc(12, 4);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(testKey, 'base64'), iv);
  cipher.setAAD(Buffer.from(id));
  const encrypted = Buffer.concat([cipher.update(password, 'utf8'), cipher.final()]);
  return `v1$${iv.toString('hex')}$${cipher.getAuthTag().toString('hex')}$${encrypted.toString('base64')}`;
}

function legacyUser(id, role, password, extra = {}) {
  return {
    id, role, username: id, name: `Synthetic ${id}`, email: `${id}@example.test`,
    assignedSubjects: ['Biology'], passwordHash: sha256(password),
    plainTextNotice: password, ...extra
  };
}

function fixture(t, users) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tis-password-test-'));
  const data = path.join(root, 'data');
  const uploads = path.join(root, 'uploads');
  fs.mkdirSync(data);
  fs.mkdirSync(uploads);
  const usersFile = path.join(data, 'users.json');
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
  return { root, data, uploads, usersFile };
}

async function freePort() {
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve()));
  return port;
}

async function startServer(t, dirs, environment = {}, script = path.join(__dirname, 'server.js')) {
  const port = await freePort();
  const child = spawn(process.execPath, ['--require', __filename, script], {
    cwd: dirs.root,
    env: {
      PATH: process.env.PATH || '', SystemRoot: process.env.SystemRoot || '',
      NODE_ENV: 'test', PORT: String(port), DATA_DIR: dirs.data, UPLOADS_DIR: dirs.uploads,
      GMAIL_USER: '', GMAIL_APP_PASSWORD: '', APP_URL: 'http://127.0.0.1',
      PASSWORD_ENCRYPTION_KEY: testKey, ...environment
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let output = '';
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { output += chunk; });
  const exited = new Promise((resolve, reject) => {
    child.once('exit', (code, signal) => resolve({ code, signal }));
    child.once('error', reject);
  });
  t.after(async () => {
    try {
      if (child.exitCode === null && child.signalCode === null) child.kill();
      await exited;
    } finally {
      fs.rmSync(dirs.root, { recursive: true, force: true });
    }
  });
  return { child, exited, port, output: () => output };
}

async function waitForServer(server) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (server.child.exitCode !== null || server.child.signalCode !== null) {
      throw new Error(`Server exited before startup: ${server.output()}`);
    }
    if (server.output().includes('TIS Paper Repository Server is running!')) return;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`Server startup timed out: ${server.output()}`);
}

function assertPrivate(value, allowTeacherPassword = false, location = '') {
  if (typeof value === 'string') {
    for (const secret of secrets) {
      if (secret === '123') assert.notEqual(value, secret, `Secret at ${location}`);
      else assert.ok(!value.includes(secret), `Secret at ${location}`);
    }
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, item] of Object.entries(value)) {
    assert.ok(!['passwordHash', 'alternatePasswordHash', 'plainTextNotice', 'encryptedPassword'].includes(key), `Private field ${key}`);
    const itemPath = location ? `${location}.${key}` : key;
    if (allowTeacherPassword && itemPath === 'teacher.password') continue;
    assert.notEqual(key, 'password', `Password field at ${itemPath}`);
    assertPrivate(item, allowTeacherPassword, itemPath);
  }
}

async function request(port, method, route, body, token, options = {}) {
  const response = await fetch(`http://127.0.0.1:${port}${route}`, {
    method,
    headers: {
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      ...(token ? { authorization: `Bearer ${token}` } : {})
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(10000)
  });
  const json = await response.json();
  const allowPassword = options.allowAdminDetails === true && method === 'GET' &&
    /^\/api\/admin\/teachers\/[^/]+\/details$/.test(route) && response.status === 200 && Boolean(token);
  if (options.allowAdminDetails) assert.ok(allowPassword, 'Password opt-in requires a successful authorized detail response');
  assertPrivate(json, allowPassword);
  return { status: response.status, json, headers: response.headers };
}

function readUsers(dirs) {
  return JSON.parse(fs.readFileSync(dirs.usersFile, 'utf8'));
}

if (require.main === module) {
test('legacy passwords, invitation gate, password changes and reset', { timeout: 90000 }, async t => {
  const hashOnly = legacyUser('hash-only', 'teacher', 'synthetic-hash-password');
  delete hashOnly.plainTextNotice;
  const dirs = fixture(t, [
    legacyUser('admin', 'admin', 'synthetic-admin-password'),
    legacyUser('teacher-one', 'teacher', sharedPassword),
    legacyUser('teacher-two', 'teacher', sharedPassword),
    hashOnly,
    legacyUser('pending', 'teacher', '123', {
      mustChangePassword: true, invitationTokenHash: sha256(invitationToken)
    }),
    legacyUser('student', 'student', 'synthetic-student-password'),
    legacyUser('conflict-plain', 'teacher', 'synthetic-plain-password', { passwordHash: sha256('synthetic-hash-password') }),
    legacyUser('conflict-hash', 'teacher', 'synthetic-plain-password', { passwordHash: sha256('synthetic-hash-password') }),
    legacyUser('stale', 'teacher', 'synthetic-stale-password', { passwordHash: scryptHash('synthetic-scrypt-password') })
  ]);
  const server = await startServer(t, dirs);
  await waitForServer(server);
  const api = (method, route, body, token, options) => request(server.port, method, route, body, token, options);
  const login = (id, password, invitation) => api('POST', '/api/auth/login', {
    email: `${id}@example.test`, password, ...(invitation ? { invitationToken: invitation } : {})
  });
  const user = id => readUsers(dirs).find(item => item.id === id);
  let adminToken;
  const detail = async (id, expected) => {
    const response = await api('GET', `/api/admin/teachers/${id}/details`, undefined, adminToken, { allowAdminDetails: true });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.json.teacher.id, id);
    assert.equal(response.json.teacher.password, expected);
  };

  await t.test('startup migration removes plaintext and randomizes salts', () => {
    const migrated = readUsers(dirs);
    for (const item of migrated) assert.equal(Object.hasOwn(item, 'plainTextNotice'), false);
    for (const password of [sharedPassword, 'synthetic-plain-password', 'synthetic-admin-password']) {
      assert.equal(JSON.stringify(migrated).includes(password), false);
    }
    for (const id of ['admin', 'teacher-one', 'teacher-two', 'pending', 'student']) {
      assert.match(user(id).passwordHash, /^scrypt\$[a-f0-9]{32}\$[a-f0-9]{64}$/);
    }
    assert.notEqual(user('teacher-one').passwordHash.split('$')[1], user('teacher-two').passwordHash.split('$')[1]);
    assert.match(user('hash-only').passwordHash, /^scrypt-sha256\$[a-f0-9]{32}\$[a-f0-9]{64}$/);
    for (const id of ['conflict-plain', 'conflict-hash']) {
      assert.match(user(id).passwordHash, /^scrypt\$[a-f0-9]{32}\$[a-f0-9]{64}$/);
      assert.match(user(id).alternatePasswordHash, /^scrypt-sha256\$[a-f0-9]{32}\$[a-f0-9]{64}$/);
      assert.equal(Object.hasOwn(user(id), 'encryptedPassword'), false);
    }
    assert.ok(user('teacher-one').encryptedPassword);
    for (const id of ['hash-only', 'stale']) assert.equal(Object.hasOwn(user(id), 'encryptedPassword'), false);
  });

  await t.test('admin details are restricted and legacy availability is accurate before login', async () => {
    const admin = await login('admin', 'synthetic-admin-password');
    assert.equal(admin.status, 200);
    adminToken = admin.json.token;
    const teacher = await login('teacher-two', sharedPassword);
    const student = await login('student', 'synthetic-student-password');
    assert.equal(teacher.status, 200);
    assert.equal(student.status, 200);
    const route = '/api/admin/teachers/teacher-one/details';
    assert.equal((await api('GET', route)).status, 401);
    assert.equal((await api('GET', route, undefined, teacher.json.token)).status, 403);
    assert.equal((await api('GET', route, undefined, student.json.token)).status, 403);
    const list = await api('GET', '/api/admin/teachers', undefined, adminToken);
    assert.equal(list.status, 200);
    assert.ok(list.json.teachers.some(item => item.id === 'pending'));
    await detail('teacher-one', sharedPassword);
    await detail('pending', '123');
    for (const id of ['hash-only', 'conflict-plain', 'conflict-hash', 'stale']) await detail(id, null);
  });

  await t.test('conflicting legacy passwords are preserved until the next sign-in', async () => {
    assert.equal((await login('conflict-plain', 'incorrect-password')).status, 401);
    assert.ok(user('conflict-plain').alternatePasswordHash);
    await detail('conflict-plain', null);
    assert.equal((await login('conflict-plain', 'synthetic-plain-password')).status, 200);
    await detail('conflict-plain', 'synthetic-plain-password');
    assert.equal(Object.hasOwn(user('conflict-plain'), 'alternatePasswordHash'), false);
    assert.equal((await login('conflict-plain', 'synthetic-hash-password')).status, 401);
    assert.equal((await login('conflict-hash', 'synthetic-hash-password')).status, 200);
    await detail('conflict-hash', 'synthetic-hash-password');
    assert.equal(Object.hasOwn(user('conflict-hash'), 'alternatePasswordHash'), false);
    assert.equal((await login('conflict-hash', 'synthetic-plain-password')).status, 401);
  });

  await t.test('legacy authentication and hash-only upgrade', async () => {
    assert.equal((await login('teacher-one', 'incorrect-password')).status, 401);
    assert.equal((await login('missing', sharedPassword)).status, 401);
    assert.equal((await login('teacher-one', sharedPassword)).status, 200);
    assert.equal((await login('teacher-two', sharedPassword)).status, 200);
    assert.equal((await login('student', 'synthetic-student-password')).status, 200);
    const oldHash = user('hash-only').passwordHash;
    assert.equal((await login('hash-only', 'incorrect-password')).status, 401);
    assert.equal(user('hash-only').passwordHash, oldHash);
    await detail('hash-only', null);
    assert.equal((await login('hash-only', 'synthetic-hash-password')).status, 200);
    assert.match(user('hash-only').passwordHash, /^scrypt\$[a-f0-9]{32}\$[a-f0-9]{64}$/);
    await detail('hash-only', 'synthetic-hash-password');
    assert.equal((await login('stale', 'synthetic-stale-password')).status, 401);
    await detail('stale', null);
    assert.equal((await login('stale', 'synthetic-scrypt-password')).status, 200);
    await detail('stale', 'synthetic-scrypt-password');
  });

  let pendingToken;
  await t.test('registration stores only a protected password when email is unavailable', async () => {
    const registered = await api('POST', '/api/admin/teachers', {
      username: 'registered', name: 'Synthetic Registered', email: 'registered@example.test', assignedSubjects: ['Biology']
    }, adminToken);
    assert.equal(registered.status, 201);
    assert.equal(registered.json.notificationStatus, 'not_configured');
    const created = user(registered.json.teacher.id);
    assert.match(created.passwordHash, /^scrypt\$[a-f0-9]{32}\$[a-f0-9]{64}$/);
    assert.equal(Object.hasOwn(created, 'plainTextNotice'), false);
    assert.equal(created.mustChangePassword, true);
    await detail(created.id, '123');
    assert.equal((await login('registered', '123')).status, 401);
    const originalInvitation = created.invitationTokenHash;
    const resend = await api('POST', `/api/admin/teachers/${created.id}/invitation`, undefined, adminToken);
    assert.equal(resend.status, 200);
    assert.equal(resend.json.notificationStatus, 'not_configured');
    assert.notEqual(user(created.id).invitationTokenHash, originalInvitation);
  });

  await t.test('pending invitation requires token and gates other APIs until password change', async () => {
    assert.equal((await login('pending', '123')).status, 401);
    assert.equal((await login('pending', '123', 'b'.repeat(64))).status, 401);
    assert.equal((await login('pending', 'wrong', invitationToken)).status, 401);
    const pending = await login('pending', '123', invitationToken);
    assert.equal(pending.status, 200);
    assert.equal(pending.json.user.mustChangePassword, true);
    pendingToken = pending.json.token;
    assert.equal((await api('GET', '/api/auth/me', undefined, pendingToken)).status, 200);
    assert.equal((await api('GET', '/api/admin/teachers', undefined, pendingToken)).status, 403);
    assert.equal((await api('PUT', '/api/auth/password', { currentPassword: '123', newPassword: 'short' }, pendingToken)).status, 400);
    assert.equal((await api('PUT', '/api/admin/teachers/pending', { password: 'synthetic-reset' }, adminToken)).status, 400);
    const changed = await api('PUT', '/api/auth/password', { currentPassword: '123', newPassword: 'pending-new-password' }, pendingToken);
    assert.equal(changed.status, 200);
    assert.equal(changed.json.user.mustChangePassword, false);
    await detail('pending', 'pending-new-password');
    assert.equal(Object.hasOwn(user('pending'), 'invitationTokenHash'), false);
    assert.equal((await login('pending', '123', invitationToken)).status, 401);
    assert.equal((await login('pending', 'pending-new-password')).status, 200);
  });

  let currentToken;
  await t.test('normal password change enforces minimum and revokes other sessions', async () => {
    const first = await login('teacher-one', sharedPassword);
    const second = await login('teacher-one', sharedPassword);
    assert.equal(first.status, 200);
    assert.equal(second.status, 200);
    currentToken = first.json.token;
    assert.equal((await api('PUT', '/api/auth/password', { currentPassword: sharedPassword, newPassword: 'short' }, currentToken)).status, 400);
    assert.equal((await api('GET', '/api/auth/me', undefined, second.json.token)).status, 200);
    assert.equal((await api('PUT', '/api/auth/password', { currentPassword: sharedPassword, newPassword: 'teacher-new-password' }, currentToken)).status, 200);
    await detail('teacher-one', 'teacher-new-password');
    assert.equal((await api('GET', '/api/auth/me', undefined, currentToken)).status, 200);
    assert.equal((await api('GET', '/api/auth/me', undefined, second.json.token)).status, 401);
    assert.equal((await login('teacher-one', sharedPassword)).status, 401);
    assert.equal((await login('teacher-one', 'teacher-new-password')).status, 200);
  });

  await t.test('admin reset enforces minimum and revokes teacher sessions', async () => {
    const extra = await login('teacher-one', 'teacher-new-password');
    assert.equal(extra.status, 200);
    assert.equal((await api('PUT', '/api/admin/teachers/teacher-one', { password: 'short' }, adminToken)).status, 400);
    assert.equal((await api('GET', '/api/auth/me', undefined, currentToken)).status, 200);
    assert.equal((await api('PUT', '/api/admin/teachers/teacher-one', { password: 'synthetic-reset-password' }, adminToken)).status, 200);
    await detail('teacher-one', 'synthetic-reset-password');
    assert.equal((await api('GET', '/api/auth/me', undefined, currentToken)).status, 401);
    assert.equal((await api('GET', '/api/auth/me', undefined, extra.json.token)).status, 401);
    assert.equal((await login('teacher-one', 'teacher-new-password')).status, 401);
    assert.equal((await login('teacher-one', 'synthetic-reset-password')).status, 200);
  });
});

test('invalid encryption keys and ciphertext abort without rewriting users', { timeout: 30000 }, async t => {
  for (const [name, environment, tampered] of [
    ['missing production key', { NODE_ENV: 'production', PASSWORD_ENCRYPTION_KEY: '' }, ''],
    ['invalid production key', { NODE_ENV: 'production', PASSWORD_ENCRYPTION_KEY: 'invalid' }, ''],
    ['wrong key', { PASSWORD_ENCRYPTION_KEY: Buffer.alloc(32, 8).toString('base64') }, ''],
    ['tampered ciphertext', {}, 'tag'],
    ['ciphertext from another account', {}, 'account']
  ]) {
    await t.test(name, async t => {
      let encryptedPassword = encryptFixture('synthetic-scrypt-password', tampered === 'account' ? 'another-account' : 'encrypted');
      if (tampered === 'tag') {
        const parts = encryptedPassword.split('$');
        parts[2] = `${parts[2][0] === '0' ? '1' : '0'}${parts[2].slice(1)}`;
        encryptedPassword = parts.join('$');
      }
      const dirs = fixture(t, [
        legacyUser('valid-first', 'teacher', 'synthetic-plain-password'),
        legacyUser('encrypted', 'teacher', 'synthetic-scrypt-password', { encryptedPassword })
      ]);
      const original = fs.readFileSync(dirs.usersFile);
      const server = await startServer(t, dirs, environment);
      const result = await server.exited;
      assert.notEqual(result.code, 0);
      assert.match(server.output(), name.includes('production key') ? /PASSWORD_ENCRYPTION_KEY must be/ : /Unable to decrypt a stored teacher password/);
      assert.deepEqual(fs.readFileSync(dirs.usersFile), original);
      assert.deepEqual(fs.readdirSync(dirs.data).filter(file => file.startsWith('users.json.')), []);
    });
  }
});

test('a missing local key does not replace the key for encrypted accounts', { timeout: 30000 }, async t => {
  const dirs = fixture(t, [
    legacyUser('encrypted', 'teacher', 'synthetic-scrypt-password', {
      encryptedPassword: encryptFixture('synthetic-scrypt-password', 'encrypted')
    })
  ]);
  const original = fs.readFileSync(dirs.usersFile);
  const serverCopy = path.join(dirs.root, 'server.js');
  fs.copyFileSync(path.join(__dirname, 'server.js'), serverCopy);
  const server = await startServer(t, dirs, {
    PASSWORD_ENCRYPTION_KEY: '', NODE_PATH: path.join(__dirname, 'node_modules')
  }, serverCopy);
  const result = await server.exited;
  assert.notEqual(result.code, 0);
  assert.match(server.output(), /local password encryption key is missing/);
  assert.deepEqual(fs.readFileSync(dirs.usersFile), original);
  assert.equal(fs.existsSync(path.join(dirs.root, '.password-key')), false);
});

test('production bootstrap requires a strong administrator password', { timeout: 30000 }, async t => {
  await t.test('rejects a short password without creating an account', async t => {
    const dirs = fixture(t, []);
    fs.unlinkSync(dirs.usersFile);
    const server = await startServer(t, dirs, { NODE_ENV: 'production', ADMIN_EMAIL: 'admin@example.test', ADMIN_PASSWORD: 'short' });
    const result = await server.exited;
    assert.notEqual(result.code, 0);
    assert.equal(fs.existsSync(dirs.usersFile), false);
  });
  await t.test('stores only a protected administrator password', async t => {
    const dirs = fixture(t, []);
    fs.unlinkSync(dirs.usersFile);
    const server = await startServer(t, dirs, { NODE_ENV: 'production', ADMIN_EMAIL: 'admin@example.test', ADMIN_PASSWORD: 'synthetic-admin-password' });
    await waitForServer(server);
    const admin = readUsers(dirs)[0];
    assert.match(admin.passwordHash, /^scrypt\$[a-f0-9]{32}\$[a-f0-9]{64}$/);
    assert.equal(Object.hasOwn(admin, 'plainTextNotice'), false);
    assert.equal((await request(server.port, 'POST', '/api/auth/login', {
      email: 'admin@example.test', password: 'synthetic-admin-password'
    })).status, 200);
  });
});

test('invalid legacy password records abort migration without rewriting users', { timeout: 30000 }, async t => {
  const dirs = fixture(t, [
    legacyUser('valid-first', 'teacher', 'synthetic-valid-password'),
    legacyUser('invalid', 'teacher', 'synthetic-password', { passwordHash: 'invalid-hash' })
  ]);
  const original = fs.readFileSync(dirs.usersFile);
  const server = await startServer(t, dirs);
  const result = await server.exited;
  assert.notEqual(result.code, 0);
  assert.match(server.output(), /Password record for account invalid is invalid; migration stopped/);
  assert.deepEqual(fs.readFileSync(dirs.usersFile), original);
  assert.deepEqual(fs.readdirSync(dirs.data).filter(name => name.startsWith('users.json.')), []);
});
}
