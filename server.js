const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const nodemailer = require('nodemailer');
require('dotenv').config({ path: path.join(__dirname, '.env'), quiet: true });

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Directories (DATA_DIR / UPLOADS_DIR can point to a persistent volume in production)
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(__dirname, 'data');
const UPLOADS_DIR = process.env.UPLOADS_DIR ? path.resolve(process.env.UPLOADS_DIR) : path.join(__dirname, 'uploads');
const PAPERS_FILE = path.join(DATA_DIR, 'papers.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const CLASSES_FILE = path.join(DATA_DIR, 'classes.json');

// Ensure directories exist before writing any files into them
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(PAPERS_FILE)) fs.writeFileSync(PAPERS_FILE, '[]', 'utf8');

const DELETION_REQUESTS_FILE = path.join(DATA_DIR, 'deletion_requests.json');
if (!fs.existsSync(DELETION_REQUESTS_FILE)) fs.writeFileSync(DELETION_REQUESTS_FILE, '[]', 'utf8');

const SCRYPT_OPTIONS = { N: 32768, r: 8, p: 3, maxmem: 64 * 1024 * 1024 };

function hashToken(value) {
  return crypto.createHash('sha256').update(value.trim()).digest('hex');
}

function hashPassword(password, legacyHash = false) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password.trim(), salt, 32, SCRYPT_OPTIONS);
  return `${legacyHash ? 'scrypt-sha256' : 'scrypt'}$${salt.toString('hex')}$${derived.toString('hex')}`;
}

function verifyPassword(password, storedHash) {
  const parts = typeof storedHash === 'string' ? storedHash.split('$') : [];
  if (parts.length !== 3 || !['scrypt', 'scrypt-sha256'].includes(parts[0]) ||
      !/^[a-f0-9]{32}$/.test(parts[1]) || !/^[a-f0-9]{64}$/.test(parts[2])) return false;
  const input = parts[0] === 'scrypt-sha256' ? hashToken(password) : password.trim();
  const expected = Buffer.from(parts[2], 'hex');
  const actual = crypto.scryptSync(input, Buffer.from(parts[1], 'hex'), expected.length, SCRYPT_OPTIONS);
  return crypto.timingSafeEqual(actual, expected);
}

function loadPasswordEncryptionKey() {
  let encoded = (process.env.PASSWORD_ENCRYPTION_KEY || '').trim();
  if (!encoded && process.env.NODE_ENV !== 'production') {
    const keyFile = path.join(__dirname, '.password-key');
    if (!fs.existsSync(keyFile)) {
      if (fs.existsSync(USERS_FILE)) {
        const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        if (!Array.isArray(users)) throw new Error('User data must be an array.');
        if (users.some(user => user.encryptedPassword)) {
          throw new Error('The local password encryption key is missing. Restore the original key.');
        }
      }
      fs.writeFileSync(keyFile, crypto.randomBytes(32).toString('base64'), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    }
    encoded = fs.readFileSync(keyFile, 'utf8').trim();
  }
  if (!/^[A-Za-z0-9+/]{43}=$/.test(encoded)) {
    throw new Error('PASSWORD_ENCRYPTION_KEY must be a base64-encoded 32-byte key.');
  }
  const key = Buffer.from(encoded, 'base64');
  if (key.length !== 32 || key.toString('base64') !== encoded) {
    throw new Error('PASSWORD_ENCRYPTION_KEY must be a base64-encoded 32-byte key.');
  }
  return key;
}

function encryptTeacherPassword(password, userId) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', passwordEncryptionKey, iv);
  cipher.setAAD(Buffer.from(userId));
  const ciphertext = Buffer.concat([cipher.update(password.trim(), 'utf8'), cipher.final()]);
  return `v1$${iv.toString('hex')}$${cipher.getAuthTag().toString('hex')}$${ciphertext.toString('base64')}`;
}

function decryptTeacherPassword(value, userId) {
  const parts = typeof value === 'string' ? value.split('$') : [];
  if (parts.length !== 4 || parts[0] !== 'v1' || !/^[a-f0-9]{24}$/.test(parts[1]) ||
      !/^[a-f0-9]{32}$/.test(parts[2]) || !/^[A-Za-z0-9+/]+={0,2}$/.test(parts[3])) {
    throw new Error('Stored teacher password is invalid.');
  }
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', passwordEncryptionKey, Buffer.from(parts[1], 'hex'));
    decipher.setAAD(Buffer.from(userId));
    decipher.setAuthTag(Buffer.from(parts[2], 'hex'));
    return Buffer.concat([decipher.update(Buffer.from(parts[3], 'base64')), decipher.final()]).toString('utf8');
  } catch {
    throw new Error('Unable to decrypt a stored teacher password. Check the encryption key.');
  }
}

function writeUsers(users) {
  const temporaryPath = `${USERS_FILE}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  let file;
  let created = false;
  try {
    file = fs.openSync(temporaryPath, 'wx', 0o600);
    created = true;
    fs.writeFileSync(file, JSON.stringify(users, null, 2), 'utf8');
    fs.closeSync(file);
    file = undefined;
    fs.renameSync(temporaryPath, USERS_FILE);
    created = false;
  } finally {
    if (file !== undefined) fs.closeSync(file);
    if (created) fs.unlinkSync(temporaryPath);
  }
}

function migratePasswords() {
  const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  if (!Array.isArray(users)) throw new Error('User data must be an array.');
  let changed = false;
  for (const user of users) {
    const protectedHash = /^(scrypt|scrypt-sha256)\$[a-f0-9]{32}\$[a-f0-9]{64}$/.test(user.passwordHash || '');
    if (user.role === 'teacher') {
      if (Object.hasOwn(user, 'encryptedPassword')) {
        decryptTeacherPassword(user.encryptedPassword, user.id);
      } else if (typeof user.plainTextNotice === 'string' && user.plainTextNotice.trim() &&
          (protectedHash ? verifyPassword(user.plainTextNotice, user.passwordHash) :
           !user.passwordHash || hashToken(user.plainTextNotice) === user.passwordHash)) {
        user.encryptedPassword = encryptTeacherPassword(user.plainTextNotice, user.id);
        changed = true;
      }
    }
    if (protectedHash) {
      if (Object.hasOwn(user, 'plainTextNotice')) {
        delete user.plainTextNotice;
        changed = true;
      }
      continue;
    }
    const legacyHash = user.passwordHash;
    const plain = user.plainTextNotice;
    if (typeof plain === 'string' && plain.trim()) {
      if (legacyHash && !/^[a-f0-9]{64}$/.test(legacyHash)) {
        throw new Error(`Password record for account ${user.id} is invalid; migration stopped.`);
      }
      user.passwordHash = hashPassword(plain);
      // Older records could authenticate against either conflicting value.
      if (legacyHash && hashToken(plain) !== legacyHash) {
        user.alternatePasswordHash = hashPassword(legacyHash, true);
      }
    } else if (typeof legacyHash === 'string' && /^[a-f0-9]{64}$/.test(legacyHash)) {
      user.passwordHash = hashPassword(legacyHash, true);
    } else {
      throw new Error(`Password record for account ${user.id} is invalid; migration stopped.`);
    }
    delete user.plainTextNotice;
    changed = true;
  }
  if (changed) writeUsers(users);
}

function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function isValidEmail(email) {
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

async function sendRegistrationEmail(teacher, invitationToken) {
  const user = (process.env.GMAIL_USER || '').trim();
  const pass = (process.env.GMAIL_APP_PASSWORD || '').trim();
  const baseUrl = (process.env.APP_URL || (process.env.NODE_ENV === 'production' ? '' : `http://localhost:${PORT}`)).trim();
  let loginUrl;
  try {
    loginUrl = new URL(baseUrl);
    if (!['http:', 'https:'].includes(loginUrl.protocol) || loginUrl.username || loginUrl.password ||
        (process.env.NODE_ENV === 'production' && loginUrl.protocol !== 'https:')) return 'not_configured';
    loginUrl.hash = `invite=${invitationToken}`;
  } catch {
    return 'not_configured';
  }
  if (!user || !pass) return 'not_configured';

  const transport = nodemailer.createTransport({
    service: 'gmail',
    auth: { user, pass },
    connectionTimeout: 15000,
    greetingTimeout: 15000,
    socketTimeout: 20000
  });

  try {
    const safeName = escapeHtml(teacher.name);
    const safeEmail = escapeHtml(teacher.email);
    const safeUrl = escapeHtml(loginUrl.href);
    const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Cambridge Assessment account</title></head>
<body style="margin:0;padding:0;background-color:#f1f6ed;font-family:Arial,Helvetica,sans-serif;color:#243527;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#f1f6ed;">
    <tr><td align="center" style="padding:32px 16px;">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;background-color:#ffffff;border:1px solid #dfebd7;border-radius:16px;overflow:hidden;">
        <tr><td style="background-color:#3a6b28;padding:28px 32px;color:#ffffff;">
          <table role="presentation" cellspacing="0" cellpadding="0" style="background-color:#ffffff;border-radius:8px;">
            <tr><td style="padding:10px 14px;"><img src="cid:cambridge-assessment-logo" width="270" alt="Cambridge Assessment International Education" style="display:block;width:270px;max-width:100%;height:auto;border:0;"></td></tr>
          </table>
          <p style="margin:12px 0 0;color:#d4ebc8;font-size:11px;font-weight:700;letter-spacing:1.6px;text-transform:uppercase;">Paper Repository</p>
        </td></tr>
        <tr><td style="padding:32px;">
          <p style="margin:0 0 10px;color:#5da440;font-size:11px;font-weight:700;letter-spacing:1.4px;text-transform:uppercase;">Your account is ready</p>
          <h1 style="margin:0 0 18px;color:#243527;font-size:26px;line-height:1.2;">Welcome, ${safeName}</h1>
          <p style="margin:0 0 22px;color:#506252;font-size:15px;line-height:1.65;">Your Cambridge Assessment Paper Repository account has been created. Use the private link below to sign in and set your password.</p>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#f4f9f0;border:1px solid #d6e8cb;border-radius:10px;">
            <tr><td style="padding:19px 20px;">
              <p style="margin:0 0 6px;color:#61765f;font-size:11px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;">Email address</p>
              <p style="margin:0 0 16px;color:#243527;font-size:15px;word-break:break-all;">${safeEmail}</p>
              <p style="margin:0 0 6px;color:#61765f;font-size:11px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;">Temporary password</p>
              <p style="margin:0;color:#2a4e1d;font-size:22px;font-weight:700;letter-spacing:2px;">123</p>
            </td></tr>
          </table>
          <p style="margin:24px 0;"><a href="${safeUrl}" style="display:inline-block;background-color:#4a8833;color:#ffffff;text-decoration:none;font-size:14px;font-weight:700;padding:14px 23px;border-radius:8px;">Sign in &amp; set password</a></p>
          <p style="margin:0;color:#506252;font-size:14px;line-height:1.6;">On your first sign-in, you must change your temporary password.</p>
        </td></tr>
        <tr><td style="background-color:#f8fbf6;border-top:1px solid #e3eddd;padding:20px 32px;color:#71836d;font-size:12px;line-height:1.5;">
          Cambridge Assessment &bull; Paper Repository<br>Need help? Contact your administrator.
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;
    await transport.sendMail({
      from: { name: 'Cambridge Assessment', address: user },
      to: teacher.email,
      subject: 'Welcome to Cambridge Assessment Paper Repository',
      text: `Hello ${teacher.name},\n\nYour Cambridge Assessment Paper Repository account has been created.\n\nEmail address: ${teacher.email}\nTemporary password: 123\n\nTo sign in and set your password, view this email in an app that displays the sign-in button. You must choose a new password when you first sign in.\n\nCambridge Assessment Paper Repository`,
      html,
      attachments: [{
        filename: 'cambridge-assessment.png',
        path: path.join(__dirname, 'public', 'images', 'cambridge-email-logo.png'),
        cid: 'cambridge-assessment-logo',
        contentDisposition: 'inline'
      }]
    });
    return 'sent';
  } catch (err) {
    console.error('Registration email could not be sent:', err.code || 'MAIL_ERROR');
    return 'failed';
  } finally {
    transport.close();
  }
}

const passwordEncryptionKey = loadPasswordEncryptionKey();

// Ensure default users if empty
if (!fs.existsSync(USERS_FILE)) {
  if (process.env.NODE_ENV === 'production') {
    const adminUsername = (process.env.ADMIN_USERNAME || 'admin').trim().toLowerCase();
    const adminEmail = normalizeEmail(process.env.ADMIN_EMAIL);
    const adminPassword = (process.env.ADMIN_PASSWORD || '').trim();

    if (!isValidEmail(adminEmail) || adminPassword.length < 8) {
      console.error('A valid ADMIN_EMAIL and an ADMIN_PASSWORD of at least 8 characters are required for the first production start.');
      process.exit(1);
    }

    const productionAdmin = [{
      id: 'admin-1',
      username: adminUsername,
      email: adminEmail,
      passwordHash: hashPassword(adminPassword),
      role: 'admin',
      name: (process.env.ADMIN_NAME || 'Administrator').trim(),
      assignedSubjects: ['Biology', 'Chemistry'],
      createdAt: new Date().toISOString()
    }];

    fs.writeFileSync(USERS_FILE, JSON.stringify(productionAdmin, null, 2), 'utf8');
    console.log(`Created initial administrator account "${adminUsername}" from environment variables.`);
  } else {
    const defaultUsers = [
      {
        id: 'admin-1',
        username: 'admin',
        email: 'admin@example.test',
        passwordHash: hashPassword('admin123'),
        role: 'admin',
        name: 'Head of Science / Admin',
        assignedSubjects: ['Biology', 'Chemistry'],
        createdAt: new Date().toISOString()
      },
      {
        id: 'teacher-bio-1',
        username: 'bio_teacher',
        email: 'biology@example.test',
        passwordHash: hashPassword('teacher123'),
        encryptedPassword: encryptTeacherPassword('teacher123', 'teacher-bio-1'),
        role: 'teacher',
        name: 'Sarah Jenkins (Biology)',
        assignedSubjects: ['Biology'],
        createdAt: new Date().toISOString()
      },
      {
        id: 'teacher-chem-1',
        username: 'chem_teacher',
        email: 'chemistry@example.test',
        passwordHash: hashPassword('teacher123'),
        encryptedPassword: encryptTeacherPassword('teacher123', 'teacher-chem-1'),
        role: 'teacher',
        name: 'David Alistair (Chemistry)',
        assignedSubjects: ['Chemistry'],
        createdAt: new Date().toISOString()
      },
      {
        id: 'student-1',
        username: 'student',
        email: 'student@example.test',
        passwordHash: hashPassword('student123'),
        role: 'student',
        name: 'Student Member',
        assignedSubjects: ['Biology', 'Chemistry'],
        createdAt: new Date().toISOString()
      }
    ];
    fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2), 'utf8');
  }
}

migratePasswords();

// In-memory active sessions token -> user
const sessions = new Map();

// Helpers for data read/write
function readData(filePath, defaultVal = []) {
  try {
    if (!fs.existsSync(filePath)) return defaultVal;
    const content = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(content || '[]');
  } catch (err) {
    console.error(`Error reading ${filePath}:`, err);
    return defaultVal;
  }
}

function writeData(filePath, data) {
  try {
    if (filePath === USERS_FILE) writeUsers(data);
    else fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error(`Error writing ${filePath}:`, err);
    return false;
  }
}

// Authentication Middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ error: 'Authorization token required' });
  }

  const token = authHeader.replace(/^Bearer\s+/, '');
  const user = sessions.get(token);

  if (!user) {
    return res.status(401).json({ error: 'Session expired or invalid. Please login again.' });
  }

  const passwordChangeRoute =
    (req.method === 'GET' && req.path === '/api/auth/me') ||
    (req.method === 'PUT' && req.path === '/api/auth/password') ||
    (req.method === 'POST' && req.path === '/api/auth/logout');
  if (user.mustChangePassword && !passwordChangeRoute) {
    return res.status(403).json({ error: 'You must change your temporary password first.' });
  }

  req.user = user;
  next();
}

// Admin only middleware
function adminMiddleware(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Permission denied. Administrator access required.' });
  }
  next();
}

// Multer Storage Configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOADS_DIR);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, 'paper-' + uniqueSuffix + ext);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
  fileFilter: (req, file, cb) => cb(null, true)
});

// Allowed options
const DEFAULT_CLASSES = [
  'Year 7', 'Year 8', 'Year 9', 'Year 10', 'Year 11', 'Year 12', 'Year 13'
];
const VALID_SUBJECTS = ['Biology', 'Chemistry'];
const VALID_TERMS = ['Term 1', 'Term 2', 'Term 3'];

if (!fs.existsSync(CLASSES_FILE)) {
  fs.writeFileSync(CLASSES_FILE, JSON.stringify(DEFAULT_CLASSES, null, 2), 'utf8');
}

function readClasses() {
  const stored = readData(CLASSES_FILE, []);
  const list = Array.isArray(stored) ? stored.filter(c => typeof c === 'string' && c.trim()) : [];
  return list.length ? list : DEFAULT_CLASSES.slice();
}

// ==================== AUTH ROUTES ====================

app.post('/api/auth/login', (req, res) => {
  const email = normalizeEmail(req.body.email);
  const { password, invitationToken } = req.body;
  if (!isValidEmail(email) || typeof password !== 'string' || !password.trim()) {
    return res.status(400).json({ error: 'A valid email and password are required' });
  }

  const users = readData(USERS_FILE, []);
  const matchingUsers = users.filter(u => normalizeEmail(u.email) === email);
  const matched = matchingUsers.length === 1 ? matchingUsers[0] : null;
  const invalidCredentials = !matched || (!verifyPassword(password, matched.passwordHash) &&
    !verifyPassword(password, matched.alternatePasswordHash));
  const invalidInvitation = matched && matched.mustChangePassword && (
    typeof invitationToken !== 'string' || !/^[a-f0-9]{64}$/.test(invitationToken) ||
    !matched.invitationTokenHash || hashToken(invitationToken) !== matched.invitationTokenHash
  );

  if (invalidCredentials || invalidInvitation) {
    return res.status(401).json({ error: 'Invalid email, password, or invitation link.' });
  }

  let securityUpdate = false;
  if (matched.passwordHash.startsWith('scrypt-sha256$') || matched.alternatePasswordHash) {
    matched.passwordHash = hashPassword(password);
    delete matched.alternatePasswordHash;
    securityUpdate = true;
  }
  if (matched.role === 'teacher' && (!matched.encryptedPassword || securityUpdate)) {
    matched.encryptedPassword = encryptTeacherPassword(password, matched.id);
    securityUpdate = true;
  }
  if (securityUpdate && !writeData(USERS_FILE, users)) {
    return res.status(500).json({ error: 'Could not update account security.' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  const userSession = {
    id: matched.id,
    username: matched.username,
    email: normalizeEmail(matched.email),
    name: matched.name,
    role: matched.role,
    assignedSubjects: matched.assignedSubjects || (matched.role === 'admin' ? ['Biology', 'Chemistry'] : ['Biology']),
    mustChangePassword: Boolean(matched.mustChangePassword)
  };

  sessions.set(token, userSession);

  res.json({
    message: 'Login successful',
    token,
    user: userSession
  });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  // Return fresh info from database
  const users = readData(USERS_FILE, []);
  const fresh = users.find(u => u.id === req.user.id);
  if (fresh) {
    req.user.assignedSubjects = fresh.assignedSubjects || [];
    req.user.name = fresh.name;
    req.user.email = normalizeEmail(fresh.email);
    req.user.role = fresh.role;
    req.user.mustChangePassword = Boolean(fresh.mustChangePassword);
  }
  res.json({ user: req.user });
});

// Self-service password change for the signed-in user
app.put('/api/auth/password', authMiddleware, (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (typeof currentPassword !== 'string' || typeof newPassword !== 'string' || !currentPassword.trim() || !newPassword.trim()) {
    return res.status(400).json({ error: 'Current and new password are required.' });
  }

  const cleanNew = newPassword.trim();
  const users = readData(USERS_FILE, []);
  const user = users.find(u => u.id === req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }

  const firstChange = Boolean(user.mustChangePassword);
  if (cleanNew.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  }
  if (firstChange && cleanNew === currentPassword.trim()) {
    return res.status(400).json({ error: 'Choose a different password from your temporary password.' });
  }

  if (!verifyPassword(currentPassword, user.passwordHash)) {
    return res.status(400).json({ error: 'Current password is incorrect.' });
  }

  user.passwordHash = hashPassword(cleanNew);
  if (user.role === 'teacher') user.encryptedPassword = encryptTeacherPassword(cleanNew, user.id);
  delete user.alternatePasswordHash;
  user.mustChangePassword = false;
  delete user.invitationTokenHash;
  if (!writeData(USERS_FILE, users)) {
    return res.status(500).json({ error: 'Could not save your new password.' });
  }

  for (const [token, sess] of sessions.entries()) {
    if (sess.id === user.id) {
      if (sess !== req.user) sessions.delete(token);
      else sess.mustChangePassword = false;
    }
  }

  res.json({
    message: 'Password updated successfully.',
    user: req.user
  });
});

// Self-service profile update (name only — username is admin-managed)
app.put('/api/auth/profile', authMiddleware, (req, res) => {
  const cleanName = String(req.body.name || '').trim();

  if (!cleanName) {
    return res.status(400).json({ error: 'Full name is required.' });
  }
  if (cleanName.length > 80) {
    return res.status(400).json({ error: 'Full name must be 80 characters or fewer.' });
  }

  const users = readData(USERS_FILE, []);
  const user = users.find(u => u.id === req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }

  user.name = cleanName;
  writeData(USERS_FILE, users);

  for (const sess of sessions.values()) {
    if (sess.id === user.id) sess.name = user.name;
  }

  req.user.name = user.name;

  res.json({
    message: 'Profile updated successfully.',
    user: req.user
  });
});

app.post('/api/auth/logout', authMiddleware, (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader.replace(/^Bearer\s+/, '');
  sessions.delete(token);
  res.json({ message: 'Logged out successfully' });
});

// ==================== ADMIN: TEACHER MANAGEMENT ====================

// List teachers with uploaded papers count
app.get('/api/admin/teachers', authMiddleware, adminMiddleware, (req, res) => {
  const users = readData(USERS_FILE, []);
  const papers = readData(PAPERS_FILE, []);

  const teachers = users
    .filter(u => u.role === 'teacher')
    .map(u => ({
      id: u.id,
      username: u.username,
      name: u.name,
      email: u.email || '',
      phone: u.phone || '',
      role: u.role,
      assignedSubjects: u.assignedSubjects || [],
      mustChangePassword: Boolean(u.mustChangePassword),
      createdAt: u.createdAt,
      papersCount: papers.filter(p => p.uploadedByUsername === u.username || p.uploadedBy === u.name).length
    }));
  res.json({ teachers });
});

// View single teacher details including their uploaded papers
app.get('/api/admin/teachers/:id/details', authMiddleware, adminMiddleware, (req, res) => {
  const { id } = req.params;
  const users = readData(USERS_FILE, []);
  const papers = readData(PAPERS_FILE, []);

  const teacher = users.find(u => u.id === id && u.role === 'teacher');
  if (!teacher) {
    return res.status(404).json({ error: 'Teacher not found' });
  }

  const teacherPapers = papers.filter(p => p.uploadedByUsername === teacher.username || p.uploadedBy === teacher.name);
  let password = null;
  try {
    if (teacher.encryptedPassword) password = decryptTeacherPassword(teacher.encryptedPassword, teacher.id);
  } catch {
    return res.status(500).json({ error: 'Could not decrypt the teacher password. Check the encryption key.' });
  }

  res.set('Cache-Control', 'no-store');
  res.json({
    teacher: {
      id: teacher.id,
      username: teacher.username,
      name: teacher.name,
      email: teacher.email || '',
      phone: teacher.phone || '',
      role: teacher.role,
      assignedSubjects: teacher.assignedSubjects || [],
      password,
      createdAt: teacher.createdAt
    },
    papers: teacherPapers
  });
});

// Add new teacher with subject permissions (Default password: 123)
app.post('/api/admin/teachers', authMiddleware, adminMiddleware, async (req, res) => {
  const { username, name, assignedSubjects, email, phone } = req.body;

  if (!username || !name) {
    return res.status(400).json({ error: 'Username and full name are required.' });
  }

  const cleanEmail = normalizeEmail(email);
  const cleanPhone = typeof phone === 'string' ? phone.trim() : '';
  if (!isValidEmail(cleanEmail)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  if (cleanPhone && !/^[+()\d\s-]{7,20}$/.test(cleanPhone)) {
    return res.status(400).json({ error: 'Please enter a valid phone number.' });
  }

  if (!assignedSubjects || !Array.isArray(assignedSubjects) || assignedSubjects.length === 0) {
    return res.status(400).json({ error: 'Please assign at least one subject (Biology, Chemistry, or both).' });
  }

  // Validate subjects
  for (const s of assignedSubjects) {
    if (!VALID_SUBJECTS.includes(s)) {
      return res.status(400).json({ error: `Invalid subject: ${s}. Must be Biology or Chemistry.` });
    }
  }

  const users = readData(USERS_FILE, []);

  if (users.some(u => normalizeEmail(u.email) === cleanEmail)) {
    return res.status(400).json({ error: 'This email address is already in use.' });
  }

  // Check unique username
  const exists = users.some(u => u.username.toLowerCase() === username.trim().toLowerCase());
  if (exists) {
    return res.status(400).json({ error: `Username "${username}" already exists. Please pick another.` });
  }

  const invitationToken = crypto.randomBytes(32).toString('hex');
  const teacherId = 'teacher-' + crypto.randomUUID();
  const newTeacher = {
    id: teacherId,
    username: username.trim().toLowerCase(),
    passwordHash: hashPassword('123'),
    encryptedPassword: encryptTeacherPassword('123', teacherId),
    mustChangePassword: true,
    invitationTokenHash: hashToken(invitationToken),
    role: 'teacher',
    name: name.trim(),
    email: cleanEmail,
    phone: cleanPhone,
    assignedSubjects: assignedSubjects,
    createdAt: new Date().toISOString()
  };

  users.push(newTeacher);
  if (!writeData(USERS_FILE, users)) {
    return res.status(500).json({ error: 'Could not save the teacher account.' });
  }

  const notificationStatus = await sendRegistrationEmail(newTeacher, invitationToken);
  const message = notificationStatus === 'sent'
    ? (!process.env.APP_URL ? 'Invitation sent. The local login link only works on this computer.' : 'Teacher registered and invitation sent.')
    : notificationStatus === 'not_configured'
      ? 'Teacher registered, but Gmail or the secure login link is not configured. Resend the invitation after configuration.'
      : 'Teacher registered, but the invitation could not be sent. Please resend it.';

  res.status(201).json({
    message,
    notificationStatus,
    teacher: {
      id: newTeacher.id,
      username: newTeacher.username,
      name: newTeacher.name,
      email: newTeacher.email,
      phone: newTeacher.phone,
      role: newTeacher.role,
      assignedSubjects: newTeacher.assignedSubjects,
      createdAt: newTeacher.createdAt,
      papersCount: 0
    }
  });
});

app.post('/api/admin/teachers/:id/invitation', authMiddleware, adminMiddleware, async (req, res) => {
  const users = readData(USERS_FILE, []);
  const teacher = users.find(u => u.id === req.params.id && u.role === 'teacher');
  if (!teacher) return res.status(404).json({ error: 'Teacher not found.' });
  if (!teacher.mustChangePassword) return res.status(400).json({ error: 'This teacher has already set a password.' });

  const invitationToken = crypto.randomBytes(32).toString('hex');
  teacher.invitationTokenHash = hashToken(invitationToken);
  if (!writeData(USERS_FILE, users)) return res.status(500).json({ error: 'Could not save the invitation.' });
  for (const [token, session] of sessions.entries()) {
    if (session.id === teacher.id) sessions.delete(token);
  }

  const notificationStatus = await sendRegistrationEmail(teacher, invitationToken);
  const message = notificationStatus === 'sent'
    ? (!process.env.APP_URL ? 'Invitation sent. The local login link only works on this computer.' : 'Invitation sent.')
    : notificationStatus === 'not_configured'
      ? 'Gmail or the secure login link is not configured; the invitation was not sent.'
      : 'The invitation could not be sent.';
  res.json({ notificationStatus, message });
});

// Update teacher (subjects, name, username, password)
app.put('/api/admin/teachers/:id', authMiddleware, adminMiddleware, (req, res) => {
  const { id } = req.params;
  const { name, username, assignedSubjects, password, email, phone } = req.body;

  const users = readData(USERS_FILE, []);
  const teacher = users.find(u => u.id === id && u.role === 'teacher');

  if (!teacher) {
    return res.status(404).json({ error: 'Teacher not found.' });
  }

  if (name && name.trim()) teacher.name = name.trim();

  let invitationNeedsResending = false;
  if (email !== undefined) {
    const cleanEmail = normalizeEmail(email);
    if (!isValidEmail(cleanEmail)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    if (users.some(u => u.id !== id && normalizeEmail(u.email) === cleanEmail)) {
      return res.status(400).json({ error: 'This email address is already in use.' });
    }
    if (teacher.mustChangePassword && cleanEmail !== normalizeEmail(teacher.email)) {
      delete teacher.invitationTokenHash;
      invitationNeedsResending = true;
    }
    teacher.email = cleanEmail;
  }

  if (phone !== undefined) {
    const cleanPhone = typeof phone === 'string' ? phone.trim() : '';
    if (cleanPhone && !/^[+()\d\s-]{7,20}$/.test(cleanPhone)) {
      return res.status(400).json({ error: 'Please enter a valid phone number.' });
    }
    teacher.phone = cleanPhone;
  }
  if (username && username.trim()) {
    const cleanUsername = username.trim().toLowerCase();
    const clash = users.some(u => u.id !== id && u.username.toLowerCase() === cleanUsername);
    if (clash) {
      return res.status(400).json({ error: `Username "${cleanUsername}" is already taken.` });
    }
    teacher.username = cleanUsername;
  }

  if (assignedSubjects && Array.isArray(assignedSubjects) && assignedSubjects.length > 0) {
    teacher.assignedSubjects = assignedSubjects;
  }

  const resettingPassword = password !== undefined && password !== '';
  if (resettingPassword) {
    if (typeof password !== 'string' || password.trim().length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters.' });
    }
    if (teacher.mustChangePassword) {
      return res.status(400).json({ error: 'The teacher must set their password using the invitation first.' });
    }
    teacher.passwordHash = hashPassword(password);
    teacher.encryptedPassword = encryptTeacherPassword(password, teacher.id);
    delete teacher.alternatePasswordHash;
  }

  if (!writeData(USERS_FILE, users)) {
    return res.status(500).json({ error: 'Could not save the teacher account.' });
  }

  // Update in-memory sessions if teacher is currently logged in
  for (let [tok, sess] of sessions.entries()) {
    if (sess.id === id) {
      if (invitationNeedsResending || resettingPassword) {
        sessions.delete(tok);
      } else {
        sess.name = teacher.name;
        sess.username = teacher.username;
        sess.email = normalizeEmail(teacher.email);
        sess.assignedSubjects = teacher.assignedSubjects;
      }
    }
  }

  res.json({
    message: invitationNeedsResending ? 'Teacher updated. Resend the invitation to the new email address.' : 'Teacher details updated successfully.',
    teacher: {
      id: teacher.id,
      username: teacher.username,
      name: teacher.name,
      email: teacher.email || '',
      phone: teacher.phone || '',
      assignedSubjects: teacher.assignedSubjects
    }
  });
});

// Delete teacher
app.delete('/api/admin/teachers/:id', authMiddleware, adminMiddleware, (req, res) => {
  const { id } = req.params;
  let users = readData(USERS_FILE, []);
  const index = users.findIndex(u => u.id === id && u.role === 'teacher');

  if (index === -1) {
    return res.status(404).json({ error: 'Teacher not found.' });
  }

  const deleted = users.splice(index, 1)[0];
  writeData(USERS_FILE, users);

  // Invalidate any active session
  for (let [tok, sess] of sessions.entries()) {
    if (sess.id === id) sessions.delete(tok);
  }

  res.json({ message: `Teacher ${deleted.name} removed successfully.` });
});

// ==================== PAPERS ROUTES ====================

// Metadata options
app.get('/api/meta', authMiddleware, (req, res) => {
  let allowedSubjects = VALID_SUBJECTS;
  if (req.user.role !== 'admin' && req.user.assignedSubjects) {
    allowedSubjects = req.user.assignedSubjects;
  }

  res.json({
    classes: readClasses(),
    subjects: allowedSubjects,
    terms: VALID_TERMS
  });
});

// List classes/years
app.get('/api/classes', authMiddleware, (req, res) => {
  res.json({ classes: readClasses() });
});

// Add a class/year (admin only)
app.post('/api/classes', authMiddleware, adminMiddleware, (req, res) => {
  const name = typeof req.body.name === 'string' ? req.body.name.trim().replace(/\s+/g, ' ') : '';

  if (!name) {
    return res.status(400).json({ error: 'Please enter a class name.' });
  }
  if (name.length > 30) {
    return res.status(400).json({ error: 'Class name must be 30 characters or fewer.' });
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9\s-]*$/.test(name)) {
    return res.status(400).json({ error: 'Class name may only contain letters, numbers, spaces and hyphens.' });
  }

  const classes = readClasses();
  if (classes.some(c => c.toLowerCase() === name.toLowerCase())) {
    return res.status(400).json({ error: `"${name}" already exists.` });
  }

  classes.push(name);
  writeData(CLASSES_FILE, classes);

  res.status(201).json({ message: `Class "${name}" added.`, name, classes });
});

// List papers with subject-level filtration enforcement
app.get('/api/papers', authMiddleware, (req, res) => {
  const { classYear, subject, term, academicYear, search } = req.query;
  let papers = readData(PAPERS_FILE, []);
  const deletionRequests = readData(DELETION_REQUESTS_FILE, []);

  // Strict Subject Scope Check:
  // If not admin, restrict papers strictly to user's assignedSubjects!
  if (req.user.role !== 'admin' && req.user.assignedSubjects && req.user.assignedSubjects.length > 0) {
    papers = papers.filter(p => req.user.assignedSubjects.includes(p.subject));
  }

  if (classYear && classYear !== 'all') {
    papers = papers.filter(p => p.classYear === classYear);
  }

  if (subject && subject !== 'all') {
    // Check if user is trying to access a subject they are not allowed to view
    if (req.user.role !== 'admin' && req.user.assignedSubjects && !req.user.assignedSubjects.includes(subject)) {
      return res.json({ count: 0, papers: [] });
    }
    papers = papers.filter(p => p.subject.toLowerCase() === subject.toLowerCase());
  }

  if (term && term !== 'all') {
    papers = papers.filter(p => p.term === term);
  }

  if (academicYear && academicYear !== 'all') {
    papers = papers.filter(p => p.academicYear === academicYear);
  }

  if (search && search.trim() !== '') {
    const q = search.trim().toLowerCase();
    papers = papers.filter(p => 
      (p.title || '').toLowerCase().includes(q) ||
      (p.description || '').toLowerCase().includes(q) ||
      (p.originalName || '').toLowerCase().includes(q) ||
      (p.paperType || '').toLowerCase().includes(q)
    );
  }

  papers.forEach(p => {
    const latest = deletionRequests
      .filter(r => r.paperId === p.id)
      .sort((a, b) => Number(b.status === 'pending') - Number(a.status === 'pending') ||
        new Date(b.createdAt || 0) - new Date(a.createdAt || 0))[0];
    p.deletionStatus = latest ? latest.status : null;
    p.deletionRequestedAt = latest ? latest.createdAt : null;
    p.deletionProcessedAt = latest ? latest.processedAt : null;
  });

  // Sort latest first
  papers.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));

  res.json({
    count: papers.length,
    papers
  });
});

// Upload paper with subject verification
app.post('/api/papers', authMiddleware, upload.single('paperFile'), (req, res) => {
  if (req.user.role !== 'teacher' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Permission denied. Only authorized teachers and admins can upload papers.' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'No paper file was uploaded' });
  }

  const { title, classYear, subject, term, academicYear, paperType, description } = req.body;

  if (!title || !classYear || !subject || !term) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'Please provide Title, Class/Year, Subject, and Term.' });
  }

  if (!readClasses().includes(classYear)) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: `Invalid class. Must be one of: ${readClasses().join(', ')}` });
  }

  if (!VALID_SUBJECTS.includes(subject)) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'Invalid subject. Strictly Biology or Chemistry allowed.' });
  }

  // Teacher Subject Restriction Check:
  // If not admin, teacher can ONLY upload papers in their assigned subjects!
  if (req.user.role !== 'admin' && req.user.assignedSubjects && !req.user.assignedSubjects.includes(subject)) {
    fs.unlinkSync(req.file.path);
    return res.status(403).json({ 
      error: `Access Denied: You are only authorized to upload papers for [${req.user.assignedSubjects.join(', ')}]. You cannot upload for ${subject}.` 
    });
  }

  if (!VALID_TERMS.includes(term)) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'Invalid term. Must be Term 1, Term 2, or Term 3.' });
  }

  const papers = readData(PAPERS_FILE, []);

  const newPaper = {
    id: 'paper-' + crypto.randomUUID(),
    title: title.trim(),
    classYear: classYear.trim(),
    subject: subject.trim(),
    term: term.trim(),
    academicYear: academicYear ? academicYear.trim() : new Date().getFullYear().toString(),
    paperType: paperType ? paperType.trim() : 'End of Term Exam',
    description: description ? description.trim() : '',
    originalName: req.file.originalname,
    filename: req.file.filename,
    size: req.file.size,
    mimetype: req.file.mimetype,
    uploadedBy: req.user.name || req.user.username,
    uploadedByUsername: req.user.username,
    uploadedAt: new Date().toISOString(),
    downloadsCount: 0
  };

  papers.unshift(newPaper);
  writeData(PAPERS_FILE, papers);

  res.status(201).json({
    message: 'Paper successfully uploaded!',
    paper: newPaper
  });
});

// Inline preview (does not count as a download)
app.get('/api/papers/:id/view', authMiddleware, (req, res) => {
  const { id } = req.params;
  const papers = readData(PAPERS_FILE, []);
  const paper = papers.find(p => p.id === id);

  if (!paper) {
    return res.status(404).json({ error: 'Paper not found' });
  }

  if (req.user.role !== 'admin' && req.user.assignedSubjects && !req.user.assignedSubjects.includes(paper.subject)) {
    return res.status(403).json({ error: `Access Denied: You do not have permission to view ${paper.subject} papers.` });
  }

  const filePath = path.join(UPLOADS_DIR, paper.filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found on server' });
  }

  res.setHeader('Content-Disposition', 'inline');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.sendFile(filePath);
});

// Download paper with subject restriction enforcement
app.get('/api/papers/:id/download', authMiddleware, (req, res) => {
  const { id } = req.params;
  const papers = readData(PAPERS_FILE, []);
  const paper = papers.find(p => p.id === id);

  if (!paper) {
    return res.status(404).json({ error: 'Paper not found' });
  }

  // Teacher / Student Subject Restriction:
  if (req.user.role !== 'admin' && req.user.assignedSubjects && !req.user.assignedSubjects.includes(paper.subject)) {
    return res.status(403).json({ error: `Access Denied: You do not have permission to view or download ${paper.subject} papers.` });
  }

  const filePath = path.join(UPLOADS_DIR, paper.filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found on server' });
  }

  paper.downloadsCount = (paper.downloadsCount || 0) + 1;
  writeData(PAPERS_FILE, papers);

  res.download(filePath, paper.originalName);
});

// Delete paper
app.delete('/api/papers/:id', authMiddleware, (req, res) => {
  // Teachers must request approval, admins can delete directly
  if (req.user.role !== 'teacher' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Permission denied. Only teachers and admins can delete papers.' });
  }

  const { id } = req.params;
  let papers = readData(PAPERS_FILE, []);
  const paperIndex = papers.findIndex(p => p.id === id);

  if (paperIndex === -1) {
    return res.status(404).json({ error: 'Paper not found' });
  }

  const paper = papers[paperIndex];
  // Subject permission check
  if (req.user.role !== 'admin' && req.user.assignedSubjects && !req.user.assignedSubjects.includes(paper.subject)) {
    return res.status(403).json({ error: `Permission denied. You cannot delete ${paper.subject} papers.` });
  }

  // If admin, delete immediately
  if (req.user.role === 'admin') {
    const filePath = path.join(UPLOADS_DIR, paper.filename);
    if (fs.existsSync(filePath)) {
      try {
        fs.unlinkSync(filePath);
      } catch (e) {
        console.error('Error removing file:', e);
        return res.status(500).json({ error: 'Could not remove the paper file.' });
      }
    }
    papers.splice(paperIndex, 1);
    if (!writeData(PAPERS_FILE, papers)) {
      return res.status(500).json({ error: 'Could not update the paper list.' });
    }

    const requests = readData(DELETION_REQUESTS_FILE, []);
    const processedAt = new Date().toISOString();
    requests.forEach(r => {
      if (r.paperId === paper.id && r.status === 'pending') {
        r.status = 'approved';
        r.processedAt = processedAt;
        r.note = 'Paper deleted directly by an administrator.';
      }
    });
    if (!writeData(DELETION_REQUESTS_FILE, requests)) {
      return res.status(500).json({ error: 'Paper deleted, but its requests could not be updated.' });
    }

    return res.json({ message: 'Paper deleted successfully by admin' });
  }

  // Teacher: require a reason in the request body
  const reason = req.body && typeof req.body.reason === 'string' ? req.body.reason.trim() : '';
  if (reason.length < 5) {
    return res.status(400).json({ error: 'A deletion reason of at least 5 characters is required.' });
  }

  // Only one pending request per paper
  const deletionRequests = readData(DELETION_REQUESTS_FILE, []);
  if (deletionRequests.some(r => r.paperId === paper.id && r.status === 'pending')) {
    return res.status(409).json({ error: 'A deletion request for this paper is already awaiting administrator review.' });
  }

  // Create a deletion request entry
  const newRequest = {
    id: 'delreq-' + crypto.randomUUID(),
    paperId: paper.id,
    paperTitle: paper.title,
    paperSubject: paper.subject,
    requestedBy: req.user.id,
    requestedByUsername: req.user.username,
    requestedByName: req.user.name,
    reason,
    status: 'pending',
    createdAt: new Date().toISOString()
  };
  deletionRequests.push(newRequest);
  if (!writeData(DELETION_REQUESTS_FILE, deletionRequests)) {
    return res.status(500).json({ error: 'Could not save the deletion request.' });
  }

  return res.status(202).json({ message: 'Deletion request submitted for admin approval.', requestId: newRequest.id });
});
  

// Admin: Approve deletion request
app.post('/api/admin/deletion-requests/:id/approve', authMiddleware, adminMiddleware, (req, res) => {
  const { id } = req.params;
  let requests = readData(DELETION_REQUESTS_FILE, []);
  const reqIdx = requests.findIndex(r => r.id === id);
  if (reqIdx === -1) return res.status(404).json({ error: 'Deletion request not found' });
  const delReq = requests[reqIdx];
  if (delReq.status !== 'pending') return res.status(400).json({ error: 'Request already processed' });

  const papers = readData(PAPERS_FILE, []);
  const paperIdx = papers.findIndex(p => p.id === delReq.paperId);
  if (paperIdx !== -1) {
    const filePath = path.join(UPLOADS_DIR, papers[paperIdx].filename);
    if (fs.existsSync(filePath)) {
      try {
        fs.unlinkSync(filePath);
      } catch (e) {
        console.error('Error removing file during approval:', e);
        return res.status(500).json({ error: 'Could not remove the paper file.' });
      }
    }
    papers.splice(paperIdx, 1);
    if (!writeData(PAPERS_FILE, papers)) {
      return res.status(500).json({ error: 'Could not update the paper list.' });
    }
  }

  const processedAt = new Date().toISOString();
  requests.forEach(r => {
    if (r.paperId === delReq.paperId && r.status === 'pending') {
      r.status = 'approved';
      r.processedAt = processedAt;
      if (paperIdx === -1) r.note = 'Paper was already removed before approval.';
      else if (r.id !== delReq.id) r.note = 'Paper deleted via a related request.';
    }
  });
  if (!writeData(DELETION_REQUESTS_FILE, requests)) {
    return res.status(500).json({ error: 'Paper deleted, but its requests could not be updated.' });
  }

  res.json({ message: 'Paper deleted and request approved', request: delReq });
});

// Admin: Reject deletion request
app.post('/api/admin/deletion-requests/:id/reject', authMiddleware, adminMiddleware, (req, res) => {
  const { id } = req.params;
  let requests = readData(DELETION_REQUESTS_FILE, []);
  const reqIdx = requests.findIndex(r => r.id === id);
  if (reqIdx === -1) return res.status(404).json({ error: 'Deletion request not found' });
  const delReq = requests[reqIdx];
  if (delReq.status !== 'pending') return res.status(400).json({ error: 'Request already processed' });

  delReq.status = 'rejected';
  delReq.processedAt = new Date().toISOString();
  delReq.rejectionReason = req.body && typeof req.body.reason === 'string' ? req.body.reason.trim() : '';
  requests[reqIdx] = delReq;
  if (!writeData(DELETION_REQUESTS_FILE, requests)) {
    return res.status(500).json({ error: 'Could not save the rejection.' });
  }

  res.json({ message: 'Deletion request rejected', request: delReq });
});

// Admin: List all deletion requests (for approval page)
app.get('/api/admin/deletion-requests', authMiddleware, adminMiddleware, (req, res) => {
  const requests = readData(DELETION_REQUESTS_FILE, []);
  const papers = readData(PAPERS_FILE, []);
  const users = readData(USERS_FILE, []);
  res.json({ requests: requests.map(r => {
    const paper = papers.find(p => p.id === r.paperId);
    const teacher = users.find(u => u.id === r.requestedBy);
    return {
      ...r,
      paperSubject: r.paperSubject || (paper && paper.subject),
      requestedByName: r.requestedByName || (teacher && teacher.name),
      paper: paper ? {
        id: paper.id,
        title: paper.title,
        subject: paper.subject,
        classYear: paper.classYear,
        term: paper.term,
        academicYear: paper.academicYear,
        paperType: paper.paperType,
        originalName: paper.originalName,
        size: paper.size,
        uploadedBy: paper.uploadedBy,
        uploadedByUsername: paper.uploadedByUsername,
        createdAt: paper.createdAt
      } : null
    };
  }) });
});

// Teacher: Get their own deletion requests
app.get('/api/teacher/deletion-requests', authMiddleware, (req, res) => {
  const requests = readData(DELETION_REQUESTS_FILE, []);
  const teacherRequests = requests.filter(r => r.requestedBy === req.user.id);
  res.json({ requests: teacherRequests });
});

app.get('/api/stats', authMiddleware, (req, res) => {
  let papers = readData(PAPERS_FILE, []);

  // Filter stats by user subject permissions
  if (req.user.role !== 'admin' && req.user.assignedSubjects && req.user.assignedSubjects.length > 0) {
    papers = papers.filter(p => req.user.assignedSubjects.includes(p.subject));
  }

  const stats = {
    totalPapers: papers.length,
    biologyCount: papers.filter(p => p.subject === 'Biology').length,
    chemistryCount: papers.filter(p => p.subject === 'Chemistry').length,
    byClass: {},
    byTerm: {
      'Term 1': papers.filter(p => p.term === 'Term 1').length,
      'Term 2': papers.filter(p => p.term === 'Term 2').length,
      'Term 3': papers.filter(p => p.term === 'Term 3').length
    }
  };

  const classList = readClasses();
  papers.forEach(p => {
    if (p.classYear && !classList.includes(p.classYear)) classList.push(p.classYear);
  });
  classList.forEach(c => {
    stats.byClass[c] = papers.filter(p => p.classYear === c).length;
  });

  const VALID_ACADEMIC_YEARS = ['2026', '2025', '2024', '2023', '2022', '2021', '2020'];
  stats.byAcademicYear = {};
  VALID_ACADEMIC_YEARS.forEach(y => {
    stats.byAcademicYear[y] = papers.filter(p => p.academicYear === y).length;
  });

  res.json(stats);
});

// Fallback to index.html for SPA
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
  console.log(`===============================================`);
  console.log(`  TIS Paper Repository Server is running!     `);
  console.log(`  URL: http://localhost:${PORT}                 `);
  console.log(`  Storage: ${DATA_DIR}`);
  if (process.env.NODE_ENV !== 'production') {
    console.log(`  New demo accounts use @example.test email addresses.`);
  } else {
    console.log(`  Mode: production                              `);
  }
  console.log(`===============================================`);
});
