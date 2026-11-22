import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { DatabaseSync } from 'node:sqlite';

const scrypt = promisify(scryptCallback);
const SQLITE_CONSTRAINT_UNIQUE = 2067;
const serverDirectory = path.dirname(fileURLToPath(import.meta.url));
const dataDirectory = path.join(serverDirectory, '..', 'data');
mkdirSync(dataDirectory, { recursive: true });

const database = new DatabaseSync(path.join(dataDirectory, 'users.sqlite'));
database.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));

function validEmail(value) {
  return typeof value === 'string' &&
    value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const derivedKey = await scrypt(password, salt, 64);
  return `${salt}:${Buffer.from(derivedKey).toString('hex')}`;
}

async function passwordMatches(password, storedHash) {
  const [salt, keyHex] = storedHash.split(':');
  const expectedKey = Buffer.from(keyHex ?? '', 'hex');
  if (!salt || expectedKey.length !== 64) {
    return false;
  }

  const derivedKey = Buffer.from(await scrypt(password, salt, 64));
  return timingSafeEqual(derivedKey, expectedKey);
}

app.post('/api/auth/register', async (request, response) => {
  const { fullName, email, password } = request.body ?? {};
  const normalizedName = typeof fullName === 'string' ? fullName.trim() : '';
  const normalizedEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';

  if (!normalizedName || normalizedName.length > 100) {
    return response.status(400).json({ error: 'Enter your name (up to 100 characters).' });
  }
  if (!validEmail(normalizedEmail)) {
    return response.status(400).json({ error: 'Enter a valid email address.' });
  }
  if (typeof password !== 'string' || password.length < 8 || Buffer.byteLength(password) > 256) {
    return response.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  const passwordHash = await hashPassword(password);
  try {
    database.prepare(
      'INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)',
    ).run(normalizedName, normalizedEmail, passwordHash);
  } catch (error) {
    if (error.errcode === SQLITE_CONSTRAINT_UNIQUE) {
      return response.status(409).json({ error: 'An account with this email already exists.' });
    }
    throw error;
  }

  return response.status(201).json({ message: 'Account created successfully.' });
});

app.post('/api/auth/login', async (request, response) => {
  const { email, password } = request.body ?? {};
  const normalizedEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
  if (!validEmail(normalizedEmail) || typeof password !== 'string' || password.length > 256) {
    return response.status(401).json({ error: 'Invalid email or password.' });
  }

  const user = database.prepare(
    'SELECT id, full_name, email, password_hash FROM users WHERE email = ?',
  ).get(normalizedEmail);

  if (!user || !(await passwordMatches(password, user.password_hash))) {
    return response.status(401).json({ error: 'Invalid email or password.' });
  }

  return response.json({
    message: 'Login successful.',
    user: { id: user.id, fullName: user.full_name, email: user.email },
  });
});

app.use('/api', (request, response) => {
  response.status(404).json({ error: 'API route not found.' });
});

app.use((error, request, response, next) => {
  if (error.type === 'entity.parse.failed') {
    return response.status(400).json({ error: 'Request body must be valid JSON.' });
  }

  console.error(error);
  return response.status(500).json({ error: 'A server error occurred. Please try again.' });
});

const port = Number(process.env.PORT || 3001);
app.listen(port, '127.0.0.1', () => {
  console.log(`Auth API listening at http://127.0.0.1:${port}`);
});
