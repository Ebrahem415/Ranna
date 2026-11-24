// رنة — live prototype server v2: accounts + 1:1 messaging + static front-end.
// Pure Node stdlib (node:sqlite), zero npm dependencies.
// Hardened: SQLite storage with WAL, hashed session tokens, auth/OTP rate limits,
// contacts by exact lookup only (no open member list, no phone disclosure),
// Google sign-in with state cookie + id_token signature verification.
// Remaining limits: see SECURITY.md.
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const DB_PATH = process.env.DB_PATH || '/tmp/ranna-live.db';
const PORT = Number(process.env.PORT || 8765);
const PUBLIC = path.join(import.meta.dirname, 'public');
const MAX_BODY = 16 * 1024;
const MAX_TEXT = 2000;
const SESSION_TTL = 7 * 24 * 3600 * 1000;
const OTP_TTL = 10 * 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;

const db = new DatabaseSync(DB_PATH);
db.exec(`
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,
  phone TEXT,
  google_sub TEXT UNIQUE,
  email TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  username TEXT NOT NULL REFERENCES users(username),
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  from_user TEXT NOT NULL,
  to_user TEXT NOT NULL,
  text TEXT NOT NULL,
  at INTEGER NOT NULL,
  read INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_msgs_pair ON messages(from_user, to_user);
CREATE TABLE IF NOT EXISTS phone_codes (
  phone TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  exp INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0
);
`);
try { db.exec('ALTER TABLE users ADD COLUMN last_seen INTEGER'); } catch {}

const hash = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// --- rate limiting (fixed window per key, in memory) ---
const buckets = new Map();
const limited = (key, max, windowMs) => {
  const now = Date.now();
  const b = buckets.get(key);
  if (!b || now > b.reset) { buckets.set(key, { count: 1, reset: now + windowMs }); return false; }
  b.count += 1;
  return b.count > max;
};
const ip = (req) => req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';

const SMS_LIVE = !!(process.env.TWILIO_SID && process.env.TWILIO_TOKEN && process.env.TWILIO_FROM);
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_LIVE = !!(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);

const json = (res, code, obj, extraHeaders = {}) => {
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'x-content-type-options': 'nosniff', 'cache-control': 'no-store', ...extraHeaders });
  res.end(JSON.stringify(obj));
};
const body = (req) => new Promise((ok, no) => {
  let b = ''; req.on('data', (c) => { b += c; if (b.length > MAX_BODY) { no(new Error('body too large')); req.destroy(); } });
  req.on('end', () => { try { ok(JSON.parse(b || '{}')); } catch (e) { no(e); } });
});
const newSession = (username) => {
  const token = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO sessions(token_hash, username, created_at) VALUES (?,?,?)').run(sha256(token), username, Date.now());
  return token;
};
const auth = (req) => {
  const t = req.headers['x-session'];
  if (!t || typeof t !== 'string') return null;
  const row = db.prepare('SELECT username, created_at FROM sessions WHERE token_hash = ?').get(sha256(t));
  if (!row) return null;
  if (Date.now() - row.created_at > SESSION_TTL) { db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(t)); return null; }
  db.prepare('UPDATE users SET last_seen = ? WHERE username = ?').run(Date.now(), row.username);
  return row.username;
};
const validName = (u) => typeof u === 'string' && /^[\w\u0600-\u06FF.-]{2,32}$/.test(u);
const publicUser = (u) => ({ username: u.username, name: u.name }); // never phone/email

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.png': 'image/png', '.svg': 'image/svg+xml' };

// --- Google id_token verification (RS256 against Google's published keys) ---
const b64url = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
let jwksCache = { at: 0, keys: [] };
const googleKeys = async () => {
  if (Date.now() - jwksCache.at > 3600_000) {
    const j = await (await fetch('https://www.googleapis.com/oauth2/v3/certs')).json();
    jwksCache = { at: Date.now(), keys: j.keys || [] };
  }
  return jwksCache.keys;
};
const verifyIdToken = async (idToken) => {
  const [h, p, sig] = String(idToken).split('.');
  if (!h || !p || !sig) return null;
  const header = JSON.parse(b64url(h).toString());
  const payload = JSON.parse(b64url(p).toString());
  const jwk = (await googleKeys()).find((k) => k.kid === header.kid);
  if (!jwk) return null;
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const ok = crypto.verify('RSA-SHA256', Buffer.from(`${h}.${p}`), key, b64url(sig));
  if (!ok) return null;
  if (payload.aud !== GOOGLE_CLIENT_ID) return null;
  if (!['https://accounts.google.com', 'accounts.google.com'].includes(payload.iss)) return null;
  if (!payload.exp || payload.exp * 1000 < Date.now()) return null;
  return payload;
};

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const client = ip(req);
  try {
    if (url.pathname.startsWith('/api/')) {
      if (req.method === 'GET' && url.pathname === '/api/auth/config') {
        return json(res, 200, { google: GOOGLE_LIVE, phone: true, phoneMode: SMS_LIVE ? 'live' : 'dev' });
      }
      if (req.method === 'POST' && url.pathname === '/api/phone/start') {
        if (limited('otp:' + client, 5, 10 * 60_000)) return json(res, 429, { error: 'too many requests, try later' });
        const { phone } = await body(req);
        const norm = String(phone || '').replace(/[\s-]/g, '');
        if (!/^\+?\d{8,15}$/.test(norm)) return json(res, 400, { error: 'bad phone' });
        const code = String(crypto.randomInt(100000, 1000000));
        const salt = crypto.randomBytes(8).toString('hex');
        db.prepare('INSERT INTO phone_codes(phone, code_hash, salt, exp, attempts) VALUES (?,?,?,?,0) ON CONFLICT(phone) DO UPDATE SET code_hash=excluded.code_hash, salt=excluded.salt, exp=excluded.exp, attempts=0')
          .run(norm, hash(code, salt), salt, Date.now() + OTP_TTL);
        if (SMS_LIVE) {
          const creds = Buffer.from(`${process.env.TWILIO_SID}:${process.env.TWILIO_TOKEN}`).toString('base64');
          await fetch(`https://api.twilio.com/2010-04-01/Accounts/${process.env.TWILIO_SID}/Messages.json`, {
            method: 'POST',
            headers: { authorization: 'Basic ' + creds, 'content-type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ To: norm, From: process.env.TWILIO_FROM, Body: `كود رنة: ${code}` }),
          });
        } else {
          console.log(`[DEV SMS] code for ${norm}: ${code}`);
        }
        return json(res, 200, { ok: true, mode: SMS_LIVE ? 'live' : 'dev' });
      }
      if (req.method === 'POST' && url.pathname === '/api/phone/verify') {
        if (limited('otpverify:' + client, 15, 10 * 60_000)) return json(res, 429, { error: 'too many requests, try later' });
        const { phone, code, name } = await body(req);
        const norm = String(phone || '').replace(/[\s-]/g, '');
        const rec = db.prepare('SELECT * FROM phone_codes WHERE phone = ?').get(norm);
        if (!rec || Date.now() > rec.exp || rec.attempts >= OTP_MAX_ATTEMPTS) return json(res, 401, { error: 'code expired or too many attempts' });
        db.prepare('UPDATE phone_codes SET attempts = attempts + 1 WHERE phone = ?').run(norm);
        if (hash(String(code || ''), rec.salt) !== rec.code_hash) return json(res, 401, { error: 'wrong code' });
        db.prepare('DELETE FROM phone_codes WHERE phone = ?').run(norm);
        let user = db.prepare('SELECT * FROM users WHERE phone = ?').get(norm);
        if (!user) {
          const username = 'u' + crypto.randomBytes(6).toString('hex');
          const salt = crypto.randomBytes(16).toString('hex');
          db.prepare('INSERT INTO users(username, name, salt, hash, phone, created_at) VALUES (?,?,?,?,?,?)')
            .run(username, String(name || 'مستخدم رنة').slice(0, 40) || 'مستخدم رنة', salt, hash(crypto.randomBytes(16).toString('hex'), salt), norm, Date.now());
          user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        }
        return json(res, 200, { session: newSession(user.username), ...publicUser(user) });
      }
      if (req.method === 'GET' && url.pathname === '/api/auth/google/start') {
        if (!GOOGLE_LIVE) return json(res, 501, { error: 'google sign-in not configured: needs an OAuth client from the app owner\'s Google Cloud project' });
        const state = crypto.randomBytes(12).toString('hex');
        const redirect = `${url.origin}/api/auth/google/callback`;
        res.writeHead(302, {
          'set-cookie': `g_state=${state}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`,
          location: `https://accounts.google.com/o/oauth2/v2/auth?client_id=${GOOGLE_CLIENT_ID}&redirect_uri=${encodeURIComponent(redirect)}&response_type=code&scope=openid%20email%20profile&state=${state}`,
        });
        return res.end();
      }
      if (req.method === 'GET' && url.pathname === '/api/auth/google/callback') {
        if (!GOOGLE_LIVE) return json(res, 501, { error: 'google sign-in not configured' });
        // state cookie must match the state parameter (login CSRF protection)
        const cookieState = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith('g_state='))?.slice(8);
        if (!cookieState || cookieState !== url.searchParams.get('state')) return json(res, 403, { error: 'state mismatch' });
        const code = url.searchParams.get('code');
        if (!code) return json(res, 400, { error: 'missing code' });
        const redirect = `${url.origin}/api/auth/google/callback`;
        const tok = await (await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ code, client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET, redirect_uri: redirect, grant_type: 'authorization_code' }) })).json();
        if (!tok.id_token) return json(res, 401, { error: 'google token exchange failed' });
        // verified identity: signature against Google's published keys + audience/issuer/expiry checks
        const claims = await verifyIdToken(tok.id_token);
        if (!claims || !claims.sub) return json(res, 401, { error: 'id token verification failed' });
        if (claims.email && claims.email_verified !== true) return json(res, 403, { error: 'google email not verified' });
        let user = db.prepare('SELECT * FROM users WHERE google_sub = ?').get(claims.sub);
        if (!user) {
          const username = 'g' + claims.sub;
          const salt = crypto.randomBytes(16).toString('hex');
          db.prepare('INSERT INTO users(username, name, salt, hash, google_sub, email, created_at) VALUES (?,?,?,?,?,?,?)')
            .run(username, String(claims.name || claims.email || 'مستخدم رنة').slice(0, 40), salt, hash(crypto.randomBytes(16).toString('hex'), salt), claims.sub, claims.email_verified === true ? claims.email : null, Date.now());
          user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        }
        const token = newSession(user.username);
        res.writeHead(302, { location: '/#session=' + token + '&user=' + encodeURIComponent(user.username) });
        return res.end();
      }
      if (req.method === 'POST' && url.pathname === '/api/register') {
        if (limited('register:' + client, 5, 10 * 60_000)) return json(res, 429, { error: 'too many requests, try later' });
        const { username, password, name } = await body(req);
        if (!validName(username) || typeof password !== 'string' || password.length < 6) return json(res, 400, { error: 'username or password invalid' });
        if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) return json(res, 409, { error: 'username taken' });
        const salt = crypto.randomBytes(16).toString('hex');
        db.prepare('INSERT INTO users(username, name, salt, hash, created_at) VALUES (?,?,?,?,?)')
          .run(username, String(name || username).slice(0, 40), salt, hash(password, salt), Date.now());
        return json(res, 200, { session: newSession(username), name: String(name || username).slice(0, 40), username });
      }
      if (req.method === 'POST' && url.pathname === '/api/login') {
        if (limited('login:' + client, 10, 5 * 60_000)) return json(res, 429, { error: 'too many attempts, try later' });
        const { username, password } = await body(req);
        const u = db.prepare('SELECT * FROM users WHERE username = ?').get(String(username || ''));
        if (!u || hash(String(password || ''), u.salt) !== u.hash) return json(res, 401, { error: 'bad credentials' });
        return json(res, 200, { session: newSession(u.username), name: u.name, username: u.username });
      }
      const me = auth(req);
      if (!me) return json(res, 401, { error: 'no session' });
      if (req.method === 'POST' && url.pathname === '/api/send') {
        const { to, text } = await body(req);
        if (!db.prepare('SELECT 1 FROM users WHERE username = ?').get(String(to || ''))) return json(res, 404, { error: 'no such user' });
        if (typeof text !== 'string' || !text.trim() || text.length > MAX_TEXT) return json(res, 400, { error: 'bad text' });
        const id = crypto.randomUUID();
        db.prepare('INSERT INTO messages(id, from_user, to_user, text, at, read) VALUES (?,?,?,?,?,0)').run(id, me, String(to), text.slice(0, MAX_TEXT), Date.now());
        return json(res, 200, { ok: true, id });
      }
      if (req.method === 'GET' && url.pathname === '/api/inbox') {
        const peer = String(url.searchParams.get('with') || '');
        const msgs = db.prepare('SELECT id, from_user AS "from", to_user AS "to", text, at, read FROM messages WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?) ORDER BY at').all(me, peer, peer, me);
        db.prepare('UPDATE messages SET read = 1 WHERE from_user = ? AND to_user = ? AND read = 0').run(peer, me);
        return json(res, 200, { me, messages: msgs.map((m) => ({ ...m, read: !!m.read })) });
      }
      if (req.method === 'GET' && url.pathname === '/api/presence') {
        const peer = String(url.searchParams.get('with') || '');
        const u = db.prepare('SELECT last_seen FROM users WHERE username = ?').get(peer);
        if (!u) return json(res, 404, { error: 'no such user' });
        const online = !!u.last_seen && Date.now() - u.last_seen < 10_000;
        return json(res, 200, { online, last_seen: u.last_seen || null });
      }
      // contacts: exact lookup only — no member list, and the response never includes the phone number or email
      if (req.method === 'GET' && url.pathname === '/api/contacts/lookup') {
        if (limited('lookup:' + client, 10, 5 * 60_000)) return json(res, 429, { error: 'too many lookups, try later' });
        const q = String(url.searchParams.get('q') || '').trim();
        if (!q) return json(res, 400, { error: 'missing query' });
        const byName = db.prepare('SELECT username, name FROM users WHERE username = ?').get(q);
        if (byName) return json(res, 200, { user: byName });
        const norm = q.replace(/[\s-]/g, '');
        if (/^\+?\d{8,15}$/.test(norm)) {
          const byPhone = db.prepare('SELECT username, name FROM users WHERE phone = ?').get(norm);
          if (byPhone) return json(res, 200, { user: byPhone });
        }
        return json(res, 404, { error: 'not found' });
      }
      if (req.method === 'GET' && url.pathname === '/api/conversations') {
        const rows = db.prepare(`
          SELECT peer, MAX(at) AS at FROM (
            SELECT to_user AS peer, at FROM messages WHERE from_user = ?
            UNION ALL
            SELECT from_user AS peer, at FROM messages WHERE to_user = ?
          ) GROUP BY peer ORDER BY at DESC`).all(me, me);
        const convos = rows.map((r) => {
          const u = db.prepare('SELECT username, name FROM users WHERE username = ?').get(r.peer);
          const last = db.prepare('SELECT text, at FROM messages WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?) ORDER BY at DESC LIMIT 1').get(me, r.peer, r.peer, me);
          const unread = db.prepare('SELECT COUNT(*) c FROM messages WHERE from_user = ? AND to_user = ? AND read = 0').get(r.peer, me).c > 0;
          return { username: r.peer, name: u?.name || r.peer, text: last?.text || '', at: last?.at || r.at, unread };
        });
        return json(res, 200, { conversations: convos });
      }
      return json(res, 404, { error: 'not found' });
    }
    // static
    let p = path.normalize(url.pathname).replace(/^([/\\])+/, '');
    if (!p || p.endsWith('/')) p += 'index.html';
    const file = path.join(PUBLIC, p);
    if (!file.startsWith(PUBLIC) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream', 'x-content-type-options': 'nosniff' });
    fs.createReadStream(file).pipe(res);
  } catch (e) { return json(res, 500, { error: String(e && e.message || e) }); }
}).listen(PORT, () => console.log('ranna-live v2 listening on', PORT));
