// Viora sign-in site: Google OAuth (authorization-code flow) for Render.
// The client secret stays on the server. No database needed.
const express = require('express');
const crypto = require('crypto');

const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  SESSION_SECRET,
  ALLOWED_EXTENSION_IDS = '',
  RENDER_EXTERNAL_URL,
  PORT = 3000,
} = process.env;
const BASE_URL = (process.env.BASE_URL || RENDER_EXTERNAL_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const CALLBACK = `${BASE_URL}/auth/google/callback`;
const allowedExt = ALLOWED_EXTENSION_IDS.split(',').map(s => s.trim()).filter(Boolean);
const secure = BASE_URL.startsWith('https://');

for (const [k, v] of Object.entries({ GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, SESSION_SECRET })) {
  if (!v) console.warn(`Missing env var ${k}`);
}

// ---- tiny signed tokens (HMAC-SHA256) ----
const b64 = b => Buffer.from(b).toString('base64url');
const sign = (obj, ttlSec) => {
  const body = b64(JSON.stringify({ ...obj, exp: Date.now() + ttlSec * 1000 }));
  return `${body}.${crypto.createHmac('sha256', SESSION_SECRET || 'dev').update(body).digest('base64url')}`;
};
const verify = tok => {
  try {
    const [body, mac] = String(tok).split('.');
    const good = crypto.createHmac('sha256', SESSION_SECRET || 'dev').update(body).digest('base64url');
    if (!mac || mac.length !== good.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(good))) return null;
    const data = JSON.parse(Buffer.from(body, 'base64url').toString());
    return data.exp > Date.now() ? data : null;
  } catch { return null; }
};
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(/;\s*/).filter(Boolean).map(c => { const i = c.indexOf('='); return [c.slice(0, i), decodeURIComponent(c.slice(i + 1))]; }));
const setCookie = (res, name, val, maxAge) =>
  res.append('Set-Cookie', `${name}=${encodeURIComponent(val)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? '; Secure' : ''}`);

const app = express();
app.disable('x-powered-by');
app.use(express.static('public'));

// 1) Start sign-in. Add ?ext=<extension id> to return the result to the Viora extension.
app.get('/auth/google', (req, res) => {
  const ext = String(req.query.ext || '');
  if (ext && !allowedExt.includes(ext)) return res.status(400).send('This extension ID is not allowed. Add it to ALLOWED_EXTENSION_IDS.');
  const nonce = crypto.randomBytes(16).toString('hex');
  setCookie(res, 'oauth_nonce', nonce, 600);
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID || '',
    redirect_uri: CALLBACK,
    response_type: 'code',
    scope: 'openid email profile',
    state: sign({ nonce, ext }, 600),
    prompt: 'select_account',
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

// 2) Google sends the user back here.
app.get('/auth/google/callback', async (req, res) => {
  try {
    if (req.query.error) throw new Error(req.query.error === 'access_denied' ? 'Sign-in was cancelled.' : `Google error: ${req.query.error}`);
    const state = verify(req.query.state);
    if (!state || state.nonce !== cookies(req).oauth_nonce) throw new Error('Sign-in expired or was tampered with. Try again.');
    res.append('Set-Cookie', 'oauth_nonce=; Path=/; Max-Age=0');

    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code: String(req.query.code || ''),
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: CALLBACK,
        grant_type: 'authorization_code',
      }),
    });
    const tok = await tokenRes.json();
    if (!tokenRes.ok) throw new Error(tok.error_description || 'Google rejected the sign-in code.');

    const infoRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers: { Authorization: `Bearer ${tok.access_token}` } });
    const info = await infoRes.json();
    if (!info.email || !info.email_verified) throw new Error('That Google account has no verified email.');

    const user = { email: info.email, name: info.name || '', picture: info.picture || '' };
    if (state.ext) {
      // chrome.identity.launchWebAuthFlow catches this redirect and returns it to the extension.
      const q = new URLSearchParams({ token: sign(user, 3600), email: user.email, name: user.name, picture: user.picture });
      return res.redirect(`https://${state.ext}.chromiumapp.org/?${q}`);
    }
    setCookie(res, 'session', sign(user, 7 * 86400), 7 * 86400);
    res.redirect('/');
  } catch (e) {
    res.status(400).send(`<!doctype html><meta charset="utf-8"><body style="font:16px system-ui;padding:2rem;max-width:36rem"><h1>Sign-in failed</h1><p>${String(e.message).replace(/[<>&]/g, '')}</p><p><a href="/">Back to start</a></p>`);
  }
});

// Who is signed in (browser session).
app.get('/api/me', (req, res) => {
  const u = verify(cookies(req).session);
  res.json(u ? { email: u.email, name: u.name, picture: u.picture } : null);
});

// Lets the extension check a token it received.
app.get('/api/verify', (req, res) => {
  const u = verify(req.query.token);
  res.status(u ? 200 : 401).json(u ? { email: u.email, name: u.name, picture: u.picture } : { error: 'invalid or expired' });
});

app.post('/logout', (req, res) => { res.append('Set-Cookie', 'session=; Path=/; Max-Age=0'); res.redirect('/'); });
app.get('/healthz', (_req, res) => res.send('ok'));

app.listen(PORT, () => { console.log(`Listening on ${PORT}`); console.log(`Google redirect URI to register: ${CALLBACK}`); });
