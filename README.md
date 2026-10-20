# Viora sign-in (Google) for Render

## 1. Google Cloud Console
1. APIs & Services > Credentials > Create credentials > OAuth client ID > **Web application**.
2. Authorized redirect URI: `https://YOUR-SERVICE.onrender.com/auth/google/callback`
   (the server prints this exact URI in its logs on start).
3. Copy the Client ID and Client secret. While the app is in Testing, add your Google accounts as Test users.

## 2. Deploy on Render
1. Push this folder to a GitHub repo.
2. Render > New > Blueprint (uses `render.yaml`), or New > Web Service (build `npm install`, start `npm start`).
3. Set env vars: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `ALLOWED_EXTENSION_IDS`. `SESSION_SECRET` is generated for you.
4. Deploy, then open the site and press **Continue with Google**.

## 3. Use it from the Viora extension
Call this instead of Google directly (the extension's `identity` permission is already in the manifest):

```js
const EXT_ID = chrome.runtime.id;
const url = `https://YOUR-SERVICE.onrender.com/auth/google?ext=${EXT_ID}`;
const resp = await chrome.identity.launchWebAuthFlow({ url, interactive: true });
const q = new URL(resp).searchParams;       // token, email, name
const account = { email: q.get('email'), name: q.get('name'), token: q.get('token') };
// Optional check: fetch(`https://YOUR-SERVICE.onrender.com/api/verify?token=${q.get('token')}`)
```
Put the extension ID in `ALLOWED_EXTENSION_IDS`. Tokens last 1 hour; browser sessions last 7 days.

Free Render services sleep when idle, so the first sign-in after a pause can take ~30 seconds.
