// Password protection for the whole site (Cloudflare Pages Functions).
// The password is the encrypted secret SITE_PASSWORD in the Pages project settings, never in this file.
// A correct password sets a signed cookie for 30 days; changing the password signs everyone out.

const COOKIE = 'portfolio_auth';
const MAX_AGE = 60 * 60 * 24 * 30;
const LOGIN = '/__login';
const LOGOUT = '/__logout';

async function token(secret) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode('portfolio-auth-v1'));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function readCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

function safeNext(value) {
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//') && !value.startsWith('/__') ? value : '/';
}

function esc(s) {
  return s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function page(next, error, status) {
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Adisa Soren</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Urbanist:wght@400..600&family=Mona+Sans:wght@400..600&display=swap">
<style>
  :root { --bg: #f7f9fa; --surface: #ecf0f2; --ink: #1f3038; --muted: #5d6b72; --accent: #3239f2; --accent-ink: #f7f9fa; --line: #1f30381f; --error: #a3231b; }
  * { box-sizing: border-box; }
  html, body { margin: 0; min-height: 100%; }
  body { background: var(--bg); color: var(--ink); font: 400 16px/1.55 "Mona Sans", system-ui, sans-serif; display: grid; place-items: center; min-height: 100vh; padding: 24px; }
  main { width: min(100%, 400px); display: grid; gap: 24px; }
  .name { font: 500 22px/1 "Urbanist", system-ui, sans-serif; letter-spacing: -0.02em; }
  h1 { margin: 0; font: 400 40px/1.1 "Urbanist", system-ui, sans-serif; letter-spacing: -0.03em; text-wrap: balance; }
  p { margin: 0; color: var(--muted); }
  form { display: grid; gap: 12px; }
  label { font-size: 14px; font-weight: 500; }
  input { height: 48px; padding: 0 16px; border: 1px solid #1f303833; border-radius: 8px; background: #fff; color: var(--ink); font: inherit; }
  input:focus-visible, button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  input[aria-invalid="true"] { border: 2px solid var(--error); }
  .error { color: var(--error); font-size: 14px; font-weight: 500; }
  button { height: 48px; border: 0; border-radius: 8px; background: var(--accent); color: var(--accent-ink); font: 500 16px/1 "Mona Sans", system-ui, sans-serif; cursor: pointer; margin-top: 4px; }
  button:hover { background: #2a30cf; }
  .foot { font-size: 14px; border-top: 1px solid var(--line); padding-top: 16px; }
</style>
</head>
<body>
<main>
  <span class="name">Adisa Soren</span>
  <div style="display:grid;gap:12px">
    <h1>UX research portfolio</h1>
    <p>This portfolio is shared privately. Enter the password from my application or email.</p>
  </div>
  <form method="post" action="${LOGIN}">
    <input type="hidden" name="next" value="${esc(next)}">
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required autofocus${error ? ' aria-invalid="true" aria-describedby="err"' : ''}>
    ${error ? '<p class="error" id="err" role="alert">That password didn\'t work. Check it and try again.</p>' : ''}
    <button type="submit">View portfolio</button>
  </form>
  <p class="foot">No password? Email asoren@iconoclassique.com.</p>
</main>
</body>
</html>`;
  return new Response(html, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex' } });
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const secret = env.SITE_PASSWORD;

  // Fail closed: without a configured password nothing is served.
  if (!secret) return new Response('This site is not available yet.', { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });

  const expected = await token(secret);

  if (url.pathname === LOGOUT) {
    return new Response(null, { status: 303, headers: { Location: '/', 'Set-Cookie': `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax` } });
  }

  if (url.pathname === LOGIN && request.method === 'POST') {
    const form = await request.formData();
    const target = safeNext(form.get('next'));
    const given = await token(String(form.get('password') || ''));
    if (safeEqual(given, expected)) {
      return new Response(null, { status: 303, headers: { Location: target, 'Set-Cookie': `${COOKIE}=${expected}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Lax`, 'Cache-Control': 'no-store' } });
    }
    return page(target, true, 401);
  }

  if (safeEqual(readCookie(request, COOKIE), expected)) {
    const response = await next();
    const out = new Response(response.body, response);
    out.headers.set('Cache-Control', 'private, no-store');
    out.headers.set('X-Robots-Tag', 'noindex');
    return out;
  }

  return page(safeNext(url.pathname + url.search), false, 401);
}
