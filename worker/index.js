const TWITCH_TOKEN_URL = 'https://id.twitch.tv/oauth2/token';
const TWITCH_USERS_URL = 'https://api.twitch.tv/helix/users';

const ALLOWED_ORIGINS = [
  'https://marsantony.github.io',
];

function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  const allowed = ALLOWED_ORIGINS.includes(origin);
  return {
    'Access-Control-Allow-Origin': allowed ? origin : ALLOWED_ORIGINS[0],
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function json(data, status, request) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(request) },
  });
}

function checkOrigin(request) {
  const origin = request.headers.get('Origin') || '';
  return ALLOWED_ORIGINS.includes(origin);
}

/**
 * POST /token — exchange authorization code for tokens
 * Body: { code, redirect_uri }
 */
async function handleToken(request, env) {
  if (!checkOrigin(request)) return json({ error: 'Forbidden' }, 403, request);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON' }, 400, request);
  }

  const { code, redirect_uri } = body;
  if (!code || !redirect_uri) {
    return json({ error: 'Missing code or redirect_uri' }, 400, request);
  }

  // Exchange code for tokens with Twitch
  const twitchRes = await fetch(TWITCH_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.TWITCH_CLIENT_ID,
      client_secret: env.TWITCH_CLIENT_SECRET,
      code,
      grant_type: 'authorization_code',
      redirect_uri,
    }),
  });

  const twitchData = await twitchRes.json();

  if (!twitchRes.ok) {
    return json({
      error: twitchData.message || 'Token exchange failed',
    }, twitchRes.status, request);
  }

  const { access_token, refresh_token, expires_in } = twitchData;

  // Fetch username
  let username = '';
  try {
    const userRes = await fetch(TWITCH_USERS_URL, {
      headers: {
        'Authorization': 'Bearer ' + access_token,
        'Client-Id': env.TWITCH_CLIENT_ID,
      },
    });
    if (userRes.ok) {
      const userData = await userRes.json();
      const user = userData.data && userData.data[0];
      if (user) username = user.login;
    }
  } catch {
    // Non-fatal: username lookup failed
  }

  // Generate session_id and store refresh_token in KV
  const sessionId = crypto.randomUUID();
  await env.KV.put(sessionId, JSON.stringify({
    refresh_token,
    username,
    created_at: new Date().toISOString(),
  }));

  return json({
    access_token,
    session_id: sessionId,
    username,
    expires_in,
  }, 200, request);
}

/**
 * POST /refresh — refresh access_token using session_id
 * Body: { session_id }
 */
async function handleRefresh(request, env) {
  if (!checkOrigin(request)) return json({ error: 'Forbidden' }, 403, request);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON' }, 400, request);
  }

  const { session_id } = body;
  if (!session_id) {
    return json({ error: 'Missing session_id' }, 400, request);
  }

  const stored = await env.KV.get(session_id);
  if (!stored) {
    return json({ error: 'Invalid session' }, 401, request);
  }

  const { refresh_token, username } = JSON.parse(stored);

  // Refresh with Twitch
  const twitchRes = await fetch(TWITCH_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.TWITCH_CLIENT_ID,
      client_secret: env.TWITCH_CLIENT_SECRET,
      grant_type: 'refresh_token',
      refresh_token,
    }),
  });

  const twitchData = await twitchRes.json();

  if (!twitchRes.ok) {
    // If refresh_token is revoked, clean up the session
    if (twitchRes.status === 400 || twitchRes.status === 401) {
      await env.KV.delete(session_id);
    }
    return json({
      error: twitchData.message || 'Refresh failed',
    }, twitchRes.status, request);
  }

  // Update KV with new refresh_token
  await env.KV.put(session_id, JSON.stringify({
    refresh_token: twitchData.refresh_token,
    username,
    created_at: new Date().toISOString(),
  }));

  return json({
    access_token: twitchData.access_token,
    expires_in: twitchData.expires_in,
  }, 200, request);
}

/**
 * POST /logout — delete session from KV
 * Body: { session_id }
 */
async function handleLogout(request, env) {
  if (!checkOrigin(request)) return json({ error: 'Forbidden' }, 403, request);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON' }, 400, request);
  }

  const { session_id } = body;
  if (!session_id) {
    return json({ error: 'Missing session_id' }, 400, request);
  }

  await env.KV.delete(session_id);
  return json({ ok: true }, 200, request);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    if (request.method !== 'POST') {
      return json({ error: 'Method not allowed' }, 405, request);
    }

    if (path === '/token') return handleToken(request, env);
    if (path === '/refresh') return handleRefresh(request, env);
    if (path === '/logout') return handleLogout(request, env);

    return json({ error: 'Not found' }, 404, request);
  },
};
