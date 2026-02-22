import { describe, it, expect, vi, beforeEach } from 'vitest';
import worker from '../index.js';

// Mock KV store
function createMockKV() {
  const store = new Map();
  return {
    get: vi.fn((key) => Promise.resolve(store.get(key) || null)),
    put: vi.fn((key, value) => { store.set(key, value); return Promise.resolve(); }),
    delete: vi.fn((key) => { store.delete(key); return Promise.resolve(); }),
    _store: store,
  };
}

function createMockEnv(kv) {
  return {
    TWITCH_CLIENT_ID: 'test-client-id',
    TWITCH_CLIENT_SECRET: 'test-client-secret',
    KV: kv || createMockKV(),
  };
}

function createRequest(method, path, body, origin) {
  const url = 'https://twitch-oauth-proxy.workers.dev' + path;
  const headers = new Headers();
  headers.set('Origin', origin || 'https://marsantony.github.io');
  if (body) headers.set('Content-Type', 'application/json');
  return new Request(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
}

// Mock global fetch for Twitch API calls
let mockFetchResponses;

beforeEach(() => {
  mockFetchResponses = [];
  vi.stubGlobal('fetch', vi.fn((...args) => {
    const handler = mockFetchResponses.shift();
    if (handler) return handler(...args);
    return Promise.resolve(new Response('{}', { status: 500 }));
  }));
  vi.stubGlobal('crypto', {
    randomUUID: () => 'test-session-id-1234',
  });
});

describe('Worker', () => {
  describe('CORS preflight', () => {
    it('OPTIONS 回傳 204 + CORS headers', async () => {
      const env = createMockEnv();
      const req = createRequest('OPTIONS', '/token');
      const res = await worker.fetch(req, env);

      expect(res.status).toBe(204);
      expect(res.headers.get('Access-Control-Allow-Origin')).toBe('https://marsantony.github.io');
      expect(res.headers.get('Access-Control-Allow-Methods')).toContain('POST');
    });
  });

  describe('Origin 檢查', () => {
    it('非白名單 origin 回傳 403', async () => {
      const env = createMockEnv();
      const req = createRequest('POST', '/token', { code: 'abc', redirect_uri: 'https://marsantony.github.io/auth/' }, 'https://evil.com');
      const res = await worker.fetch(req, env);

      expect(res.status).toBe(403);
      const data = await res.json();
      expect(data.error).toBe('Forbidden');
    });

    it('沒有 Origin header 回傳 403', async () => {
      const env = createMockEnv();
      const url = 'https://twitch-oauth-proxy.workers.dev/token';
      const req = new Request(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: 'abc', redirect_uri: 'https://marsantony.github.io/auth/' }),
      });
      const res = await worker.fetch(req, env);

      expect(res.status).toBe(403);
    });
  });

  describe('Method 檢查', () => {
    it('GET 回傳 405', async () => {
      const env = createMockEnv();
      const req = createRequest('GET', '/token');
      const res = await worker.fetch(req, env);

      expect(res.status).toBe(405);
    });
  });

  describe('POST /token', () => {
    it('正確交換 code → access_token + session_id + username', async () => {
      const kv = createMockKV();
      const env = createMockEnv(kv);

      // Mock Twitch token exchange
      mockFetchResponses.push(() => Promise.resolve(new Response(JSON.stringify({
        access_token: 'twitch-access-token',
        refresh_token: 'twitch-refresh-token',
        expires_in: 14400,
      }), { status: 200 })));

      // Mock Twitch user fetch
      mockFetchResponses.push(() => Promise.resolve(new Response(JSON.stringify({
        data: [{ login: 'testuser' }],
      }), { status: 200 })));

      const req = createRequest('POST', '/token', {
        code: 'valid-code',
        redirect_uri: 'https://marsantony.github.io/auth/',
      });
      const res = await worker.fetch(req, env);

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.access_token).toBe('twitch-access-token');
      expect(data.session_id).toBe('test-session-id-1234');
      expect(data.username).toBe('testuser');
      expect(data.expires_in).toBe(14400);

      // Verify refresh_token stored in KV
      expect(kv.put).toHaveBeenCalledWith(
        'test-session-id-1234',
        expect.stringContaining('twitch-refresh-token')
      );

      // Verify Twitch API was called with correct params
      const tokenCall = fetch.mock.calls[0];
      expect(tokenCall[0]).toBe('https://id.twitch.tv/oauth2/token');
      expect(tokenCall[1].method).toBe('POST');
    });

    it('缺少 code 回傳 400', async () => {
      const env = createMockEnv();
      const req = createRequest('POST', '/token', { redirect_uri: 'https://marsantony.github.io/auth/' });
      const res = await worker.fetch(req, env);

      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.error).toContain('Missing');
    });

    it('缺少 redirect_uri 回傳 400', async () => {
      const env = createMockEnv();
      const req = createRequest('POST', '/token', { code: 'abc' });
      const res = await worker.fetch(req, env);

      expect(res.status).toBe(400);
    });

    it('無效 JSON body 回傳 400', async () => {
      const env = createMockEnv();
      const url = 'https://twitch-oauth-proxy.workers.dev/token';
      const req = new Request(url, {
        method: 'POST',
        headers: {
          'Origin': 'https://marsantony.github.io',
          'Content-Type': 'application/json',
        },
        body: 'not-json',
      });
      const res = await worker.fetch(req, env);

      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.error).toBe('Invalid JSON');
    });

    it('Twitch 回傳錯誤時轉發錯誤', async () => {
      const env = createMockEnv();

      mockFetchResponses.push(() => Promise.resolve(new Response(JSON.stringify({
        message: 'Invalid authorization code',
      }), { status: 400 })));

      const req = createRequest('POST', '/token', {
        code: 'invalid-code',
        redirect_uri: 'https://marsantony.github.io/auth/',
      });
      const res = await worker.fetch(req, env);

      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.error).toContain('Invalid authorization code');
    });

    it('user fetch 失敗時 username 為空但不影響流程', async () => {
      const env = createMockEnv();

      mockFetchResponses.push(() => Promise.resolve(new Response(JSON.stringify({
        access_token: 'token',
        refresh_token: 'refresh',
        expires_in: 14400,
      }), { status: 200 })));

      // User fetch fails
      mockFetchResponses.push(() => Promise.resolve(new Response('', { status: 500 })));

      const req = createRequest('POST', '/token', {
        code: 'code',
        redirect_uri: 'https://marsantony.github.io/auth/',
      });
      const res = await worker.fetch(req, env);

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.access_token).toBe('token');
      expect(data.username).toBe('');
    });
  });

  describe('POST /refresh', () => {
    it('有效 session_id → 新 access_token + 更新 KV', async () => {
      const kv = createMockKV();
      const env = createMockEnv(kv);

      // Pre-store session in KV
      kv._store.set('existing-session', JSON.stringify({
        refresh_token: 'old-refresh-token',
        username: 'testuser',
        created_at: new Date().toISOString(),
      }));

      mockFetchResponses.push(() => Promise.resolve(new Response(JSON.stringify({
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        expires_in: 14400,
      }), { status: 200 })));

      const req = createRequest('POST', '/refresh', { session_id: 'existing-session' });
      const res = await worker.fetch(req, env);

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.access_token).toBe('new-access-token');
      expect(data.expires_in).toBe(14400);

      // Verify KV was updated with new refresh_token
      expect(kv.put).toHaveBeenCalledWith(
        'existing-session',
        expect.stringContaining('new-refresh-token')
      );
    });

    it('無效 session_id 回傳 401', async () => {
      const env = createMockEnv();
      const req = createRequest('POST', '/refresh', { session_id: 'nonexistent' });
      const res = await worker.fetch(req, env);

      expect(res.status).toBe(401);
      const data = await res.json();
      expect(data.error).toContain('Invalid session');
    });

    it('缺少 session_id 回傳 400', async () => {
      const env = createMockEnv();
      const req = createRequest('POST', '/refresh', {});
      const res = await worker.fetch(req, env);

      expect(res.status).toBe(400);
    });

    it('Twitch refresh 失敗時刪除 session', async () => {
      const kv = createMockKV();
      const env = createMockEnv(kv);

      kv._store.set('revoked-session', JSON.stringify({
        refresh_token: 'revoked-token',
        username: 'testuser',
        created_at: new Date().toISOString(),
      }));

      mockFetchResponses.push(() => Promise.resolve(new Response(JSON.stringify({
        message: 'Invalid refresh token',
      }), { status: 400 })));

      const req = createRequest('POST', '/refresh', { session_id: 'revoked-session' });
      const res = await worker.fetch(req, env);

      expect(res.status).toBe(400);
      expect(kv.delete).toHaveBeenCalledWith('revoked-session');
    });
  });

  describe('POST /logout', () => {
    it('刪除 KV 中的 session', async () => {
      const kv = createMockKV();
      const env = createMockEnv(kv);

      kv._store.set('session-to-delete', JSON.stringify({
        refresh_token: 'token',
        username: 'user',
        created_at: new Date().toISOString(),
      }));

      const req = createRequest('POST', '/logout', { session_id: 'session-to-delete' });
      const res = await worker.fetch(req, env);

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.ok).toBe(true);
      expect(kv.delete).toHaveBeenCalledWith('session-to-delete');
    });

    it('缺少 session_id 回傳 400', async () => {
      const env = createMockEnv();
      const req = createRequest('POST', '/logout', {});
      const res = await worker.fetch(req, env);

      expect(res.status).toBe(400);
    });
  });

  describe('路由', () => {
    it('未知路徑回傳 404', async () => {
      const env = createMockEnv();
      const req = createRequest('POST', '/unknown');
      const res = await worker.fetch(req, env);

      expect(res.status).toBe(404);
    });
  });
});
