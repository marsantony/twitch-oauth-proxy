# twitch-oauth-proxy

Cloudflare Worker，作為 Twitch OAuth Authorization Code flow 的代理（簡化版 BFF pattern）。

## 功能

- 前端發送 authorization code，Worker 用 `client_secret` 向 Twitch 換取 token
- `refresh_token` 儲存在 Cloudflare KV，前端永遠不會接觸到
- 前端只拿到 `access_token`（sessionStorage）和 `session_id`（localStorage）
- 支援 token 刷新和登出

## 端點

| 方法 | 路徑 | 說明 |
|------|------|------|
| POST | `/token` | 用 authorization code 換取 access_token + session_id |
| POST | `/refresh` | 用 session_id 刷新 access_token |
| POST | `/logout` | 刪除 session |
| OPTIONS | `*` | CORS preflight |

## 技術棧

- Cloudflare Workers
- Cloudflare KV（儲存 refresh_token）
- Vitest（測試）

## 開發

```bash
npm install
npm test          # 執行測試
npm run dev       # 本地開發
```

## 部署

推送到 `main` 分支後，GitHub Actions 會自動執行測試並部署。

### 前置設定

1. Cloudflare：KV namespace ID 已在 `wrangler.toml`
2. Worker Secrets：`TWITCH_CLIENT_ID`、`TWITCH_CLIENT_SECRET`
3. GitHub Secret：`CLOUDFLARE_API_TOKEN`
