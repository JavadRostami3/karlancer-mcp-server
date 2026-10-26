# Self-hosting and deployment

The bundled Docker Compose file builds a Node 24 application, runs as an unprivileged user and binds **127.0.0.1:18940** only. It persists encrypted SQLite data in a named Docker volume and drops Linux capabilities.

1. Copy .env.example to .env. Supply a public HTTPS BASE_URL, permanent 64-hex MASTER_KEY, and SHA-256 OWNER_PHONE_HASH.
2. Run docker compose up -d --build and verify curl -fsS http://127.0.0.1:18940/healthz.
3. Configure an HTTPS reverse proxy (Nginx or Caddy) from your domain to http://127.0.0.1:18940. Pass the public Host and X-Forwarded-Proto headers and disable response buffering for streaming.
4. Open https://YOUR_DOMAIN/ to complete human OTP sign-in. Users other than the owner need an invitation.
5. Register https://YOUR_DOMAIN/mcp in a remote OAuth-capable MCP client.

## Example Nginx location

~~~nginx
location / {
    proxy_pass http://127.0.0.1:18940;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_read_timeout 3600s;
}
~~~

Configure a valid SSL certificate and HTTPS server separately; do not publicly expose ports 8940 or 18940.

## Backups and upgrades

Back up SQLite **consistently** (SQLite online backup, not an uncoordinated live file copy). Keep the corresponding MASTER_KEY in separate protected storage. Never regenerate the key when reusing the database. For upgrades, test source and rollback compatibility before rebuilding. Never delete the data volume as part of normal redeployments.

## Troubleshooting

| Symptom | First check |
| --- | --- |
| 502 from reverse proxy | Container health and loopback upstream |
| OAuth redirect rejected | Exact HTTPS redirect URI, PKCE and client registration |
| REAUTH_REQUIRED | Reconnect Karlancer account in portal |
| UNKNOWN submission | Read get_operation_status; do not blindly retry |
| Needs payment | Actual upstream quota or paid limits |

This is an unofficial adapter. Upstream behavior, quota and terms can change.
