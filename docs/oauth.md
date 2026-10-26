# OAuth and remote MCP integration

- MCP: **https://YOUR_DOMAIN/mcp**
- OAuth issuer: **https://YOUR_DOMAIN/oidc**
- Protected resource metadata: **/.well-known/oauth-protected-resource/mcp**
- OpenID Connect discovery: **/oidc/.well-known/openid-configuration**
- Dynamic client registration: **/oidc/reg**

Use a remote MCP client supporting Streamable HTTP, authorization code and OAuth resource indicators. Public OAuth clients require **S256 PKCE** and approved public HTTPS redirect URIs. Confidential clients may use client_secret_post and should use PKCE.

Required base scope: **mcp**. Additional scope values: **profile:read**, **profile:write**, **projects:read**, **proposals:read**, **proposals:write**, **conversations:read**, **conversations:write**.

Only scoped, tenant-authorized tools are advertised and callable. OAuth consent is separate from the owner's human portal financial/sending controls. The server does not need an LLM API key; the connected AI client supplies its own model.

Handle REAUTH_REQUIRED, NEEDS_PAYMENT and UNKNOWN safely. This unofficial integration can be affected by changes to Karlancer's observed endpoints.
