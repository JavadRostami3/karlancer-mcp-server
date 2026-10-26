import { createHash, generateKeyPairSync, randomBytes, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import express, { type Express, type Request, type RequestHandler } from 'express';
import Provider, { errors, type Configuration } from 'oidc-provider';
import type { Store } from './store.js';
import {addOAuthCspReporting,installOAuthTrace,traceGoogleHandoff} from './oauth-trace.js';

type Payload = Record<string, any>;
type Stored = { payload: Payload; expiresAt?: number };
type Member = { model: string; id: string; expiresAt?: number };
const MCP_SCOPES = ['mcp','profile:read','profile:write','projects:read','proposals:read','proposals:write','conversations:read','conversations:write'];
const loopback = (host: string) => ['localhost', '127.0.0.1', '[::1]'].includes(host);
const escapeHtml = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
type InteractionStage = 'interactionDetails' | 'consentValidation' | 'clientLookup' | 'grantLookup' | 'grantSave' | 'interactionFinished';
const interactionFailures = new WeakMap<object, { stage: InteractionStage; cookieMatchesRoute: boolean }>();

/** Only fixed messages may reach diagnostics; provider error details can contain credentials. */
export function identityErrorDiagnostic(req: Request, error: unknown) {
  if (req.route?.path !== '/interaction/:uid') return undefined;
  const value = error as { name?: unknown; status?: unknown; message?: unknown; error_description?: unknown } | null;
  const names = ['SessionNotFound', 'InvalidRequest', 'InvalidTarget', 'Error', 'TypeError', 'SyntaxError', 'BadRequestError', 'PayloadTooLargeError'];
  const messages = ['interaction session id cookie not found', 'interaction session not found', 'session not found', 'session principal changed', 'request is invalid', 'request aborted', 'request size did not match content length', 'stream is not readable'];
  const description = value?.error_description ?? value?.message;
  const safeDescription = typeof description === 'string' && messages.includes(description) ? description : 'OAuth interaction failed; details redacted';
  const context = error && typeof error === 'object' ? interactionFailures.get(error) : undefined;
  const binding = context && description === 'interaction session not found' ? `; cookie UID ${context.cookieMatchesRoute ? 'matches' : 'differs from'} route` : '';
  return {
    route: '/interaction/:uid',
    method: req.method === 'POST' ? 'POST' : req.method === 'GET' ? 'GET' : 'OTHER',
    error: {
      name: typeof value?.name === 'string' && names.includes(value.name) ? value.name : 'Error',
      status: typeof value?.status === 'number' && Number.isInteger(value.status) && value.status >= 400 && value.status <= 599 ? value.status : 500,
      message: context ? `${context.stage}: ${safeDescription}${binding}` : safeDescription,
    },
  };
}

/** Durable provider adapter. Namespace includes the issuer so tokens cannot cross deployments. */
function adapters(store: Store, prefix: string) {
  return class PersistentAdapter {
    private readonly ns: string;
    constructor(private readonly model: string) { this.ns = `${prefix}:${model}`; }
    private key(id: string) { return createHash('sha256').update(id).digest('hex'); }
    private readKey(key: string): Stored | undefined {
      const marker = store.get<{ expiresAt?: number }>(this.ns, key);
      if (!marker) return undefined;
      const payload = store.unseal<Payload>(this.ns, key);
      return payload ? { payload, expiresAt: marker.expiresAt } : undefined;
    }
    private read(id: string): Stored | undefined { return this.readKey(this.key(id)); }
    private write(key: string, item: Stored, ttl?: number) {
      store.seal(this.ns, key, item.payload);
      const vaultKey = JSON.stringify([this.ns, key]);
      store.put('vault', vaultKey, store.get('vault', vaultKey), ttl);
      store.put(this.ns, key, { expiresAt: item.expiresAt }, ttl);
    }
    private cleanKey(key: string, previous?: Stored) {
      store.delete(this.ns, key);
      store.delete('vault', JSON.stringify([this.ns, key]));
      for (const field of ['uid', 'userCode']) {
        const value = previous?.payload[field];
        if (typeof value === 'string' && store.get(`${this.ns}:${field}`, this.key(value)) === key) store.delete(`${this.ns}:${field}`, this.key(value));
      }
    }
    async upsert(id: string, payload: Payload, expiresIn?: number) {
      store.transaction(() => {
        if (this.model === 'Client' && !this.read(id) && store.list(this.ns).length >= 200) throw new errors.InvalidClientMetadata('Client registration capacity reached');
        const key = this.key(id);
        this.cleanKey(key, this.read(id));
        const ttl = this.model === 'Client' ? Math.min(expiresIn ?? 30*24*60*60,30*24*60*60) : expiresIn === undefined ? undefined : Math.max(1, Math.ceil(expiresIn));
        const expiresAt = ttl === undefined ? undefined : Date.now() + ttl * 1000;
        this.write(key, { payload, expiresAt }, ttl);
        for (const field of ['uid', 'userCode']) if (typeof payload[field] === 'string') store.put(`${this.ns}:${field}`, this.key(payload[field]), key, ttl);
        if (typeof payload.grantId === 'string') {
          const grantNs = `${prefix}:grants`;
          const members = (store.get<Member[]>(grantNs, payload.grantId) ?? []).filter(m => (m.expiresAt === undefined || m.expiresAt > Date.now()) && !(m.model === this.model && m.id === key));
          members.push({ model: this.model, id: key, expiresAt });
          const latest = members.some(m => m.expiresAt === undefined) ? undefined : Math.max(...members.map(m => m.expiresAt!));
          store.put(grantNs, payload.grantId, members, latest === undefined ? undefined : Math.max(1, Math.ceil((latest - Date.now()) / 1000)));
        }
      });
    }
    async find(id: string) { return this.read(id)?.payload; }
    async findByUid(uid: string) { const key = store.get<string>(`${this.ns}:uid`, this.key(uid)); return key ? this.readKey(key)?.payload : undefined; }
    async findByUserCode(code: string) { const key = store.get<string>(`${this.ns}:userCode`, this.key(code)); return key ? this.readKey(key)?.payload : undefined; }
    async destroy(id: string) { store.transaction(() => this.cleanKey(this.key(id), this.read(id))); }
    async consume(id: string) {
      store.transaction(() => {
        const item = this.read(id);
        if (!item) return;
        if (item.payload.consumed) throw new errors.InvalidGrant('Token already consumed');
        item.payload.consumed = Math.floor(Date.now() / 1000);
        this.write(this.key(id), item, item.expiresAt === undefined ? undefined : Math.max(1, Math.ceil((item.expiresAt - Date.now()) / 1000)));
      });
    }
    async revokeByGrantId(grantId: string) {
      store.transaction(() => {
        for (const member of store.get<Member[]>(`${prefix}:grants`, grantId) ?? []) {
          const adapter = new PersistentAdapter(member.model);
          adapter.cleanKey(member.id, adapter.readKey(member.id));
        }
        store.delete(`${prefix}:grants`, grantId);
      });
    }
  };
}

function validateClient(metadata: Payload, development: boolean) {
  const invalid = (message: string): never => { throw new errors.InvalidClientMetadata(message); };
  if (!['none', 'client_secret_post'].includes(metadata.token_endpoint_auth_method)) invalid('Only none and client_secret_post clients are supported');
  if (!Array.isArray(metadata.grant_types) || metadata.grant_types.some((v: string) => !['authorization_code', 'refresh_token'].includes(v)) || !metadata.grant_types.includes('authorization_code')) invalid('Only authorization_code and refresh_token grants are supported');
  if (!Array.isArray(metadata.response_types) || metadata.response_types.length !== 1 || metadata.response_types[0] !== 'code') invalid('Only code response_type is supported');
  if (!Array.isArray(metadata.redirect_uris) || metadata.redirect_uris.length < 1 || metadata.redirect_uris.length > 10) invalid('One to ten redirect URIs are required');
  for (const value of metadata.redirect_uris) {
    if (typeof value !== 'string') invalid('Invalid redirect URI');
    let url: URL;
    try { url = new URL(value); } catch { invalid('Invalid redirect URI'); }
    const host = url!.hostname.replace(/\.$/, '');
    if (url!.username || url!.password || url!.hash || value.includes('*')) invalid('Unsafe redirect URI');
    if (development && loopback(host) && ['http:', 'https:'].includes(url!.protocol)) continue;
    if (url!.protocol !== 'https:' || isIP(host.replace(/^\[|\]$/g, '')) || loopback(host) || !host.includes('.') || /\.(?:local|localhost|internal|lan|home|test|invalid)$/.test(host)) invalid('Redirect URI must use a public HTTPS host');
  }
  if (metadata.jwks_uri || metadata.sector_identifier_uri || metadata.request_uris?.length || metadata.jwks) invalid('Remote client keys and request objects are not supported');
}

/**
 * Portal contract: getPortalAccount returns the Store users record's immutable id.
 * /login must accept a validated local `return` path and preserve the portal session.
 * Mount before any generic body parser: oidc-provider parses its own OAuth bodies.
 */
export async function installIdentity(app: Express, options: { store: Store; baseUrl: string; getPortalAccount: (req: Request) => string | undefined }): Promise<{ provider: any; requireMcp: RequestHandler }> {
  const { store, getPortalAccount } = options;
  const baseUrl = options.baseUrl.replace(/\/$/, '');
  const parsed = new URL(baseUrl);
  const development = loopback(parsed.hostname);
  if ((!development && parsed.protocol !== 'https:') || !['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) throw new Error('BASE_URL must be an HTTPS origin (HTTP loopback is allowed for development)');
  const issuer = `${baseUrl}/oidc`, resource = `${baseUrl}/mcp`;
  const prefix = `oidc:${createHash('sha256').update(issuer).digest('hex').slice(0, 24)}`;
  let secrets = store.unseal<{ jwks: { keys: any[] }; cookieKeys: string[] }>(prefix, 'keys');
  if (!secrets) {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = privateKey.export({ format: 'jwk' });
    secrets = { jwks: { keys: [{ ...jwk, kid: randomBytes(16).toString('hex'), use: 'sig', alg: 'RS256' }] }, cookieKeys: [randomBytes(32).toString('base64url'), randomBytes(32).toString('base64url')] };
    store.seal(prefix, 'keys', secrets);
  }
  const activeAccount = (id: unknown) => {
    if (typeof id !== 'string') return undefined;
    const user = store.get<Payload>('users', id);
    return user && user.id === id && !user.disabled ? user : undefined;
  };
  const config: Configuration = {
    adapter: adapters(store, prefix),
    jwks: secrets.jwks,
    cookies: { keys: secrets.cookieKeys, short: { secure: !development }, long: { secure: !development } },
    clients: [],
    clientDefaults: { token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] },
    responseTypes: ['code'],
    scopes: ['openid', 'offline_access', ...MCP_SCOPES],
    claims: { openid: ['sub'], profile: ['name'] },
    pkce: { required: (_ctx, client) => client.clientAuthMethod === 'none' },
    clientAuthMethods: ['client_secret_post', 'none'],
    features: {
      devInteractions: { enabled: false },
      registration: { enabled: true },
      revocation: { enabled: true },
      resourceIndicators: {
        enabled: true,
        defaultResource: () => resource,
        useGrantedResource: () => true,
        getResourceServerInfo: (_ctx, indicator) => {
          if (indicator !== resource) throw new errors.InvalidTarget();
          return { scope: MCP_SCOPES.join(' '), audience: resource, accessTokenFormat: 'opaque', accessTokenTTL: 900 };
        },
      },
    },
    extraClientMetadata: { properties: ['mcp_policy'], validator: (_ctx, _key, _value, metadata) => validateClient(metadata, development) },
    interactions: { url: (_ctx, interaction) => `${baseUrl}/interaction/${interaction.uid}` },
    findAccount: async (_ctx, id) => {
      const user = activeAccount(id);
      if (!user) return undefined;
      return { accountId: id, claims: async () => ({ sub: id, name: user.name ?? id }) };
    },
    issueRefreshToken: (_ctx, client) => client.grantTypeAllowed('refresh_token'),
    expiresWithSession: () => false,
    ttl: { AccessToken: 900, AuthorizationCode: 120, RefreshToken: 604800, Grant: 604800, Interaction: 600, Session: 604800 },
  };
  const provider = new Provider(issuer, config);
  provider.proxy = !development;
  installOAuthTrace(app, provider, baseUrl);
  const rememberFailure = (req: Request, error: unknown, stage: InteractionStage) => {
    if (!error || typeof error !== 'object') return;
    const prefix = `${provider.cookieName('interaction')}=`;
    const cookie = req.headers.cookie?.split(';').map(part => part.trim()).find(part => part.startsWith(prefix))?.slice(prefix.length).replace(/^"(.*)"$/, '$1');
    interactionFailures.set(error, { stage, cookieMatchesRoute: typeof cookie === 'string' && cookie === req.params.uid });
  };
  const bindInteractionCookie = (req: Request, res: express.Response) => {
    const uid = req.params.uid;
    if (typeof uid !== 'string' || !/^[A-Za-z0-9_-]{1,200}$/.test(uid)) return;
    const name = provider.cookieName('interaction'), signatureName = `${name}.sig`;
    const parts = (req.headers.cookie ?? '').split(';').map(part => part.trim()).filter(Boolean);
    const cookies = parts.map(part => { const index = part.indexOf('='); return { part, name: part.slice(0, index), value: part.slice(index + 1).replace(/^"(.*)"$/, '$1') }; });
    const values = cookies.filter(cookie => cookie.name === name), signatures = cookies.filter(cookie => cookie.name === signatureName);
    if (values.length <= 1 && signatures.length <= 1) return;
    if (!values.some(cookie => cookie.value === uid)) return;
    // Cookie headers do not include Path and their order is not authoritative.
    // Retain the route's existing cookie only when its signature verifies using
    // the provider's signing keys. interactionDetails verifies it again below.
    const keys = (provider.createContext(req, res).cookies as unknown as { keys?: { verify(data: string, digest: string): boolean } }).keys;
    const signature = signatures.find(cookie => cookie.value.length <= 256 && keys?.verify(`${name}=${uid}`, cookie.value));
    if (!signature) throw new errors.SessionNotFound('interaction session id cookie not found');
    req.headers.cookie = [`${name}=${uid}`, `${signatureName}=${signature.value}`, ...cookies.filter(cookie => cookie.name !== name && cookie.name !== signatureName).map(cookie => cookie.part)].join('; ');
  };
  const metadata = { resource, authorization_servers: [issuer], scopes_supported: MCP_SCOPES, bearer_methods_supported: ['header'], resource_name: 'Karlancer MCP' };
  app.get(['/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-protected-resource'], (_req, res) => { res.set('Cache-Control', 'public, max-age=300'); res.json(metadata); });
  // RFC 8414 issuer path form, in addition to the provider's native discovery URL.
  app.get('/.well-known/oauth-authorization-server/oidc', (_req, res) => res.redirect(302, `${issuer}/.well-known/openid-configuration`));
  app.get('/interaction/:uid', async (req, res, next) => {
    let stage: InteractionStage = 'interactionDetails';
    try {
      res.set('Cache-Control', 'no-store');
      bindInteractionCookie(req, res);
      const interaction = await provider.interactionDetails(req, res);
      stage = 'consentValidation';
      if (req.params.uid !== interaction.uid) { res.status(403).send('Interaction mismatch'); return; }
      const accountId = getPortalAccount(req);
      if (!activeAccount(accountId)) { res.redirect(`/login?return=${encodeURIComponent(`/interaction/${interaction.uid}`)}`); return; }
      if (!['login', 'consent'].includes(interaction.prompt.name)) { res.status(400).send('Unsupported authorization prompt'); return; }
      if (interaction.prompt.name === 'consent' && interaction.session?.accountId !== accountId) { res.status(403).send('Sign in with the account that started authorization'); return; }
      const nonce = randomBytes(32).toString('base64url');
      store.put(`${prefix}:consent`, interaction.uid, { accountId, nonce: createHash('sha256').update(nonce).digest('hex') }, 600);
      stage = 'clientLookup';
      const client = await provider.Client.find(String(interaction.params.client_id));
      const redirectUri = interaction.params.redirect_uri;
      if (typeof redirectUri !== 'string' || !client?.redirectUris?.includes(redirectUri)) { res.status(400).send('Invalid authorization request'); return; }
      let callbackOrigin: string;
      try {
        const callback = new URL(redirectUri);
        if (!['http:', 'https:'].includes(callback.protocol) || callback.origin === 'null') { res.status(400).send('Invalid authorization request'); return; }
        callbackOrigin = callback.origin;
      } catch { res.status(400).send('Invalid authorization request'); return; }
      store.put(prefix + ':callback-origin', interaction.uid, callbackOrigin, 600);
      const contentSecurityPolicy = res.getHeader('Content-Security-Policy');
      if (typeof contentSecurityPolicy === 'string') {
        const directives = contentSecurityPolicy.split(';').map(value => value.trim()).filter(value => value && !/^form-action(?:\s|$)/i.test(value));
        directives.push("form-action 'self' " + callbackOrigin);
        res.setHeader('Content-Security-Policy', directives.join(';'));
      }
      res.setHeader('Cross-Origin-Opener-Policy', googleCallbackOrigins.has(callbackOrigin) ? 'unsafe-none' : 'same-origin');
      if (googleCallbackOrigins.has(callbackOrigin)) addOAuthCspReporting(res);
      res.type('html').send(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Authorize Karlancer MCP</title><h1>Authorize access</h1><p>Application: ${escapeHtml(client?.clientName ?? client?.clientId)}</p><p>Account: ${escapeHtml(activeAccount(accountId)?.name ?? accountId)}</p><p>Requested access: ${escapeHtml(interaction.params.scope)}</p><p>This application can use Karlancer MCP tools under your account. Proposals, replies and financial limits follow the policy you configure in the human portal.</p><form method="post" action="/interaction/${escapeHtml(interaction.uid)}"><input type="hidden" name="csrf" value="${nonce}"><button name="decision" value="approve">Continue and authorize</button><button name="decision" value="deny">Deny</button></form></html>`);
    } catch (error) { rememberFailure(req, error, stage); next(error); }
  });
  app.post('/interaction/:uid', express.urlencoded({ extended: false, limit: '8kb' }), async (req, res, next) => {
    let stage: InteractionStage = 'interactionDetails';
    try {
      res.set('Cache-Control', 'no-store');
      bindInteractionCookie(req, res);
      const interaction = await provider.interactionDetails(req, res);
      stage = 'consentValidation';
      if (req.params.uid !== interaction.uid) { res.status(403).send('Interaction mismatch'); return; }
      const accountId = getPortalAccount(req);
      const saved = store.get<{ accountId: string; nonce: string }>(`${prefix}:consent`, interaction.uid);
      const supplied = typeof req.body?.csrf === 'string' ? req.body.csrf : '';
      const digest = createHash('sha256').update(supplied).digest('hex');
      if (!saved || !activeAccount(accountId) || saved.accountId !== accountId || !timingSafeEqual(Buffer.from(digest), Buffer.from(saved.nonce))) { res.status(403).send('Invalid authorization request'); return; }
      if (req.get('origin') && req.get('origin') !== baseUrl) { res.status(403).send('Invalid origin'); return; }
      if (req.body.decision === 'approve' || req.body.decision === 'deny') {
        const storedOrigin = store.get<string>(prefix + ':callback-origin', interaction.uid);
        if (typeof storedOrigin === 'string') {
          try {
            const callback = new URL(storedOrigin);
            if (['http:', 'https:'].includes(callback.protocol) && callback.origin === storedOrigin) {
              const contentSecurityPolicy = res.getHeader('Content-Security-Policy');
              if (typeof contentSecurityPolicy === 'string') {
                const directives = contentSecurityPolicy.split(';').map(value => value.trim()).filter(value => value && !/^form-action(?:\s|$)/i.test(value));
                directives.push("form-action 'self' " + storedOrigin);
                res.setHeader('Content-Security-Policy', directives.join(';'));
              }
              res.setHeader('Cross-Origin-Opener-Policy', googleCallbackOrigins.has(storedOrigin) ? 'unsafe-none' : 'same-origin');
              if (googleCallbackOrigins.has(storedOrigin)) addOAuthCspReporting(res);
            }
          } catch {}
        }
      }
      store.delete(`${prefix}:consent`, interaction.uid);
      if (req.body.decision === 'deny') { stage = 'interactionFinished'; await provider.interactionFinished(req, res, { error: 'access_denied', error_description: 'User denied access' }, { mergeWithLastSubmission: false }); return; }
      if (req.body.decision !== 'approve') { res.status(400).send('Choose approve or deny'); return; }
      if (interaction.prompt.name === 'login') {
        stage = 'interactionFinished';
        await provider.interactionFinished(req, res, { login: { accountId: accountId! } }, { mergeWithLastSubmission: false }); return;
      }
      if (interaction.prompt.name !== 'consent' || interaction.session?.accountId !== accountId) { res.status(403).send('Account mismatch'); return; }
      stage = 'grantLookup';
      const grant = interaction.grantId ? await provider.Grant.find(interaction.grantId) : new provider.Grant({ accountId: accountId!, clientId: String(interaction.params.client_id) });
      if (!grant || grant.accountId !== accountId || grant.clientId !== interaction.params.client_id) { res.status(403).send('Grant mismatch'); return; }
      const details = interaction.prompt.details as Payload;
      if (details.missingOIDCScope) grant.addOIDCScope(details.missingOIDCScope.join(' '));
      if (details.missingOIDCClaims) grant.addOIDCClaims(details.missingOIDCClaims);
      for (const [indicator, scopes] of Object.entries(details.missingResourceScopes ?? {})) {
        if (indicator !== resource) throw new errors.InvalidTarget();
        grant.addResourceScope(indicator, (scopes as string[]).join(' '));
      }
      stage = 'grantSave';
      const grantId = await grant.save();
      stage = 'interactionFinished';
      await provider.interactionFinished(req, res, { consent: { grantId } }, { mergeWithLastSubmission: true });
    } catch (error) { rememberFailure(req, error, stage); next(error); }
  });
  const googleCallbackOrigins = new Set([
    'https://oauth-redirect.googleusercontent.com',
    'https://oauth-redirect-sandbox.googleusercontent.com',
    'https://oauth-redirect-test.googleusercontent.com',
  ]);
  app.get('/oidc/auth', async (req, res, next) => {
    try {
      const clientId = typeof req.query.client_id === 'string' ? req.query.client_id : undefined;
      const redirectUri = typeof req.query.redirect_uri === 'string' ? req.query.redirect_uri : undefined;
      if (clientId && redirectUri) {
        const client = await provider.Client.find(clientId);
        if (client?.redirectUris?.includes(redirectUri)) {
          const callback = new URL(redirectUri);
          if (googleCallbackOrigins.has(callback.origin)) {
            res.setHeader('Cross-Origin-Opener-Policy', 'unsafe-none');
            addOAuthCspReporting(res);
          }
        }
      }
    } catch {
      // Let oidc-provider handle malformed or unknown authorization requests.
    }
    next();
  });
  app.get('/oidc/auth/:uid', (req, res, next) => {
    let callbackOrigin: string | undefined;
    try {
      const callbackOriginKey = prefix + ':callback-origin';
      const storedOrigin = store.get<string>(callbackOriginKey, req.params.uid);
      store.delete(callbackOriginKey, req.params.uid);
      if (typeof storedOrigin === 'string') {
        const callback = new URL(storedOrigin);
        if (['http:', 'https:'].includes(callback.protocol) && callback.origin === storedOrigin) callbackOrigin = storedOrigin;
      }
    } catch {}
    const contentSecurityPolicy = res.getHeader('Content-Security-Policy');
    if (callbackOrigin) res.setHeader('Cross-Origin-Opener-Policy', googleCallbackOrigins.has(callbackOrigin) ? 'unsafe-none' : 'same-origin');
    if (callbackOrigin && typeof contentSecurityPolicy === 'string') {
      const directives = contentSecurityPolicy.split(';').map(value => value.trim()).filter(value => value && !/^form-action(?:\s|$)/i.test(value));
      directives.push("form-action 'self' " + callbackOrigin);
      res.setHeader('Content-Security-Policy', directives.join(';'));
    }
    if (callbackOrigin && googleCallbackOrigins.has(callbackOrigin)) addOAuthCspReporting(res);
    next();
  });
  provider.use(async (ctx: any, next: () => Promise<unknown>) => {
    await next();
    if (ctx.status !== 303 || ctx.oidc?.route !== 'resume' || ctx.oidc.responseMode !== 'query') return;
    const redirectUri = ctx.oidc.params?.redirect_uri;
    const code = ctx.oidc.entities?.AuthorizationCode;
    if (typeof redirectUri !== 'string' || !code || !ctx.oidc.client?.redirectUris?.includes(redirectUri)) return;
    const location = ctx.response.get('Location');
    let registered: URL, target: URL;
    try { registered = new URL(redirectUri); target = new URL(location); } catch { return; }
    if (!googleCallbackOrigins.has(registered.origin) || target.origin !== registered.origin || target.pathname !== registered.pathname || target.hash || target.username || target.password) return;
    if (target.searchParams.get('code') !== code.jti || target.searchParams.get('iss') !== provider.issuer) return;
    const state = ctx.oidc.params.state;
    if (typeof state === 'string' ? target.searchParams.get('state') !== state : target.searchParams.has('state')) return;
    // Commit a document before navigating to Google's callback. Browser form-action
    // checks otherwise remain active across Google's subsequent redirect chain.
    const policy = ctx.response.get('Content-Security-Policy');
    const directives = typeof policy === 'string' ? policy.split(';').map((value: string) => value.trim()).filter((value: string) => value && !/^form-action(?:\s|$)/i.test(value)) : [];
    ctx.set('Content-Security-Policy', directives.concat("form-action 'self'").join(';'));
    ctx.set('Cross-Origin-Opener-Policy', 'unsafe-none');
    ctx.set('Cache-Control', 'no-store');
    ctx.remove('Location');
    ctx.status = 200;
    ctx.type = 'html';
    const destination = escapeHtml(location);
    ctx.body = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="refresh" content="0;url=${destination}"><title>Completing connection</title><h1>Completing connection</h1><p><a id="oauth-callback" href="${destination}">Continue to Google</a></p></html>`;
    traceGoogleHandoff(ctx.req, location);
  });
  app.use('/oidc', provider.callback());
  const requireMcp: RequestHandler = async (req, res, next) => {
    const reject = () => { res.set('WWW-Authenticate', `Bearer resource_metadata="${baseUrl}/.well-known/oauth-protected-resource/mcp"`); res.status(401).json({ error: 'invalid_token' }); };
    try {
      const match = /^Bearer ([A-Za-z0-9._~+\/-]+=*)$/i.exec(req.get('authorization') ?? '');
      if (!match || match[1].length > 4096) { reject(); return; }
      const token = await provider.AccessToken.find(match[1]);
      if (!token || token.isExpired || !token.accountId || !token.clientId || !activeAccount(token.accountId) || token.aud !== resource || token.tokenType !== 'Bearer' || !token.scopes.has('mcp')) { reject(); return; }
      const client=await provider.Client.find(token.clientId);
      if(!client){reject();return;}
      (req as any).auth = { token: match[1], clientId: token.clientId, scopes: [...token.scopes], expiresAt: token.exp, extra: { tenantId: token.accountId, clientClass: client.clientName==='Google'?'google':client.clientAuthMethod==='none'?'public':'confidential' } };
      next();
    } catch { reject(); }
  };
  return { provider, requireMcp };
}
