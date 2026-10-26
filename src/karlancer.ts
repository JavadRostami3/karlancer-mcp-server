/** Error details intentionally contain no arbitrary upstream body, headers or cause. */
export class KarlancerError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly status: number,
    public readonly details: Readonly<Record<string, number | boolean>> = {},
  ) {
    super(message);
    this.name = 'KarlancerError';
  }
}

export interface ProjectSearch {
  q?: string;
  page?: number;
  order?: string;
  minPrice?: number;
  maxPrice?: number;
  skillIds?: number[];
  isUrgent?: boolean;
  lowCompetition?: boolean;
}

export interface RequestContext {
  tool: string;
  requestId: string;
}

export type ResponseValidation = 'valid' | 'invalid' | 'not_attempted';

export interface SafeTelemetryEvent {
  event: 'karlancer_upstream_request';
  tool: string;
  request_id: string;
  request_path: string;
  http_status: number | null;
  duration_ms: number;
  response_validation: ResponseValidation;
  error_kind?: string;
}

interface ClientOptions {
  token?: string;
  /** Constructor injection for local HTTP fixture tests; never accept from tool input. */
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  requestContext?: RequestContext;
  /** Receives allowlisted diagnostics only; never receives headers, bodies, or credentials. */
  telemetry?: (event: SafeTelemetryEvent) => void;
}

export class KarlancerClient {
  private readonly authorization?: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly requestContext?: RequestContext;
  private readonly telemetry: (event: SafeTelemetryEvent) => void;

  constructor({ token, baseUrl = 'https://www.karlancer.com', fetchImpl = fetch, requestContext, telemetry }: ClientOptions = {}) {
    const normalized = token?.trim().replace(/^Bearer\s+/i, '');
    this.authorization = normalized ? `Bearer ${normalized}` : undefined;
    this.baseUrl = baseUrl;
    this.fetchImpl = fetchImpl;
    this.requestContext = requestContext;
    this.telemetry = telemetry ?? (requestContext ? event => console.info(JSON.stringify(event)) : () => {});
  }

  private emit(requestPath: string, startedAt: number, status: number | undefined, validation: ResponseValidation, errorKind?: string): void {
    this.telemetry({
      event: 'karlancer_upstream_request',
      tool: this.requestContext?.tool ?? 'unknown',
      request_id: this.requestContext?.requestId ?? 'unknown',
      request_path: requestPath,
      http_status: status ?? null,
      duration_ms: Date.now() - startedAt,
      response_validation: validation,
      ...(errorKind ? {error_kind: errorKind} : {}),
    });
  }

  private httpErrorCode(status: number): string {
    if (status === 401) return 'UNAUTHORIZED';
    if (status === 402) return 'PAYMENT_REQUIRED';
    if (status === 429) return 'RATE_LIMITED';
    if (status === 400 || status === 422) return 'VALIDATION_ERROR';
    if (status >= 500) return 'UPSTREAM_SERVER_ERROR';
    return 'UPSTREAM_REQUEST_REJECTED';
  }

  private async request(path: string, method = 'GET', body?: Record<string, unknown>, query?: URLSearchParams, requestPath = path): Promise<any> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new DOMException('Request deadline exceeded', 'TimeoutError')), 25_000);
    const startedAt = Date.now();
    let status: number | undefined;
    let validation: ResponseValidation = 'not_attempted';
    let errorKind: string | undefined;
    try {
      const url = new URL(path, this.baseUrl);
      if (query) url.search = query.toString();
      const headers: Record<string, string> = { Accept: 'application/json' };
      if (this.authorization) headers.Authorization = this.authorization;
      if (body !== undefined) headers['Content-Type'] = 'application/json';
      const response = await this.fetchImpl(url, {
        method, headers, body: body === undefined ? undefined : JSON.stringify(body),
        redirect: 'error', signal: controller.signal,
      });
      status = response.status;
      if (!response.ok) {
        // Never echo upstream error text: it can contain credentials or login codes.
        const code = this.httpErrorCode(response.status);
        errorKind = code;
        throw new KarlancerError('Karlancer rejected the request', code, response.status, { upstreamStatus: response.status });
      }
      let envelope: any;
      try { envelope = await response.json(); }
      catch (error) {
        if (controller.signal.aborted) throw error;
        validation = 'invalid';
        errorKind = 'MALFORMED_RESPONSE';
        throw new KarlancerError('Karlancer returned invalid JSON', 'MALFORMED_RESPONSE', response.status);
      }
      if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope) ||
          !Object.prototype.hasOwnProperty.call(envelope, 'data') || envelope.status === false || envelope.status === 'error') {
        validation = 'invalid';
        errorKind = 'MALFORMED_RESPONSE';
        throw new KarlancerError('Karlancer returned an invalid response envelope', 'MALFORMED_RESPONSE', response.status);
      }
      validation = 'valid';
      return envelope.data;
    } catch (error) {
      if (error instanceof KarlancerError) { errorKind ??= error.code; throw error; }
      const timeout = controller.signal.aborted || (error instanceof Error && error.name === 'TimeoutError');
      errorKind = timeout ? 'TIMEOUT' : 'NETWORK_ERROR';
      throw new KarlancerError(
        timeout ? 'Karlancer request timed out; delivery is unknown' : 'Karlancer network request failed; delivery is unknown',
        errorKind, 0,
      );
    } finally {
      clearTimeout(timer);
      this.emit(requestPath, startedAt, status, validation, errorKind);
    }
  }

  getProfile(): Promise<any> { return this.request('/api/profile'); }

  searchProjects(input: ProjectSearch): Promise<any> {
    const query = new URLSearchParams({ q: input.q ?? '', page: String(input.page ?? 1), order: input.order ?? 'newest' });
    if (input.minPrice !== undefined) query.set('price[min]', String(input.minPrice));
    if (input.maxPrice !== undefined) query.set('price[max]', String(input.maxPrice));
    input.skillIds?.forEach((id, index) => query.set(`skillIds[${index}]`, String(id)));
    if (input.isUrgent !== undefined) query.set('is_urgent', input.isUrgent ? '1' : '0');
    if (input.lowCompetition !== undefined) query.set('low_competition', input.lowCompetition ? '1' : '0');
    if (this.authorization) query.set('logged_in', '1');
    return this.request('/api/publics/search/projects', 'GET', undefined, query);
  }

  private numericProjectId(ref: string | number): string | undefined {
    const candidate = typeof ref === 'number' ? String(ref) : ref;
    if (!/^[1-9]\d*$/.test(candidate)) return undefined;
    return Number.isSafeInteger(Number(candidate)) ? candidate : undefined;
  }

  private async resolveProjectSlug(id: string): Promise<string> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new DOMException('Request deadline exceeded', 'TimeoutError')), 25_000);
    const startedAt = Date.now();
    let status: number | undefined;
    let validation: ResponseValidation = 'not_attempted';
    let errorKind: string | undefined;
    try {
      const source = new URL(`/projects/${encodeURIComponent(id)}`, this.baseUrl);
      const response = await this.fetchImpl(source, {
        method: 'GET', headers: {Accept: 'text/html'}, redirect: 'manual', signal: controller.signal,
      });
      status = response.status;
      if (![301, 302, 307, 308].includes(response.status)) {
        validation = 'invalid';
        errorKind = 'INVALID_PROJECT_REDIRECT';
        throw new KarlancerError('Karlancer did not resolve the project ID', 'INVALID_PROJECT_REDIRECT', response.status, {upstreamStatus: response.status});
      }
      const location = response.headers.get('location');
      if (!location) {
        validation = 'invalid';
        errorKind = 'INVALID_PROJECT_REDIRECT';
        throw new KarlancerError('Karlancer returned a project redirect without a location', 'INVALID_PROJECT_REDIRECT', response.status, {upstreamStatus: response.status});
      }
      let target: URL;
      try { target = new URL(location, source); }
      catch {
        validation = 'invalid';
        errorKind = 'INVALID_PROJECT_REDIRECT';
        throw new KarlancerError('Karlancer returned an invalid project redirect', 'INVALID_PROJECT_REDIRECT', response.status, {upstreamStatus: response.status});
      }
      const parts = target.pathname.split('/').filter(Boolean);
      if (target.origin !== source.origin || target.search || target.hash || parts.length !== 2 || parts[0] !== 'projects') {
        validation = 'invalid';
        errorKind = 'INVALID_PROJECT_REDIRECT';
        throw new KarlancerError('Karlancer returned an unsupported project redirect', 'INVALID_PROJECT_REDIRECT', response.status, {upstreamStatus: response.status});
      }
      let slug: string;
      try { slug = decodeURIComponent(parts[1]); }
      catch {
        validation = 'invalid';
        errorKind = 'INVALID_PROJECT_REDIRECT';
        throw new KarlancerError('Karlancer returned an invalid project redirect', 'INVALID_PROJECT_REDIRECT', response.status, {upstreamStatus: response.status});
      }
      if (!slug || slug.length > 200) {
        validation = 'invalid';
        errorKind = 'INVALID_PROJECT_REDIRECT';
        throw new KarlancerError('Karlancer returned an invalid project redirect', 'INVALID_PROJECT_REDIRECT', response.status, {upstreamStatus: response.status});
      }
      validation = 'valid';
      return slug;
    } catch (error) {
      if (error instanceof KarlancerError) throw error;
      const timeout = controller.signal.aborted || (error instanceof Error && error.name === 'TimeoutError');
      errorKind = timeout ? 'TIMEOUT' : 'NETWORK_ERROR';
      throw new KarlancerError(
        timeout ? 'Karlancer project ID resolution timed out' : 'Karlancer project ID resolution failed',
        errorKind, 0,
      );
    } finally {
      clearTimeout(timer);
      this.emit('/projects/:project_id', startedAt, status, validation, errorKind);
    }
  }

  getProject(ref: string | number): Promise<any> {
    const id = this.numericProjectId(ref);
    return id === undefined
      ? this.request(`/api/publics/projects/${encodeURIComponent(String(ref))}`, 'GET', undefined, undefined, '/api/publics/projects/:project_ref')
      : this.resolveProjectSlug(id).then(slug => this.request(`/api/publics/projects/${encodeURIComponent(slug)}`, 'GET', undefined, undefined, '/api/publics/projects/:project_ref'));
  }

  getPlans(context?: { employerId: number; skillIds: number[]; projectId: number }): Promise<any> {
    if (!context) return this.request('/api/plans');
    return this.request(`/api/plans/${context.employerId}/skills`, 'GET', undefined, new URLSearchParams({
      ids: context.skillIds.join(','), project_id: String(context.projectId), t: String(Date.now()),
    }), '/api/plans/:employer_id/skills');
  }

  listProposals(page = 1, status?: string): Promise<any> {
    const query = new URLSearchParams({page: String(page)});
    if (status) query.set('status', status);
    return this.request('/api/bids/', 'GET', undefined, query);
  }

  getProposal(id: number): Promise<any> { return this.request(`/api/bids/${id}`, 'GET', undefined, undefined, '/api/bids/:proposal_id'); }

  listConversations(page = 1, search = '', unreadOnly = false): Promise<any> {
    return this.request(unreadOnly ? '/api/rooms-unread/' : '/api/rooms/', 'GET', undefined,
      new URLSearchParams({ page: String(page), search }));
  }

  getMessages(roomId: number, page = 1): Promise<any> {
    return this.request(`/api/rooms/${roomId}/messages-pg`, 'GET', undefined, new URLSearchParams({ page: String(page) }), '/api/rooms/:room_id/messages-pg');
  }

  submitBid(body: Record<string, unknown>): Promise<any> { return this.request('/api/bids', 'POST', body); }
  updateBid(body: Record<string, unknown>): Promise<any> { return this.request('/api/bids', 'PATCH', body); }
  sendMessage(body: Record<string, unknown>): Promise<any> { return this.request('/api/messages', 'POST', body); }
  markRead(roomId: number): Promise<any> { return this.request(`/api/rooms/${roomId}/read`, 'POST', undefined, undefined, '/api/rooms/:room_id/read'); }
  competitionStatistics(projectId: number): Promise<any> { return this.request(`/api/projects/${projectId}/stat`, 'GET', undefined, undefined, '/api/projects/:project_id/stat'); }

  requestOtp(phone: string): Promise<any> {
    return this.request('/api/login/otp', 'POST', { phone, verify_token: Number(phone.slice(-9)) * 47 % 1236987 });
  }

  /** Caller must keep this result in the trusted portal; it contains an access token. */
  verifyOtp(phone: string, code: string): Promise<any> {
    return this.request('/api/login/otp', 'POST', {
      phone, token: code, role: 'freelancer', verify_token: Number(phone.slice(-9)) * 47 % 1236987,
    });
  }
}
