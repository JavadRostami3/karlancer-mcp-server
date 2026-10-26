import assert from 'node:assert/strict';
import test from 'node:test';
import { KarlancerClient } from '../src/karlancer.js';

const envelope = (data: unknown, status = 200) => new Response(JSON.stringify({status: 'success', data}), {
  status,
  headers: {'content-type': 'application/json'},
});

test('getProject resolves numeric IDs and numeric strings through a validated redirect before reading details', async () => {
  const calls: Array<{path: string; redirect?: RequestRedirect}> = [];
  const client = new KarlancerClient({
    baseUrl: 'https://www.karlancer.com',
    fetchImpl: async (url, init) => {
      const parsed = new URL(url);
      calls.push({path: parsed.pathname, redirect: init?.redirect});
      if (parsed.pathname === '/projects/336227') {
        return new Response(null, {status: 301, headers: {location: '/projects/resolved-project'}});
      }
      if (parsed.pathname === '/api/publics/projects/resolved-project') return envelope({id: 336227});
      throw new Error(`Unexpected request ${parsed.pathname}`);
    },
  });

  await assert.deepEqual(await client.getProject(336227), {id: 336227});
  await assert.deepEqual(await client.getProject('336227'), {id: 336227});
  assert.deepEqual(calls, [
    {path: '/projects/336227', redirect: 'manual'},
    {path: '/api/publics/projects/resolved-project', redirect: 'error'},
    {path: '/projects/336227', redirect: 'manual'},
    {path: '/api/publics/projects/resolved-project', redirect: 'error'},
  ]);
});

test('getProject sends valid slugs directly with URL encoding', async () => {
  const slug = 'اپ تحت پسوند';
  let path = '';
  const client = new KarlancerClient({
    baseUrl: 'https://www.karlancer.com',
    fetchImpl: async url => {
      path = new URL(url).pathname;
      return envelope({id: 1});
    },
  });

  await client.getProject(slug);
  assert.equal(path, `/api/publics/projects/${encodeURIComponent(slug)}`);
});

test('getProject rejects a numeric redirect outside the Karlancer project route', async () => {
  const client = new KarlancerClient({
    baseUrl: 'https://www.karlancer.com',
    fetchImpl: async () => new Response(null, {status: 302, headers: {location: 'https://attacker.invalid/projects/slug'}}),
  });

  await assert.rejects(client.getProject(336227), error => (error as {code?: string}).code === 'INVALID_PROJECT_REDIRECT');
});

test('getProject classifies a malformed numeric redirect as a project-resolution error', async () => {
  const client = new KarlancerClient({
    baseUrl: 'https://www.karlancer.com',
    fetchImpl: async () => new Response(null, {status: 302, headers: {location: 'http://['}}),
  });

  await assert.rejects(client.getProject(336227), error => (error as {code?: string}).code === 'INVALID_PROJECT_REDIRECT');
});

test('listProposals omits a missing status filter but encodes a supplied status filter', async () => {
  const searches: string[] = [];
  const client = new KarlancerClient({
    baseUrl: 'https://www.karlancer.com',
    fetchImpl: async url => {
      searches.push(new URL(url).search);
      return envelope({total: 0, data: []});
    },
  });

  await client.listProposals(1);
  await client.listProposals(2, 'pending');
  assert.deepEqual(searches, ['?page=1', '?page=2&status=pending']);
});

test('classifies upstream failures and emits only allowlisted request telemetry', async () => {
  const events: Array<Record<string, unknown>> = [];
  const client = new KarlancerClient({
    token: 'super-secret-token',
    baseUrl: 'https://www.karlancer.com',
    telemetry: event => events.push(event),
    fetchImpl: async () => new Response(JSON.stringify({status: 'error', data: 'never log this body'}), {status: 429}),
  });

  await assert.rejects(client.getProfile(), error => (error as {code?: string}).code === 'RATE_LIMITED');
  assert.deepEqual(events, [{
    event: 'karlancer_upstream_request',
    tool: 'unknown',
    request_id: 'unknown',
    request_path: '/api/profile',
    http_status: 429,
    response_validation: 'not_attempted',
    error_kind: 'RATE_LIMITED',
    duration_ms: events[0]?.duration_ms,
  }]);
  assert.equal(typeof events[0]?.duration_ms, 'number');
  assert.equal(JSON.stringify(events).includes('super-secret-token'), false);
  assert.equal(JSON.stringify(events).includes('never log this body'), false);
});

test('uses distinct safe codes for validation, server, malformed, timeout, and network failures', async () => {
  const cases: Array<{name: string; response?: Response; error?: Error; expected: string}> = [
    {name: 'validation', response: new Response('{}', {status: 422}), expected: 'VALIDATION_ERROR'},
    {name: 'server', response: new Response('{}', {status: 503}), expected: 'UPSTREAM_SERVER_ERROR'},
    {name: 'malformed', response: new Response('{', {status: 200}), expected: 'MALFORMED_RESPONSE'},
    {name: 'timeout', error: new DOMException('deadline', 'TimeoutError'), expected: 'TIMEOUT'},
    {name: 'network', error: new TypeError('socket closed'), expected: 'NETWORK_ERROR'},
  ];
  for (const item of cases) {
    const client = new KarlancerClient({
      fetchImpl: async () => {
        if (item.error) throw item.error;
        return item.response!;
      },
    });
    await assert.rejects(client.getProfile(), error => (error as {code?: string}).code === item.expected, item.name);
  }
});
