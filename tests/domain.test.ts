import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';
import {DomainService} from '../src/domain.js';
import {KarlancerError} from '../src/karlancer.js';
import {Store} from '../src/store.js';

test('maps upstream failure to a safe request-correlated MCP domain error', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'karlancer-domain-'));
  const store = new Store(join(directory, 'state.sqlite'), Buffer.alloc(32, 7));
  const logs: Array<Record<string, unknown>> = [];
  try {
    store.seal('tenant', 'karlancer', {accountId: 713391, token: 'never-log-this-token'});
    const domain = new DomainService({
      store,
      logger: event => logs.push(event),
      clientFor: () => ({
        getProfile: async () => ({user: {id: 713391}}),
        searchProjects: async () => { throw new KarlancerError('upstream body: never log this', 'RATE_LIMITED', 429); },
      }) as any,
    });

    await assert.rejects(domain.execute('tenant', 'search_projects', {}), error => {
      const value = error as {code?: string; requestId?: string; message?: string};
      return value.code === 'UPSTREAM_RATE_LIMITED' && typeof value.requestId === 'string' && !value.message?.includes('upstream body');
    });
    assert.equal(logs.length, 1);
    assert.equal(logs[0]?.tool, 'search_projects');
    assert.equal(logs[0]?.request_path, 'domain');
    assert.equal(logs[0]?.http_status, 429);
    assert.equal(logs[0]?.error_kind, 'UPSTREAM_RATE_LIMITED');
    assert.equal(JSON.stringify(logs).includes('never-log-this-token'), false);
    assert.equal(JSON.stringify(logs).includes('upstream body'), false);
  } finally {
    store.close();
    rmSync(directory, {recursive: true, force: true});
  }
});

function proposalPolicy(overrides: Record<string, unknown> = {}) {
  return {
    version: 1,
    proposalsEnabled: true,
    repliesEnabled: false,
    minNetIncome: 0,
    maxDurationDays: 30,
    dailyMaxProposals: 5,
    dailyMaxTokens: 20,
    dailyMaxStatistics: 0,
    cashPremiumLimit: 0,
    allowIncludedPromotions: false,
    aiFields: [],
    ...overrides,
  };
}

function proposalClient() {
  return {
    getProfile: async () => ({user: {id: 713391}}),
    getProject: async () => ({id: 336227, status: 'pending', min_budget: 1000000, max_budget: 5000000, bid_token_cost: 4, employer_id: 99, skills: [{id: 7}]}),
    getPlans: async () => ({commission_percent: 10, available_tokens: 8}),
    submitBid: async () => { throw new Error('prepare must not submit a bid'); },
  };
}

test('prepare_proposal reuses an equivalent unexpired draft and enforces the proposal policy', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'karlancer-draft-'));
  const store = new Store(join(directory, 'state.sqlite'), Buffer.alloc(32, 8));
  const input = {
    project_ref: 336227,
    description: 'برای این پروژه، برنامه اجرا، کنترل کیفیت و تحویل مرحله‌ای را به‌صورت شفاف ارائه می‌کنم.',
    milestones: [{description: 'پیاده‌سازی نسخه PWA', duration: 2, budget: 4500000}],
  };
  try {
    store.seal('tenant', 'karlancer', {accountId: 713391, token: 'test-token'});
    store.put('policy', 'tenant', proposalPolicy());
    const domain = new DomainService({store, clientFor: () => proposalClient() as any, logger: () => {}});

    const first = await domain.execute('tenant', 'prepare_proposal', input);
    const retry = await domain.execute('tenant', 'prepare_proposal', input);
    assert.equal(first.status, 'PREPARED');
    assert.equal(typeof first.draft_id, 'string');
    assert.equal(typeof first.expires_at, 'string');
    assert.equal(first.estimate.budget_toman, 4500000);
    assert.equal(first.estimate.duration_days, 2);
    assert.equal(retry.draft_id, first.draft_id);

    const [{key: fingerprint}] = store.list<string>('draft-fingerprint:tenant');
    store.delete('draft-fingerprint:tenant', fingerprint);
    const recovered = await domain.execute('tenant', 'prepare_proposal', input);
    assert.equal(recovered.draft_id, first.draft_id);

    store.put('policy', 'tenant', proposalPolicy({proposalsEnabled: false}));
    await assert.rejects(domain.execute('tenant', 'prepare_proposal', input), error => (error as {code?: string}).code === 'POLICY_NOT_CONFIGURED');
  } finally {
    store.close();
    rmSync(directory, {recursive: true, force: true});
  }
});

test('submit_proposal validates its contract and reuses one operation for an idempotency key', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'karlancer-submit-'));
  const store = new Store(join(directory, 'state.sqlite'), Buffer.alloc(32, 9));
  const input = {
    project_ref: 336227,
    description: 'برای این پروژه، برنامه اجرا، کنترل کیفیت و تحویل مرحله‌ای را به‌صورت شفاف ارائه می‌کنم.',
    milestones: [{description: 'پیاده‌سازی نسخه PWA', duration: 2, budget: 4500000}],
  };
  let submitCalls = 0;
  let submitted: Record<string, any> | undefined;
  try {
    store.seal('tenant', 'karlancer', {accountId: 713391, token: 'test-token'});
    store.put('policy', 'tenant', proposalPolicy());
    const client = {
      getProfile: async () => ({user: {id: 713391}}),
      getProject: async () => ({id: 336227, status: 'pending', min_budget: 1000000, max_budget: 5000000, bid_token_cost: 4, employer_id: 99, skills: [{id: 7}]}),
      getPlans: async () => ({commission_percent: 10, available_tokens: 8}),
      submitBid: async (body: Record<string, any>) => { submitCalls++; submitted = body; return {id: 909}; },
      listProposals: async () => [{id: 909, project_id: 336227, freelancer_id: 713391}],
      getProposal: async () => ({id: 909, project_id: 336227, freelancer_id: 713391, description: submitted?.description, milestones: submitted?.milestones}),
    };
    const domain = new DomainService({store, clientFor: () => client as any, logger: () => {}});

    const draft = await domain.execute('tenant', 'prepare_proposal', input);
    await assert.rejects(domain.execute('tenant', 'submit_proposal', {draft_id: draft.draft_id, idempotency_key: ''}), error => (error as {code?: string}).code === 'INVALID_INPUT');
    const first = await domain.execute('tenant', 'submit_proposal', {draft_id: draft.draft_id, idempotency_key: 'fixture-submit-key'});
    const retry = await domain.execute('tenant', 'submit_proposal', {draft_id: draft.draft_id, idempotency_key: 'fixture-submit-key'});
    assert.equal(first.status, 'CONFIRMED');
    assert.equal(retry.operation_id, first.operation_id);
    assert.equal(submitCalls, 1);
  } finally {
    store.close();
    rmSync(directory, {recursive: true, force: true});
  }
});

test('prepare_proposal blocks a budget above the verified project ceiling', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'karlancer-budget-cap-'));
  const store = new Store(join(directory, 'state.sqlite'), Buffer.alloc(32, 10));
  try {
    store.seal('tenant', 'karlancer', {accountId: 713391, token: 'test-token'});
    store.put('policy', 'tenant', proposalPolicy());
    const domain = new DomainService({
      store,
      clientFor: () => ({
        getProfile: async () => ({user: {id: 713391}}),
        getProject: async () => ({id: 336227, status: 'pending', min_budget: 1000000, max_budget: 4499999, bid_token_cost: 4, employer_id: 99, skills: [{id: 7}]}),
        getPlans: async () => ({commission_percent: 10, available_tokens: 8}),
      }) as any,
      logger: () => {},
    });
    await assert.rejects(domain.execute('tenant', 'prepare_proposal', {
      project_ref: 336227,
      description: 'برای این پروژه، برنامه اجرا، کنترل کیفیت و تحویل مرحله‌ای را به‌صورت شفاف ارائه می‌کنم.',
      milestones: [{description: 'پیاده‌سازی نسخه PWA', duration: 2, budget: 4500000}],
    }), error => (error as {code?: string}).code === 'BUDGET_CAP_EXCEEDED');
  } finally {
    store.close();
    rmSync(directory, {recursive: true, force: true});
  }
});
