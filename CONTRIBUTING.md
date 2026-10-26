# Contributing

1. Open an issue with an anonymized reproduction or a scoped enhancement.
2. Fork the repository, create a topic branch and submit a focused pull request.
3. Run **npm ci**, **npm run build**, and **npm test** with Node.js 24+.
4. Include regression tests for behavior changes, especially OAuth, tenant isolation, policy enforcement and idempotency.
5. Explain risks and upstream compatibility changes in the PR.

Never contribute real cookies, credentials, OTPs, messages, customer data, .env files, server traces or non-redistributable font assets. Security issues should be reported privately per [SECURITY.md](SECURITY.md). Changes that bypass platform access controls or enable unauthorized payments are not accepted.
