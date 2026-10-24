import test from 'node:test';
import assert from 'node:assert/strict';
import { formatGeminiError, checkGemini } from '../gemini.mjs';

test('429 diagnostics identify zero quota and redact credentials', () => {
  const key = 'AIzaPrivateTestCredential';
  const text = formatGeminiError(429, { error: { status: 'RESOURCE_EXHAUSTED', message: `do not echo ${key}`, details: [{ violations: [{ quotaMetric: 'generate_content_free_tier_requests', quotaId: key, quotaValue: '0' }] }, { retryDelay: '30s' }] } }, key);
  assert.match(text, /limit=0/);
  assert.match(text, /retryAfter=30s/);
  assert.doesNotMatch(text, /AIzaPrivateTestCredential/);
  assert.match(text, /description=do not echo \[REDACTED\]/);
});
test('connectivity check sends one small request and never executes workflow tools', async t => {
  const previous = { key: process.env.GEMINI_API_KEY, model: process.env.GEMINI_MODEL };
  process.env.GEMINI_API_KEY = 'test-key'; process.env.GEMINI_MODEL = 'test-model';
  t.after(() => {
    if (previous.key === undefined) delete process.env.GEMINI_API_KEY; else process.env.GEMINI_API_KEY = previous.key;
    if (previous.model === undefined) delete process.env.GEMINI_MODEL; else process.env.GEMINI_MODEL = previous.model;
  });
  let count = 0;
  const result = await checkGemini(async (url, options) => {
    count++;
    const body = JSON.parse(options.body);
    assert.equal(body.tools, undefined);
    assert.equal(body.generationConfig.maxOutputTokens, 64);
    return { ok: true, json: async () => ({ candidates: [{ content: { parts: [{ text: 'OK' }] } }] }) };
  });
  assert.equal(count, 1);
  assert.equal(result.status, 'connected');
});
