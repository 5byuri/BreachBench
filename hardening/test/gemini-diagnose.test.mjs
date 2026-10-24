import test from 'node:test';
import assert from 'node:assert/strict';
import { diagnoseGemini } from '../gemini-diagnose.mjs';

function environment(t, model = 'available-model') {
  const previous = { key: process.env.GEMINI_API_KEY, model: process.env.GEMINI_MODEL };
  process.env.GEMINI_API_KEY = 'AIzaPrivateDiagnosticTest';
  process.env.GEMINI_MODEL = model;
  t.after(() => {
    for (const [name, value] of [['GEMINI_API_KEY', previous.key], ['GEMINI_MODEL', previous.model]]) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  });
}
const metadata = { models: [{ name: 'models/available-model', supportedGenerationMethods: ['generateContent'] }] };
test('model listing succeeds but zero inference quota remains a failure', async t => {
  environment(t); let calls = 0;
  const result = await diagnoseGemini(async (url, options) => {
    calls++;
    assert.ok(!url.includes(process.env.GEMINI_API_KEY));
    if (!options.method) return { ok: true, json: async () => metadata };
    return { ok: false, status: 429, json: async () => ({ error: { status: 'RESOURCE_EXHAUSTED', message: `Quota limit: 0. Key ${process.env.GEMINI_API_KEY}` } }) };
  });
  assert.equal(calls, 2);
  assert.equal(result.metadataAccess, true);
  assert.equal(result.status, 'generation-failed');
  assert.match(result.message, /Quota limit: 0/);
  assert.doesNotMatch(JSON.stringify(result), /AIzaPrivateDiagnosticTest/);
});
test('unlisted model does not consume a generation request', async t => {
  environment(t, 'unavailable-model'); let calls = 0;
  const result = await diagnoseGemini(async () => { calls++; return { ok: true, json: async () => metadata }; });
  assert.equal(result.status, 'model-not-listed');
  assert.equal(calls, 1);
});
test('one successful generation establishes connection without running tools', async t => {
  environment(t);
  const result = await diagnoseGemini(async (url, options) => ({ ok: true, json: async () => options.method ? { candidates: [{ content: { parts: [{ text: 'OK' }] } }] } : metadata }));
  assert.equal(result.status, 'connected');
});
test('invalid key response is safely surfaced without inference attempt', async t => {
  environment(t); let calls = 0;
  const result = await diagnoseGemini(async () => { calls++; return { ok: false, status: 400, json: async () => ({ error: { message: 'API key not valid' } }) }; });
  assert.equal(result.status, 'metadata-request-failed');
  assert.equal(result.httpStatus, 400);
  assert.equal(calls, 1);
});
