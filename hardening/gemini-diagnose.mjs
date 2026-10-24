#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { checkGemini, formatGeminiError } from './gemini.mjs';

// Metadata access alone does not prove inference quota or paid-credit eligibility.
export async function diagnoseGemini(request = fetch) {
  const key = process.env.GEMINI_API_KEY;
  const model = process.env.GEMINI_MODEL;
  if (!key?.trim()) return { status: 'missing-key', next: 'Set GEMINI_API_KEY privately in this PowerShell session; do not paste it into chat.' };
  if (key !== key.trim()) return { status: 'invalid-key-format', next: 'The key contains leading/trailing whitespace. Enter it again without spaces.' };
  const available = [];
  let pageToken;
  let complete = false;
  for (let page = 0; page < 10; page++) {
    const url = new URL('https://generativelanguage.googleapis.com/v1beta/models');
    url.searchParams.set('pageSize', '1000');
    if (pageToken) url.searchParams.set('pageToken', pageToken);
    const response = await request(url.toString(), { headers: { 'x-goog-api-key': key }, signal: AbortSignal.timeout(60000) });
    if (!response.ok) {
      let payload = {};
      try { payload = await response.json(); } catch { /* Keep HTTP status. */ }
      return { status: 'metadata-request-failed', httpStatus: response.status, message: formatGeminiError(response.status, payload, key) };
    }
    const result = await response.json();
    for (const entry of result.models ?? []) {
      const name = entry.name?.replace(/^models\//, '');
      if (/^[a-zA-Z0-9._-]+$/.test(name ?? '') && entry.supportedGenerationMethods?.includes('generateContent')) available.push(name);
    }
    pageToken = result.nextPageToken;
    if (!pageToken) { complete = true; break; }
  }
  const summary = { metadataAccess: true, modelListComplete: complete, selectedModel: model ?? null, generationModels: [...new Set(available)].sort(), note: 'Listing models does not establish inference access, billing eligibility or available credits.' };
  if (!model || !available.includes(model)) return { ...summary, status: model ? 'model-not-listed' : 'choose-model', next: 'Set GEMINI_MODEL to an available text Gemini model from generationModels, then repeat. No generation request was made.' };
  try {
    const result = await checkGemini(request);
    return { ...summary, ...result, next: 'API generation succeeded. You can now run the Gemini tool workflow; this check does not verify function calling or credit attribution.' };
  } catch (error) {
    return { ...summary, status: 'generation-failed', httpStatus: error.httpStatus ?? null, message: error.message, next: 'For 429, inspect the selected project in AI Studio Usage/Rate limits and Billing. If the organizer credits are Vertex-only, request its project ID and use a Vertex backend instead.' };
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const result = await diagnoseGemini();
    console.log(JSON.stringify(result, null, 2));
    if (result.status !== 'connected') process.exitCode = 1;
  } catch {
    console.error(JSON.stringify({ status: 'network-error', message: 'Cannot reach Gemini metadata endpoint. Check network/proxy settings. No credential or raw network error is printed.' }));
    process.exitCode = 1;
  }
}
