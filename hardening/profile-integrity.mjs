import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])])) : value;
export const objectHash = value => sha256(JSON.stringify(canonical(value)));
export const profileHash = file => objectHash(JSON.parse(fs.readFileSync(file, 'utf8')));
export const PHASES = ['startup', 'foreground', 'background', 'uncommon', 'shutdown'];

export function traceManifest(traceFiles) {
  return PHASES.map(phase => {
    const file = traceFiles?.[phase];
    if (!file || !fs.statSync(file).isFile()) throw new Error(`Missing trace evidence for ${phase}`);
    return { phase, file: path.resolve(file), sha256: sha256(fs.readFileSync(file)) };
  });
}
export function createReviewBinding(profileFile, sidecar, evidence) {
  const sourceImageId = sidecar.workbenchAnalysis?.imageId;
  if (!sourceImageId || evidence?.sourceImageId !== sourceImageId) throw new Error('Review source image ID differs from traced image ID');
  if (!evidence.reviewer || !evidence.method) throw new Error('Review evidence requires reviewer and method');
  const traces = traceManifest(sidecar.traceFiles);
  return { sourceImageId, workbenchCommit: sidecar.workbenchAnalysis.workbenchCommit, profileSha256: profileHash(profileFile), traces, traceSetSha256: objectHash(traces) };
}
export function assertReviewBinding(profileFile, sidecar, expectedSource) {
  if (!['agent-permission-review', 'human-permission-review', 'manual-permission-review'].includes(sidecar.reviewType)) throw new Error('Unsupported permission reviewer type');
  const binding = sidecar.binding;
  if (!binding || binding.sourceImageId !== sidecar.reviewEvidence?.sourceImageId || binding.sourceImageId !== sidecar.workbenchAnalysis?.imageId) throw new Error('Profile review is not bound to its traced source image');
  if (expectedSource && binding.sourceImageId !== expectedSource) throw new Error('Profile was reviewed for a different source image');
  if (profileHash(profileFile) !== binding.profileSha256) throw new Error('Profile contents changed since permission review');
  const traces = traceManifest(sidecar.traceFiles);
  if (objectHash(traces) !== binding.traceSetSha256 || objectHash(binding.traces) !== binding.traceSetSha256) throw new Error('Workload traces changed since permission review');
  return binding;
}
