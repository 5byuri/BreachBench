import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildSeccompCandidate, reviewSeccompCandidate } from '../profiles.mjs';
import { assertReviewBinding } from '../profile-integrity.mjs';
import { planRemediation } from '../remediation.mjs';
import { clusterManifests, fixturePolicies } from '../cluster.mjs';

function candidate(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-binding-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const phases = ['startup', 'foreground', 'background', 'uncommon', 'shutdown'];
  const traces = Object.fromEntries(phases.map(phase => { const file = path.join(root, `${phase}.strace`); fs.writeFileSync(file, 'read(0,"",0)=0'); return [phase, file]; }));
  const file = path.join(root, 'candidate.json');
  buildSeccompCandidate(Object.fromEntries(phases.map(p => [p, ['read']])), file, { additionalSyscalls: {}, traceFiles: traces, workbenchAnalysis: { imageId: 'sha256:original', workbenchCommit: 'pinned-commit' } });
  return { file, traces, reviewed: path.join(root, 'reviewed.json'), options: { reviewType: 'agent-permission-review', reviewEvidence: { sourceImageId: 'sha256:original', reviewer: 'test-agent', method: 'Synthetic policy review' } } };
}
test('review cannot attest a different source image', t => {
  const c = candidate(t); c.options.reviewEvidence.sourceImageId = 'sha256:other';
  assert.throws(() => reviewSeccompCandidate(c.file, c.reviewed, c.options), /differs from traced/);
});
test('profile mutation after review is rejected', t => {
  const c = candidate(t); reviewSeccompCandidate(c.file, c.reviewed, c.options);
  const sidecar = JSON.parse(fs.readFileSync(`${c.reviewed}.review.json`));
  const profile = JSON.parse(fs.readFileSync(c.reviewed)); profile.syscalls[0].names.push('getppid');
  fs.writeFileSync(c.reviewed, JSON.stringify(profile));
  assert.throws(() => assertReviewBinding(c.reviewed, sidecar), /contents changed/);
});
test('trace mutation invalidates review even with identical syscall list', t => {
  const c = candidate(t); reviewSeccompCandidate(c.file, c.reviewed, c.options);
  const sidecar = JSON.parse(fs.readFileSync(`${c.reviewed}.review.json`));
  fs.appendFileSync(c.traces.startup, '\nread(1,"",0)=0');
  assert.throws(() => assertReviewBinding(c.reviewed, sidecar), /traces changed/);
});
test('pip removal requires a declared workload requirement and findings', () => {
  const findings = [{ id: 'CVE-pip', kind: 'vulnerability', component: 'pip', fixedVersion: '26.2.0' }];
  assert.throws(() => planRemediation({ user: '10001:10001', remediations: { removeUnusedPip: true } }, 'source', findings), /never installs/);
  const plan = planRemediation({ user: '10001:10001', runtimePackageInstallation: false, remediations: { removeUnusedPip: true } }, 'source', findings);
  assert.match(plan.dockerfile, /uninstall --yes pip/);
  assert.deepEqual(plan.changes[0].findingIds, ['CVE-pip']);
});
test('cluster workloads do not receive broad credential mounts or root privileges', () => {
  const pods = clusterManifests('test', 'image').filter(m => m.kind === 'Pod');
  for (const pod of pods) {
    assert.equal(pod.spec.automountServiceAccountToken, false);
    assert.equal(pod.spec.securityContext.runAsNonRoot, true);
    assert.ok(!pod.spec.volumes.some(v => v.hostPath));
    assert.deepEqual(pod.spec.containers[0].securityContext.capabilities.drop, ['ALL']);
    const secretMount = pod.spec.containers[0].volumeMounts.find(v => v.name === 'database-secret');
    if (['app', 'database'].includes(pod.metadata.name)) assert.equal(secretMount.readOnly, true); else assert.equal(secretMount, undefined);
  }
  const policies = fixturePolicies('test');
  const app = policies.find(p => p.metadata.name === 'breachbench-default-deny');
  assert.equal(app.spec.egress.length, 3);
  assert.ok(!app.spec.egress.some(r => r.to.some(t => t.ipBlock?.cidr === '0.0.0.0/0')));
});
