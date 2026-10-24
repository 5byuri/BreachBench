import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { run, Workflow, loadConfig } from './lib.mjs';
import { checkLsmSupport } from './profiles.mjs';
import { sha256, traceManifest, objectHash } from './profile-integrity.mjs';

const template = 'hardening/policies/apparmor.profile';
const templateReview = 'hardening/policies/apparmor.review.json';
export const fixtureHash = () => objectHash(['hardening/demo/app.py', 'hardening/demo/Containerfile'].map(file => ({ file, sha256: sha256(fs.readFileSync(file)) })));

export function generateLsmCandidate(candidateSidecar, output) {
  const observation = JSON.parse(fs.readFileSync(candidateSidecar));
  const traces = traceManifest(observation.traceFiles);
  const files = new Set();
  for (const trace of traces) {
    const text = fs.readFileSync(trace.file, 'utf8');
    const fileCalls = new Set(['open', 'openat', 'openat2', 'newfstatat', 'stat', 'statx', 'lstat', 'access', 'faccessat', 'faccessat2', 'readlink', 'readlinkat', 'execve', 'getcwd', 'mkdir', 'mkdirat', 'unlink', 'unlinkat', 'rename', 'renameat', 'renameat2', 'chdir']);
    for (const line of text.split('\n')) {
      if (!fileCalls.has(line.match(/\b([a-z][a-z0-9_]*)\(/)?.[1])) continue;
      for (const match of line.matchAll(/"(\/(?:[^"\\]|\\.)*)"/g)) {
        try { const file = JSON.parse(`"${match[1]}"`); if (!/[\n\r*?{}\[\]]/.test(file)) files.add(file); } catch {}
      }
    }
  }
  const root = path.resolve(output); fs.mkdirSync(root, { recursive: true });
  fs.copyFileSync(template, path.join(root, 'apparmor.candidate'));
  const candidate = { reviewed: false, sourceImageId: observation.workbenchAnalysis?.imageId, policySha256: sha256(fs.readFileSync(template)), traceSetSha256: objectHash(traces), traces, observedPaths: [...files].sort(),
    permissionReview: ['Review broad read/map permissions for Python libraries and abstractions/base', 'Only Python executables inherit this profile; extra programs need reviewed rules', 'Network policy is enforced separately; inet stream/dgram are not destination restrictions', 'Writable paths are limited to /tmp and a denied probe proves LSM enforcement', 'Fixture has no runtime secret requirement; adapt /run/secrets rules before using real credentials'],
    selinux: { candidateGenerator: 'udica -j <controlled-container-inspect.json> <dedicated-policy-name>', status: 'requires-target-host-tooling', reviewRequired: 'Inspect generated CIL and AVCs for this workload only; never load unreviewed audit2allow output' } };
  fs.writeFileSync(path.join(root, 'candidate-review.json'), JSON.stringify(candidate, null, 2));
  return candidate;
}

export async function verifyLsmFixture({ output = '.breachbench/lsm', execute = run } = {}) {
  const root = path.resolve(output); fs.mkdirSync(root, { recursive: true });
  const support = checkLsmSupport({ execute });
  const review = JSON.parse(fs.readFileSync(templateReview));
  if (review.policySha256 !== sha256(fs.readFileSync(template)) || review.fixtureSourceSha256 !== fixtureHash() || review.reviewType !== 'agent-permission-review') throw new Error('LSM template or fixture differs from recorded permission review');
  const report = { status: 'unverified-host', support, review, results: [], scope: 'Pre-reviewed fixture template conformance; does not approve arbitrary application profiles', remainingRisks: ['AppArmor abstractions/base varies by host; its effective permissions require target review', 'SELinux enforcement requires a SELinux-enabled host; this verifier does not equate AppArmor with SELinux'] };
  let loaded = false;
  const privileged = (...args) => process.getuid?.() === 0 ? execute(args[0], args.slice(1)) : execute('sudo', ['-n', ...args]);
  try {
    if (!support.apparmor.supported) return report;
    const baseline = loadConfig('hardening/demo/config.json');
    const imageId = JSON.parse(execute('docker', ['image', 'inspect', baseline.image]))[0].Id;
    report.imageId = imageId;
    privileged('apparmor_parser', '-r', '-W', path.resolve(template)); loaded = true;
    const workflow = new Workflow({ ...baseline, apparmorProfile: 'breachbench-python-fixture' }, { root: path.join(root, 'workflow'), execute });
    const negative = { name: 'AppArmor enforced label and denied write in otherwise writable tmpfs', category: 'lsm', argv: ['docker', 'exec', '{container}', 'python', '-c', "import os,errno; assert 'breachbench-python-fixture (enforce)' in open('/proc/self/attr/current').read(); open('/tmp/breachbench-allowed','w').close();\ntry: open('/tmp/breachbench-denied','w').close(); raise AssertionError('LSM allowed denied write')\nexcept OSError as e: assert e.errno==errno.EACCES"] };
    const control = { name: 'Control write succeeds without custom LSM', category: 'lsm-control', argv: ['docker', 'exec', '{container}', 'python', '-c', "open('/tmp/breachbench-denied','w').close()"] };
    const configWithoutProfile = new Workflow(baseline, { root: path.join(root, 'control'), execute });
    // Test EROFS separately: AppArmor may reject the same write with EACCES first.
    report.results = [...await configWithoutProfile.suite(imageId, true, [control, ...baseline.enforcementTests]), ...await workflow.suite(imageId, true, [...baseline.tests, ...baseline.enforcementTests.filter(t => t.category !== 'filesystem'), negative])];
    report.status = report.results.every(r => r.passed) ? 'passed' : 'failed';
    report.apparmorEnforced = report.status === 'passed';
    report.selinuxEnforced = false;
  } catch (error) { report.status = 'failed'; report.error = error.message; }
  finally {
    if (loaded) {
      try { privileged('apparmor_parser', '-R', path.resolve(template)); report.profileUnloaded = true; }
      catch (error) { report.profileUnloaded = false; report.status = 'failed'; report.cleanupError = error.message; }
    }
    fs.writeFileSync(path.join(root, 'report.json'), JSON.stringify(report, null, 2));
  }
  return report;
}

// Udica emits SELinux CIL candidates from the dedicated, controlled container.
// Review and module loading are intentionally separate operations.
export function generateSelinuxCandidate(container, output, execute = run) {
  if (!/^breachbench-[a-zA-Z0-9-]+$/.test(container)) throw new Error('SELinux capture requires a dedicated breachbench-* container');
  const root = path.resolve(output); fs.mkdirSync(root, { recursive: true });
  const inspection = JSON.parse(execute('docker', ['inspect', container]));
  for (const entry of inspection) if (entry.Config) entry.Config.Env = []; // Udica needs mounts/ports, not secret values.
  const file = path.join(root, 'container.json'); fs.writeFileSync(file, JSON.stringify(inspection), { mode: 0o600 });
  execute('udica', ['-j', file, 'breachbench_workload'], { cwd: root });
  const cilFiles = fs.readdirSync(root).filter(file => file.endsWith('.cil'));
  const review = { reviewed: false, reviewType: 'unreviewed-candidate', files: cilFiles.map(file => ({ file, sha256: sha256(fs.readFileSync(path.join(root, file))) })), requiredReview: ['Review CIL permissions and template inheritance', 'Use a dedicated test domain; exercise all workloads and review its AVCs', 'Verify label=type:breachbench_workload.process, positive behavior and a specific denied operation on an enforcing host'] };
  fs.writeFileSync(path.join(root, 'selinux-review.json'), JSON.stringify(review, null, 2));
  return review;
}

if (process.argv[1]?.endsWith('lsm.mjs')) {
  try {
    const [command, a, b] = process.argv.slice(2);
    const result = command === 'generate' ? generateLsmCandidate(a, b) : command === 'selinux-generate' ? generateSelinuxCandidate(a, b) : await verifyLsmFixture();
    console.log(JSON.stringify(result, null, 2));
    if (result.status && result.status !== 'passed') process.exitCode = 2;
  } catch (error) { console.error(JSON.stringify({ status: 'failed', message: error.message })); process.exitCode = 1; }
}
