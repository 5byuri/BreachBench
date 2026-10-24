import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Workflow, loadConfig, normalizeTrivy, runtimeArgs, networkPolicy, PIN, tools } from '../lib.mjs';
import { agent } from '../gemini.mjs';
import { parseStrace, buildSeccompCandidate, validateSeccompCandidate, reviewSeccompCandidate, ensureWorkbenchFilesystem, checkLsmSupport, JUSTIFIED_ADDITIONAL_SYSCALLS } from '../profiles.mjs';

const config = () => loadConfig('hardening/demo/config.json');
function fixture(t, overrides = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'breachbench-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const calls = [];
  const execute = (exe, args) => {
    calls.push([exe, ...args]);
    if (exe === 'git') return PIN;
    if (exe === 'go') return '';
    if (exe === 'trivy') return JSON.stringify({ Results: [] });
    if (args[0] === 'image') return JSON.stringify([{ Id: args.at(-1).includes('baseline') || args.at(-1).startsWith('breachbench/source:') || args.at(-1) === 'sha256:source' ? 'sha256:source' : 'sha256:candidate', Size: 100, Config: { User: '10001:10001' } }]);
    if (args[0] === 'inspect' && args.includes('{{json .State.Running}}')) return 'true';
    return '134217728/500000000/64';
  };
  const c = { ...config(), startupMs: 0, ...overrides };
  return { workflow: new Workflow(c, { root, execute }), calls, root };
}
test('full measured workflow invokes pinned work-bench and keeps rollback', async t => {
  const { workflow, calls } = fixture(t);
  let report;
  for (const tool of tools) report = await workflow.invoke(tool);
  assert.equal(report.status, 'eligible-for-review');
  assert.equal(report.promoted, false);
  assert.equal(report.rollback.image, 'sha256:source');
  assert.ok(calls.some(c => c[0] === 'go' && c.includes('inspect')));
  assert.ok(calls.some(c => c.includes('--image-config-scanners')));
  assert.ok(calls.some(c => c[1] === 'rm'));
});
test('uncommon and background tests are mandatory', async t => {
  const { workflow } = fixture(t, { tests: [config().tests[0]] });
  for (const tool of tools.slice(0, 4)) await workflow.invoke(tool);
  await assert.rejects(workflow.invoke('test_application'), /background/);
});
test('missing enforcement evidence rejects candidate', async t => {
  const { workflow } = fixture(t, { enforcementTests: [] });
  let report;
  for (const tool of tools) report = await workflow.invoke(tool);
  assert.equal(report.status, 'rejected');
  assert.ok(report.enforcement.missing.includes('syscalls'));
});
test('repeat build invalidates old acceptance evidence', async t => {
  const { workflow } = fixture(t);
  for (const tool of tools) await workflow.invoke(tool);
  await workflow.invoke('build_candidate');
  assert.throws(() => workflow.read('report'), /ENOENT/);
  await assert.rejects(workflow.invoke('compare_results'), /ENOENT/);
});
test('secret findings never contain matched credentials or code', () => {
  const normalized = normalizeTrivy({ Results: [{ Target: 'app', Secrets: [{ RuleID: 'key', Match: 'private-key', Code: 'sensitive source', Severity: 'HIGH' }], Vulnerabilities: [{ PkgName: 'php', VulnerabilityID: 'CVE-demo', Severity: 'HIGH' }] }] });
  assert.doesNotMatch(JSON.stringify(normalized), /private-key|sensitive source/);
  assert.match(normalized.find(f => f.kind === 'vulnerability').fix, /runtime/);
});
test('runtime uses no host mounts, capabilities or network', () => {
  const args = runtimeArgs(config(), 'test', 'image');
  for (const flag of ['--read-only', '--cap-drop', '--pids-limit', '--memory', '--cpus']) assert.ok(args.includes(flag));
  assert.equal(args[args.indexOf('--network') + 1], 'none');
  assert.ok(!args.includes('--privileged'));
  assert.deepEqual(networkPolicy(config()).spec.egress, []);
});
test('Gemini cannot run an out-of-order tool or arbitrary arguments', async t => {
  const { workflow } = fixture(t);
  const oldKey = process.env.GEMINI_API_KEY; const oldModel = process.env.GEMINI_MODEL;
  process.env.GEMINI_API_KEY = 'test-only'; process.env.GEMINI_MODEL = 'test-model';
  t.after(() => { if (oldKey === undefined) delete process.env.GEMINI_API_KEY; else process.env.GEMINI_API_KEY = oldKey; if (oldModel === undefined) delete process.env.GEMINI_MODEL; else process.env.GEMINI_MODEL = oldModel; });
  await assert.rejects(agent(workflow, async () => ({ ok: true, json: async () => ({ candidates: [{ content: { role: 'model', parts: [{ functionCall: { name: 'build_candidate', args: { command: 'arbitrary' } } }] } }] }) })), /out-of-order/);
});
test('failed application test cannot become an enforcement success', async t => {
  const { workflow } = fixture(t);
  for (const tool of tools.slice(0, 4)) await workflow.invoke(tool);
  const original = workflow.exec;
  workflow.exec = (exe, args, opts) => {
    if (args[0] === 'exec') throw new Error('Application failure');
    return original(exe, args, opts);
  };
  const result = await workflow.invoke('test_application');
  assert.equal(result.passed, false);
  await assert.rejects(workflow.invoke('verify_hardening'), /Functionality must pass/);
});
test('configuration change invalidates earlier evidence', async t => {
  const { workflow, root } = fixture(t);
  await workflow.invoke('inspect_container');
  const changed = new Workflow({ ...workflow.c, pids: 128 }, { root });
  assert.throws(() => changed.read('inspect'), /Stale evidence/);
});
test('same vulnerability under a different image target is not a regression', async t => {
  const { workflow } = fixture(t);
  const original = workflow.exec;
  workflow.exec = (exe, args, opts) => {
    if (exe === 'trivy' && args[0] === 'image') return JSON.stringify({ Results: [{ Target: args.at(-1), Vulnerabilities: [{ VulnerabilityID: 'CVE-existing', PkgName: 'php', InstalledVersion: 'old', Severity: 'HIGH' }] }] });
    return original(exe, args, opts);
  };
  let report;
  for (const tool of tools) report = await workflow.invoke(tool);
  assert.equal(report.securityRegression, false);
  assert.equal(report.status, 'eligible-for-review');
  assert.equal(report.findings[0].component, 'php');
});
test('new high-severity vulnerability rejects a candidate', async t => {
  const { workflow } = fixture(t);
  const original = workflow.exec;
  workflow.exec = (exe, args, opts) => {
    if (exe === 'trivy' && args[0] === 'image' && args.at(-1) === 'sha256:candidate') return JSON.stringify({ Results: [{ Target: args.at(-1), Vulnerabilities: [{ VulnerabilityID: 'CVE-new', PkgName: 'php', Severity: 'HIGH' }] }] });
    return original(exe, args, opts);
  };
  let report;
  for (const tool of tools) report = await workflow.invoke(tool);
  assert.equal(report.securityRegression, true);
  assert.equal(report.status, 'rejected');
});
test('Slim uses the server API and disables retaining private certificate keys', async t => {
  const { workflow, calls } = fixture(t, { slim: { execFile: 'hardening/demo/slim-workload.sh', includePaths: ['/app'], removeEnv: ['GPG_KEY'] } });
  const original = workflow.exec;
  workflow.exec = (exe, args, opts) => {
    if (exe === 'docker' && args[0] === 'version') return '1.52';
    return original(exe, args, opts);
  };
  for (const tool of tools.slice(0, 4)) await workflow.invoke(tool);
  const slim = calls.find(c => c[0] === 'slim');
  assert.ok(slim.includes('--crt-api-version'));
  assert.ok(slim.includes('1.52'));
  assert.ok(slim.includes('--include-cert-pk-all=false'));
  assert.ok(slim.includes('--remove-env'));
  assert.equal(workflow.read('build').slim, true);
});
test('loss of OS scanner visibility rejects a candidate', async t => {
  const { workflow } = fixture(t);
  const original = workflow.exec;
  workflow.exec = (exe, args, opts) => {
    if (exe === 'trivy' && args[0] === 'image') return JSON.stringify({ Metadata: { OS: { Family: args.at(-1) === 'sha256:candidate' ? 'none' : 'debian' } }, Results: [] });
    return original(exe, args, opts);
  };
  let report;
  for (const tool of tools) report = await workflow.invoke(tool);
  assert.equal(report.status, 'rejected');
  assert.equal(report.scannerCoverage.reduced, true);
});
test('changing profile contents invalidates evidence even if its path is unchanged', async t => {
  const { workflow, root } = fixture(t);
  const profile = path.join(root, 'profile.json');
  fs.writeFileSync(profile, '{"defaultAction":"SCMP_ACT_ERRNO"}');
  const checked = new Workflow({ ...workflow.c, seccompProfile: profile }, { root, execute: workflow.exec });
  await checked.invoke('inspect_container');
  fs.writeFileSync(profile, '{"defaultAction":"SCMP_ACT_ALLOW"}');
  await assert.rejects(checked.invoke('scan_image'), /Inputs changed/);
});
test('automated validation stays reviewed=false and permission review requires explicit reviewType and reviewEvidence', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'breachbench-seccomp-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const traceText = [
    '1234  10:00:00.123456 execve("/usr/local/bin/python3", ["python3"], 0x7ff) = 0',
    '[pid  1235] 10:00:00.234567 <... poll resumed> [{fd=3, revents=POLLIN}], 1, 500) = 1',
    '[pid  1235] 10:00:00.345678 ptrace(PTRACE_TRACEME) = 0',
    '[pid  1235] 10:00:00.456789 read(3, "GET /healthz", 4096) = 12'
  ].join('\n');
  const parsed = parseStrace(traceText);
  assert.deepEqual(parsed, ['execve', 'poll', 'read']);

  const candidatePath = path.join(root, 'seccomp.candidate.json');
  const res = buildSeccompCandidate({
    startup: ['execve', 'openat'],
    foreground: ['read', 'write', 'poll'],
    background: ['openat', 'write'],
    uncommon: ['read', 'getrandom'],
    shutdown: ['close', 'exit_group']
  }, candidatePath);
  assert.equal(res.reviewed, false);
  assert.equal(res.reviewType, 'unreviewed-candidate');

  // Automated validation checks structure & justifications but NEVER marks reviewed: true
  const valRes = validateSeccompCandidate(candidatePath);
  assert.equal(valRes.reviewed, false);
  assert.equal(valRes.reviewType, 'automated-validation-only');
  assert.equal(valRes.automatedValidation.passed, true);
  const sidecar = JSON.parse(fs.readFileSync(`${candidatePath}.review.json`, 'utf8'));
  assert.equal(sidecar.reviewed, false);
  assert.equal(sidecar.reviewType, 'automated-validation-only');
  assert.deepEqual(Object.keys(sidecar.additionalSyscalls).sort(), Object.keys(JUSTIFIED_ADDITIONAL_SYSCALLS).sort());

  const cfgPath = path.join(root, 'config.json');
  const rawCfg = JSON.parse(fs.readFileSync('hardening/demo/config.json', 'utf8'));
  rawCfg.seccompProfile = candidatePath;
  fs.writeFileSync(cfgPath, JSON.stringify(rawCfg, null, 2));
  assert.throws(() => loadConfig(cfgPath), /reviewed: false/);

  // Even if someone flips reviewed: true with automated reviewType or without reviewEvidence, loadConfig rejects it
  fs.writeFileSync(`${candidatePath}.review.json`, JSON.stringify({ ...sidecar, reviewed: true, reviewType: 'automated-validation-only', reviewEvidence: 'some note' }, null, 2));
  assert.throws(() => loadConfig(cfgPath), /explicit permission reviewType/);
  fs.writeFileSync(`${candidatePath}.review.json`, JSON.stringify({ ...sidecar, reviewed: true, reviewType: 'manual-permission-review', reviewEvidence: '' }, null, 2));
  assert.throws(() => loadConfig(cfgPath), /must record reviewEvidence/);
  fs.writeFileSync(`${candidatePath}.review.json`, JSON.stringify(sidecar, null, 2));

  // reviewSeccompCandidate rejects missing or automated reviewType and missing reviewEvidence
  const reviewedPath = path.join(root, 'seccomp.reviewed.json');
  const reviewedCfgPath = path.join(root, 'config.reviewed.json');
  assert.throws(() => reviewSeccompCandidate(candidatePath, reviewedPath, {}), /non-automated reviewType/);
  assert.throws(() => reviewSeccompCandidate(candidatePath, reviewedPath, { reviewType: 'automated', reviewEvidence: 'traces' }), /non-automated reviewType/);
  assert.throws(() => reviewSeccompCandidate(candidatePath, reviewedPath, { reviewType: 'manual-permission-review' }), /requires reviewEvidence/);

  const reviewRes = reviewSeccompCandidate(candidatePath, reviewedPath, {
    reviewType: 'manual-permission-review',
    reviewEvidence: {
      tracesReviewed: ['startup.strace', 'foreground.strace', 'background.strace', 'uncommon.strace', 'shutdown.strace'],
      kernelAuditVerified: ['openat2', 'fstatfs', 'statx'],
      negativeProbesConfirmedExcluded: ['getppid', 'getpgid']
    },
    baseConfigPath: 'hardening/demo/config.json',
    reviewedConfigPath: reviewedCfgPath
  });
  assert.equal(reviewRes.reviewed, true);
  assert.equal(reviewRes.reviewType, 'manual-permission-review');
  const loaded = loadConfig(reviewedCfgPath);
  assert.equal(loaded.seccompProfile, reviewedPath);

  // validateSeccompCandidate with reviewedPath verifies no drift and rejects when candidate syscalls change
  const verified = validateSeccompCandidate(candidatePath, reviewedPath);
  assert.equal(verified.reviewed, false);
  assert.equal(verified.reviewedProfileVerification.reviewed, true);
  buildSeccompCandidate({
    startup: ['execve', 'openat', 'nanosleep'],
    foreground: ['read', 'write', 'poll'],
    background: ['openat', 'write'],
    uncommon: ['read', 'getrandom'],
    shutdown: ['close', 'exit_group']
  }, candidatePath);
  assert.throws(() => validateSeccompCandidate(candidatePath, reviewedPath), /drifted from the reviewed profile/);
});
test('validateSeccompCandidate and reviewSeccompCandidate reject missing phases, unjustified syscalls, or forbidden probe syscalls', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'breachbench-review-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const candidatePath = path.join(root, 'bad.json');
  buildSeccompCandidate({
    startup: ['execve'],
    foreground: ['read'],
    background: ['write'],
    uncommon: ['poll'],
    shutdown: []
  }, candidatePath);
  assert.throws(() => validateSeccompCandidate(candidatePath), /missing required workload phases: shutdown/);

  buildSeccompCandidate({
    startup: ['execve'],
    foreground: ['read'],
    background: ['write'],
    uncommon: ['poll'],
    shutdown: ['exit_group']
  }, candidatePath, { additionalSyscalls: { openat2: '' } });
  assert.throws(() => validateSeccompCandidate(candidatePath), /Unjustified non-observed syscalls/);

  buildSeccompCandidate({
    startup: ['execve', 'getppid'],
    foreground: ['read'],
    background: ['write'],
    uncommon: ['poll'],
    shutdown: ['exit_group']
  }, candidatePath);
  assert.throws(() => validateSeccompCandidate(candidatePath), /forbidden or negative-probe syscalls: getppid/);
});
test('work-bench extracted filesystem is bound to exact image ID and invalidated when image ID changes', async t => {
  const wbRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'breachbench-wb-cache-'));
  t.after(() => fs.rmSync(wbRoot, { recursive: true, force: true }));
  let currentImageId = 'sha256:image-v1';
  let inspectRuns = 0;
  const mockExec = (exe, args) => {
    if (exe === 'git') return PIN;
    if (exe === 'docker' && args[0] === 'image' && args[1] === 'inspect') {
      return JSON.stringify([{ Id: currentImageId, Size: 100, Config: { User: '10001:10001' } }]);
    }
    if (exe === 'go' && args.includes('inspect')) {
      inspectRuns++;
      const outDir = args[args.indexOf('--output') + 1];
      fs.mkdirSync(outDir, { recursive: true });
      fs.writeFileSync(path.join(outDir, `marker-${currentImageId.replace(':', '-')}`), currentImageId);
      return '';
    }
    return '';
  };

  const first = ensureWorkbenchFilesystem('breachbench/demo:baseline', wbRoot, mockExec);
  assert.equal(first.imageId, 'sha256:image-v1');
  assert.equal(first.cacheHit, false);
  assert.equal(first.cacheInvalidated, false);
  assert.equal(inspectRuns, 1);
  assert.ok(fs.existsSync(path.join(first.mergedFs, 'marker-sha256-image-v1')));

  // Same image ID reuses cached extraction
  const second = ensureWorkbenchFilesystem('breachbench/demo:baseline', wbRoot, mockExec);
  assert.equal(second.imageId, 'sha256:image-v1');
  assert.equal(second.cacheHit, true);
  assert.equal(second.cacheInvalidated, false);
  assert.equal(inspectRuns, 1);

  // Changing image ID invalidates the old filesystem directory and re-extracts
  currentImageId = 'sha256:image-v2';
  const third = ensureWorkbenchFilesystem('breachbench/demo:baseline', wbRoot, mockExec);
  assert.equal(third.imageId, 'sha256:image-v2');
  assert.equal(third.cacheHit, false);
  assert.equal(third.cacheInvalidated, true);
  assert.equal(inspectRuns, 2);
  assert.ok(!fs.existsSync(path.join(third.mergedFs, 'marker-sha256-image-v1')));
  assert.ok(fs.existsSync(path.join(third.mergedFs, 'marker-sha256-image-v2')));

  // Workflow.inspect_container and scan_image also bind to source image ID and reject image ID drift
  const { workflow } = fixture(t);
  let wfImageId = 'sha256:source';
  const origExec = workflow.exec;
  workflow.exec = (exe, args, opts) => {
    if (args[0] === 'image' && args[1] === 'inspect' && args[2] === workflow.c.image) {
      return JSON.stringify([{ Id: wfImageId, Size: 100, Config: { User: '10001:10001' } }]);
    }
    return origExec(exe, args, opts);
  };
  const inspect1 = await workflow.invoke('inspect_container');
  assert.equal(inspect1.workbench.imageId, 'sha256:source');
  assert.equal(inspect1.workbench.cacheInvalidated, false);
  fs.writeFileSync(path.join(inspect1.workbench.filesystem, 'stale-file'), 'old');

  wfImageId = 'sha256:source-rebuilt';
  await assert.rejects(workflow.invoke('scan_image'), /source image ID changed since work-bench inspection/);
  const inspect2 = await workflow.invoke('inspect_container');
  assert.equal(inspect2.workbench.imageId, 'sha256:source-rebuilt');
  assert.equal(inspect2.workbench.cacheInvalidated, true);
  assert.ok(!fs.existsSync(path.join(inspect2.workbench.filesystem, 'stale-file')));
});
test('LSM support check keeps AppArmor/SELinux unverified on host and verify_hardening rejects unsupported LSM', async t => {
  const lsm = checkLsmSupport({
    execute: (exe, args) => {
      if (exe === 'docker' && args[0] === 'info') return JSON.stringify(['name=seccomp,profile=builtin', 'name=cgroupns']);
      return '';
    },
    fsModule: {
      existsSync: p => p === '/proc/version' || p === '/sys/module/apparmor/parameters/enabled',
      readFileSync: p => (p === '/proc/version' ? 'Linux version 6.6.87.2-microsoft-standard-WSL2' : 'N\n')
    }
  });
  assert.equal(lsm.overallStatus, 'partial-seccomp-only-apparmor-selinux-unverified');
  assert.equal(lsm.seccomp.supported, true);
  assert.equal(lsm.apparmor.supported, false);
  assert.equal(lsm.apparmor.verified, false);
  assert.equal(lsm.apparmor.tested, false);
  assert.equal(lsm.apparmor.status, 'unverified-on-host');
  assert.equal(lsm.selinux.supported, false);
  assert.equal(lsm.selinux.verified, false);
  assert.equal(lsm.selinux.tested, false);
  assert.equal(lsm.selinux.status, 'unverified-on-host');

  const { workflow } = fixture(t, { apparmorProfile: 'breachbench-demo-apparmor-profile', selinuxType: 'spc_t' });
  const original = workflow.exec;
  workflow.exec = (exe, args, opts) => {
    if (exe === 'docker' && args[0] === 'info') return JSON.stringify(['name=seccomp,profile=builtin', 'name=cgroupns']);
    return original(exe, args, opts);
  };
  let report;
  for (const tool of tools) report = await workflow.invoke(tool);
  assert.equal(report.status, 'rejected');
  assert.ok(report.enforcement.missing.includes('apparmor-host-support'));
  assert.ok(report.enforcement.missing.includes('selinux-host-support'));
});
