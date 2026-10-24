import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { assertReviewBinding } from './profile-integrity.mjs';
import { planRemediation } from './remediation.mjs';

export const WORKBENCH = 'container-hardening-work-bench/container-hardening-work-bench';
export const PIN = '21f38fed9c32a39a694ba0fec32b933bfc0dbcd0';
export const tools = ['inspect_container', 'scan_image', 'propose_hardening', 'build_candidate', 'test_application', 'verify_hardening', 'compare_results'];
export const digest = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
export function configFingerprint(config) {
  const reviewSidecar = config.seccompProfile && fs.existsSync(`${config.seccompProfile}.review.json`) ? `${config.seccompProfile}.review.json` : null;
  const files = [config.dockerfile, config.seccompProfile, reviewSidecar, config.slim?.execFile, ...(config.evidenceFiles ?? [])].filter(Boolean);
  return digest({ config, inputs: files.map(file => ({ file, digest: digest(fs.readFileSync(file, 'utf8')) })) });
}
export function run(exe, args, options = {}) {
  const result = spawnSync(exe, args, { encoding: 'utf8', timeout: 600000, maxBuffer: 32 * 1024 * 1024, shell: false, ...options,
    // Never pass the Gemini credential to Docker, scanners or test subprocesses.
    env: Object.fromEntries(Object.entries(process.env).filter(([key]) => !/GEMINI|GOOGLE_API_KEY|GOOGLE_APPLICATION_CREDENTIALS|GITHUB_TOKEN|GH_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AZURE_CLIENT_SECRET/.test(key))) });
  if (result.error || result.status !== 0) {
    const error = new Error(`${exe} failed (${result.status ?? result.error?.code}); see local tool installation/daemon and configuration`);
    error.diagnostic = result.stderr || result.error?.message || 'No diagnostic output';
    throw error;
  }
  return result.stdout;
}
export function loadConfig(file) {
  const config = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const field of ['image', 'candidate', 'context', 'dockerfile']) if (typeof config[field] !== 'string' || !config[field]) throw new Error(`Missing ${field}`);
  if (config.image === config.candidate || !config.candidate.startsWith('breachbench/')) throw new Error('Candidate must have a distinct breachbench/ tag');
  if (!/^[1-9][0-9]*:[1-9][0-9]*$/.test(config.user)) throw new Error('Explicit non-root numeric UID:GID required');
  if (!Number.isInteger(config.pids) || config.pids < 1 || !(config.cpus > 0) || !/^[1-9][0-9]*[mMgG]$/.test(config.memory)) throw new Error('Explicit resource limits required');
  for (const test of [...(config.tests ?? []), ...(config.enforcementTests ?? [])]) {
    if (!test.name || !Array.isArray(test.argv) || !test.argv.length || test.argv.some(x => typeof x !== 'string')) throw new Error('Tests require name and argv array');
  }
  if ((config.seccompProfile || config.apparmorProfile || config.selinuxType) && config.profilesReviewed !== true) throw new Error('Review custom profile permissions and set profilesReviewed before enforcement');
  if (config.seccompProfile && fs.existsSync(`${config.seccompProfile}.review.json`)) {
    const review = JSON.parse(fs.readFileSync(`${config.seccompProfile}.review.json`, 'utf8'));
    if (review.reviewed !== true) throw new Error('Seccomp candidate review sidecar is still marked reviewed: false');
    if (!review.reviewType || ['automated', 'automated-validation-only', 'none'].includes(review.reviewType)) {
      throw new Error('Seccomp profile requires an explicit permission reviewType; automated validation alone cannot approve a profile');
    }
    if (!review.reviewEvidence || (typeof review.reviewEvidence === 'string' && !review.reviewEvidence.trim()) || (typeof review.reviewEvidence === 'object' && !Object.keys(review.reviewEvidence).length)) {
      throw new Error('Seccomp profile review sidecar must record reviewEvidence');
    }
    assertReviewBinding(config.seccompProfile, review);
  }
  return config;
}
export function normalizeTrivy(report) {
  return (report.Results ?? []).flatMap(r => [
    ...(r.Vulnerabilities ?? []).map(v => ({ kind: 'vulnerability', id: v.VulnerabilityID, component: v.PkgName, installed: v.InstalledVersion, fixedVersion: v.FixedVersion, severity: v.Severity, fix: v.FixedVersion ? `Upgrade to ${v.FixedVersion}` : 'No fixed version reported; replace or update upstream runtime', target: r.Target })),
    ...(r.Secrets ?? []).map(s => ({ kind: 'secret', id: s.RuleID, component: r.Target, severity: s.Severity, fix: 'Revoke/rotate credential and remove it from image layers and build inputs' })),
    ...(r.Misconfigurations ?? []).filter(m => m.Status !== 'PASS').map(m => ({ kind: 'misconfiguration', id: m.ID, component: r.Target, severity: m.Severity, fix: m.Resolution || m.Title }))
  ]);
}
export function runtimeArgs(c, name, image, hardened = true) {
  const args = ['run', '-d', '--name', name];
  if (hardened) {
    args.push('--user', c.user, '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--read-only', '--memory', c.memory, '--cpus', String(c.cpus), '--pids-limit', String(c.pids), '--network', 'none');
    for (const directory of c.writable ?? ['/tmp']) {
      if (!/^\/(tmp|run|var\/cache|var\/lib)\/[a-zA-Z0-9/_-]+$/.test(directory) && directory !== '/tmp') throw new Error('Writable path must be explicitly scoped');
      args.push('--tmpfs', `${directory}:rw,nosuid,nodev,noexec,size=64m,uid=${c.user.split(':')[0]},gid=${c.user.split(':')[1]}`);
    }
    if (c.seccompProfile) args.push('--security-opt', `seccomp=${path.resolve(c.seccompProfile)}`);
    if (c.apparmorProfile) args.push('--security-opt', `apparmor=${c.apparmorProfile}`);
    if (c.selinuxType) args.push('--security-opt', `label=type:${c.selinuxType}`);
  }
  args.push(image);
  return args;
}
export function networkPolicy(c) {
  const egress = (c.egress ?? []).map(rule => {
    if (!rule.to?.length || !rule.ports?.length) throw new Error('Network allowances require destinations and ports');
    return { to: rule.to, ports: rule.ports };
  });
  return { apiVersion: 'networking.k8s.io/v1', kind: 'NetworkPolicy', metadata: { name: 'breachbench-default-deny', namespace: c.namespace ?? 'default' }, spec: { podSelector: { matchLabels: { app: 'breachbench-candidate' } }, policyTypes: ['Ingress', 'Egress'], ingress: c.ingress ?? [], egress } };
}
export class Workflow {
  constructor(config, { root = '.breachbench', execute = run } = {}) {
    this.c = config; this.exec = execute; this.root = path.resolve(root); fs.mkdirSync(this.root, { recursive: true });
    this.fingerprint = configFingerprint(config);
  }
  save(name, value) { fs.writeFileSync(path.join(this.root, `${name}.json`), JSON.stringify({ fingerprint: this.fingerprint, ...value }, null, 2)); return value; }
  read(name) { const x = JSON.parse(fs.readFileSync(path.join(this.root, `${name}.json`))); if (x.fingerprint !== this.fingerprint) throw new Error('Stale evidence: config changed'); return x; }
  async invoke(name) {
    if (configFingerprint(this.c) !== this.fingerprint) throw new Error('Inputs changed during workflow; restart to discard stale evidence');
    const index = tools.indexOf(name);
    if (index < 0) throw new Error('Unknown tool');
    const stages = ['inspect', 'baseline-scan', 'proposal', 'build', 'functionality', 'enforcement', 'report'];
    for (const stage of stages.slice(index)) fs.rmSync(path.join(this.root, `${stage}.json`), { force: true });
    return this[name]();
  }
  imageInfo(image) { const i = JSON.parse(this.exec('docker', ['image', 'inspect', image]))[0]; return { id: i.Id, repoDigests: i.RepoDigests ?? [], size: i.Size, user: i.Config.User, exposedPorts: i.Config.ExposedPorts, volumes: i.Config.Volumes }; }
  inspect_container() {
    const pin = this.exec('git', ['-C', WORKBENCH, 'rev-parse', 'HEAD']).trim();
    if (pin !== PIN) throw new Error('Work-bench checkout differs from pinned commit');
    const source = this.imageInfo(this.c.image);
    if (this.c.seccompProfile && fs.existsSync(`${this.c.seccompProfile}.review.json`)) {
      assertReviewBinding(this.c.seccompProfile, JSON.parse(fs.readFileSync(`${this.c.seccompProfile}.review.json`)), source.id);
    }
    // Invoke the actual in-repo work-bench, rather than substituting our own filesystem inspection.
    // Bind the extracted filesystem to the exact image ID and invalidate cached files when the image ID changes.
    const filesystem = process.env.BREACHBENCH_WORKBENCH_ROOT
      ? path.join(path.resolve(process.env.BREACHBENCH_WORKBENCH_ROOT), digest(this.root), 'filesystem')
      : path.join(this.root, 'workbench-filesystem');
    const metaFile = `${filesystem}.meta.json`;
    let cachedMeta = null;
    if (fs.existsSync(metaFile)) {
      try { cachedMeta = JSON.parse(fs.readFileSync(metaFile, 'utf8')); } catch { cachedMeta = null; }
    }
    const cacheInvalidated = Boolean(cachedMeta && (cachedMeta.imageId !== source.id || cachedMeta.commit !== pin));
    if (!cachedMeta || cacheInvalidated || !fs.existsSync(filesystem)) {
      fs.rmSync(filesystem, { recursive: true, force: true });
      fs.rmSync(metaFile, { force: true });
      fs.mkdirSync(filesystem, { recursive: true });
      this.exec('go', ['run', '.', 'inspect', '--tag', source.id, '--output', filesystem], { cwd: WORKBENCH });
      fs.mkdirSync(path.dirname(metaFile), { recursive: true });
      fs.writeFileSync(metaFile, JSON.stringify({ imageId: source.id, commit: pin }, null, 2));
    }
    return this.save('inspect', { source, workbench: { path: WORKBENCH, commit: pin, filesystem, imageId: source.id, cacheInvalidated } });
  }
  scan(image) {
    const imageReport = JSON.parse(this.exec('trivy', ['image', '--format', 'json', '--scanners', 'vuln,secret,misconfig', '--image-config-scanners', 'misconfig,secret', image]));
    const configReport = JSON.parse(this.exec('trivy', ['config', '--format', 'json', this.c.context]));
    // Do not persist raw secret matches, Docker environment variables, or source snippets.
    return { image: this.imageInfo(image), coverage: { osFamily: imageReport.Metadata?.OS?.Family ?? null }, findings: [...normalizeTrivy(imageReport), ...normalizeTrivy(configReport)] };
  }
  scan_image() {
    const inspected = this.read('inspect');
    if (this.imageInfo(this.c.image).id !== inspected.source.id) throw new Error('Stale evidence: source image ID changed since work-bench inspection');
    const scan = this.scan(inspected.source.id);
    if (scan.image.id !== inspected.source.id) throw new Error('Stale evidence: source image ID changed since work-bench inspection');
    return this.save('baseline-scan', scan);
  }
  propose_hardening() {
    this.read('baseline-scan');
    const source = this.read('inspect').source;
    // A locally built repo digest need not exist in a registry. Retain the exact
    // inspected image under an ID-derived local tag and recheck it before build.
    const sourceRef = `breachbench/source:${source.id.replace('sha256:', '')}`;
    this.exec('docker', ['tag', source.id, sourceRef]);
    this.save('build-source', { reference: sourceRef, id: source.id });
    const remediation = planRemediation(this.c, sourceRef, this.read('baseline-scan').findings);
    this.save('remediation-plan', remediation);
    fs.writeFileSync(path.join(this.root, 'Containerfile.candidate'), remediation.dockerfile);
    fs.writeFileSync(path.join(this.root, 'network-policy.json'), JSON.stringify(networkPolicy(this.c), null, 2));
    fs.writeFileSync(path.join(this.root, 'pod-controls.json'), JSON.stringify({ automountServiceAccountToken: false, securityContext: { runAsNonRoot: true, runAsUser: Number(this.c.user.split(':')[0]), runAsGroup: Number(this.c.user.split(':')[1]), seccompProfile: { type: 'RuntimeDefault' } }, containers: [{ name: 'app', image: this.c.candidate, securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ['ALL'] } }, resources: { limits: { memory: this.c.memory.toUpperCase().replace('M', 'Mi').replace('G', 'Gi'), cpu: String(this.c.cpus) } } }] }, null, 2));
    if (this.c.observedSyscalls?.length) {
      if (this.c.observedSyscalls.some(s => !/^[a-z0-9_]+$/.test(s))) throw new Error('Invalid syscall');
      fs.writeFileSync(path.join(this.root, 'seccomp.candidate.json'), JSON.stringify({ defaultAction: 'SCMP_ACT_ERRNO', syscalls: [{ names: this.c.observedSyscalls, action: 'SCMP_ACT_ALLOW' }] }, null, 2));
    }
    return this.save('proposal', { imageChanges: ['Immutable source ID; non-root USER', 'Optional Slim runtime-observed removal'], deploymentControls: ['Drop ALL capabilities', 'no-new-privileges', 'Read-only root with scoped tmpfs', 'CPU/memory/PID limits', 'No host mounts, privileged mode or Docker socket', 'Docker network none; separate Kubernetes policy requires CNI enforcement', 'Optional reviewed seccomp and AppArmor/SELinux profiles'], reviewRequired: ['Run representative foreground, background and uncommon-path workloads', 'Review traced syscall allowlist and LSM permissions before enforcement', 'Add only capabilities supported by failure evidence; no automatic capability restoration', 'Rotate discovered credentials; use external short-lived scoped credentials', 'Confirm required DNS/API/database ingress and egress in Kubernetes'], rollback: { image: this.read('inspect').source.id, note: 'Original image and deployment are untouched; candidate is never promoted automatically' } });
  }
  build_candidate() {
    this.read('proposal');
    if (this.imageInfo(this.c.image).id !== this.read('inspect').source.id) throw new Error('Source tag changed; inspect again');
    if (this.imageInfo(this.read('build-source').reference).id !== this.read('inspect').source.id) throw new Error('Pinned build source changed');
    this.exec('docker', ['build', '-f', path.join(this.root, 'Containerfile.candidate'), '-t', this.c.candidate, this.c.context]);
    let slim = false;
    if (this.c.slim) {
      if (!this.c.slim.execFile || !this.c.slim.includePaths?.length) throw new Error('Slim requires representative execFile and explicit includePaths');
      const apiVersion = this.exec('docker', ['version', '--format', '{{.Server.APIVersion}}']).trim();
      if (!/^1\.\d+$/.test(apiVersion)) throw new Error('Unable to determine Docker API version for Slim');
      const args = ['--crt-api-version', apiVersion, '--check-version=false', '--report', path.join(this.root, 'slim-report.json'), 'build', '--target', this.c.candidate, '--tag', `${this.c.candidate}-slim`, '--http-probe=false', '--include-cert-pk-all=false', '--continue-after=exec', '--exec-file', path.resolve(this.c.slim.execFile)];
      for (const p of this.c.slim.includePaths) args.push('--include-path', p);
      for (const name of this.c.slim.removeEnv ?? []) {
        if (!/^[A-Z_][A-Z0-9_]*$/.test(name)) throw new Error('Invalid Slim environment key');
        args.push('--remove-env', name);
      }
      this.exec('slim', args); slim = true;
    }
    const candidate = slim ? `${this.c.candidate}-slim` : this.c.candidate;
    return this.save('build', { candidate, image: this.imageInfo(candidate), slim });
  }
  async suite(image, hardened, tests) {
    const name = `breachbench-${crypto.randomUUID()}`; let started = false;
    try {
      this.exec('docker', runtimeArgs(this.c, name, image, hardened)); started = true;
      await new Promise(resolve => setTimeout(resolve, this.c.startupMs ?? 1000));
      const running = JSON.parse(this.exec('docker', ['inspect', '--format', '{{json .State.Running}}', name]));
      if (!running) throw new Error('Application exited before tests');
      const results = [];
      for (const test of tests) {
        try {
          const argv = test.argv.map(a => a.replaceAll('{container}', name).replaceAll('{image}', image));
          const output = this.exec(argv[0], argv.slice(1), { timeout: test.timeoutMs ?? 60000 });
          results.push({ name: test.name, category: test.category, passed: test.expect ? output.includes(test.expect) : true });
        } catch { results.push({ name: test.name, category: test.category, passed: false }); }
      }
      if (!JSON.parse(this.exec('docker', ['inspect', '--format', '{{json .State.Running}}', name]))) results.push({ name: 'application-still-running', passed: false });
      return results;
    } finally { if (started) this.exec('docker', ['rm', '-f', name]); }
  }
  async test_application() {
    const build = this.read('build');
    for (const category of ['foreground', 'background', 'uncommon']) if (!this.c.tests?.some(t => t.category === category)) throw new Error(`Missing representative ${category} test`);
    if (this.imageInfo(build.candidate).id !== build.image.id) throw new Error('Candidate changed');
    const baseline = await this.suite(this.read('inspect').source.id, false, this.c.tests);
    const candidate = await this.suite(build.image.id, true, this.c.tests);
    return this.save('functionality', { imageId: build.image.id, baseline, candidate, passed: [...baseline, ...candidate].every(t => t.passed) });
  }
  async verify_hardening() {
    const build = this.read('build'); const functionality = this.read('functionality');
    if (!functionality.passed || functionality.imageId !== build.image.id) throw new Error('Functionality must pass first');
    const required = ['filesystem', 'network', 'capabilities', 'syscalls', 'identity', 'privilege-escalation', 'resources'];
    const results = await this.suite(build.image.id, true, this.c.enforcementTests ?? []);
    const missing = required.filter(k => !results.some(t => t.category === k && t.passed));
    if (this.c.apparmorProfile || this.c.selinuxType) {
      if (!results.some(t => t.category === 'lsm' && t.passed)) missing.push('lsm');
      const secOpts = String(this.exec('docker', ['info', '--format', '{{json .SecurityOptions}}']));
      if (this.c.apparmorProfile && !secOpts.includes('apparmor')) missing.push('apparmor-host-support');
      if (this.c.selinuxType && !secOpts.includes('selinux')) missing.push('selinux-host-support');
    }
    return this.save('enforcement', { imageId: build.image.id, results, missing, passed: !missing.length && results.every(t => t.passed), kubernetesNetworkEnforcement: 'unverified: apply policy on a CNI-enabled cluster and test allowed and denied destinations' });
  }
  compare_results() {
    const build = this.read('build'); const functional = this.read('functionality'); const enforcement = this.read('enforcement');
    if (this.imageInfo(build.candidate).id !== build.image.id) throw new Error('Candidate changed');
    const after = this.scan(build.image.id); const before = this.read('baseline-scan');
    // Image labels differ between scans; compare the affected component and issue.
    const findingKey = ({ target, ...finding }) => digest(finding);
    const regression = after.findings.some(f => ['CRITICAL', 'HIGH'].includes(f.severity) && !before.findings.some(old => findingKey(old) === findingKey(f)));
    const coverageReduced = Boolean(before.coverage?.osFamily && before.coverage.osFamily !== 'none' && (!after.coverage.osFamily || after.coverage.osFamily === 'none'));
    return this.save('report', {
      status: functional.passed && enforcement.passed && !regression && !coverageReduced ? 'eligible-for-review' : 'rejected',
      promoted: false,
      imageChanges: { before: before.image, after: after.image, bytesRemoved: before.image.size - after.image.size },
      findings: after.findings,
      remediation: this.read('remediation-plan'),
      scannerCoverage: { before: before.coverage, after: after.coverage, reduced: coverageReduced },
      securityRegression: regression,
      functionality: functional,
      enforcement,
      rollback: this.read('proposal').rollback,
      remainingRisks: [
        'Hardening does not repair vulnerable PHP or other runtimes, or prevent every exploit',
        'Observed workloads cannot prove completeness; retain excluded-path regression tests',
        'Kubernetes policy, LSM enforcement and secret rotation require deployment-specific verification',
        'Slim image accepted for review only after representative tests; original image preserved',
        'Removed files and scanner metadata changes do not prove vulnerabilities were fixed; retain and review baseline-scan.json'
      ]
    });
  }
}
