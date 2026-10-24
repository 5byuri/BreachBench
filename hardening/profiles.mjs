// Generate, validate, and review security profiles from reproducible workload traces.
// Observation and automated validation do NOT establish permission review; generated candidates keep reviewed: false.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadConfig, PIN, WORKBENCH } from './lib.mjs';

export const REQUIRED_PHASES = ['startup', 'foreground', 'background', 'uncommon', 'shutdown'];

export const JUSTIFIED_ADDITIONAL_SYSCALLS = {
  openat2: 'runc:[2:INIT] executes openat2 (syscall 437) with RESOLVE_NO_MAGICLINKS on /proc descriptors after loading the seccomp filter (when no-new-privileges is enabled) and before execve; verified via SCMP_ACT_LOG kernel audit.',
  fstatfs: 'runc:[2:INIT] executes fstatfs (syscall 138) to verify PROC_SUPER_MAGIC on /proc descriptors after loading the seccomp filter and before execve; verified via SCMP_ACT_LOG kernel audit.',
  statx: 'runc:[2:INIT] executes statx (syscall 332) on executable and stdio file descriptors after loading the seccomp filter and before execve; verified via SCMP_ACT_LOG kernel audit.',
  exit: 'glibc/pthreads worker threads terminate individual threads via exit (syscall 60) while process termination uses exit_group (syscall 231).',
  madvise: 'glibc pthreads/malloc arena management invokes madvise (syscall 28, MADV_DONTNEED) when releasing worker thread stacks and arenas during thread exit or shutdown.'
};

export const FORBIDDEN_CANDIDATE_SYSCALLS = [
  'getppid', 'getpgid', 'ptrace', 'mount', 'umount2', 'bpf', 'perf_event_open',
  'kexec_load', 'kexec_file_load', 'init_module', 'finit_module', 'delete_module',
  'pivot_root', 'chroot', 'swapon', 'swapoff', 'reboot', 'setns', 'unshare',
  'keyctl', 'add_key', 'request_key', 'userfaultfd', 'capset', 'setuid', 'setgid',
  'setreuid', 'setregid', 'setresuid', 'setresgid', 'setgroups', 'setfsuid',
  'setfsgid', 'chown', 'fchown', 'fchownat', 'lchown'
];

const DEFAULT_ARCHITECTURES = ['SCMP_ARCH_X86_64', 'SCMP_ARCH_X86', 'SCMP_ARCH_X32'];

const execCmd = (exe, args, opts = {}) => execFileSync(exe, args, {
  encoding: 'utf8',
  maxBuffer: 50 * 1024 * 1024,
  stdio: ['ignore', 'pipe', 'pipe'],
  ...opts
}).trim();

export function parseStrace(text) {
  const calls = [
    ...text.matchAll(/(?:^|\n)(?:\[pid\s+\d+\]\s+|\d+\s+)?(?:\d\d:\d\d:\d\d(?:\.\d+)?\s+)?([a-z][a-z0-9_]*)\(/g),
    ...text.matchAll(/(?:^|\n)(?:\[pid\s+\d+\]\s+|\d+\s+)?(?:\d\d:\d\d:\d\d(?:\.\d+)?\s+)?<\.\.\.\s+([a-z][a-z0-9_]*)\s+resumed>/g)
  ].map(match => match[1]).filter(name => name !== 'ptrace');
  return [...new Set(calls)].sort();
}

export function buildSeccompCandidate(observedInput, output, options = {}) {
  const isPhaseMap = observedInput && typeof observedInput === 'object' && !Array.isArray(observedInput);
  const observedByPhase = isPhaseMap
    ? Object.fromEntries(Object.entries(observedInput).map(([phase, list]) => [phase, [...new Set(list)].sort()]))
    : (options.observedByPhase || null);
  const observedSyscalls = isPhaseMap
    ? [...new Set(Object.values(observedByPhase).flat())].sort()
    : [...new Set(observedInput || [])].sort();
  if (!observedSyscalls.length) throw new Error('No syscalls parsed; use strace -f -o workload.strace');

  const additionalSyscalls = options.additionalSyscalls ?? (isPhaseMap ? JUSTIFIED_ADDITIONAL_SYSCALLS : {});
  const allowedSyscalls = [...new Set([...observedSyscalls, ...Object.keys(additionalSyscalls)])].sort();
  const profile = {
    defaultAction: 'SCMP_ACT_ERRNO',
    defaultErrnoRet: 1,
    architectures: options.architectures || DEFAULT_ARCHITECTURES,
    syscalls: [{ names: allowedSyscalls, action: 'SCMP_ACT_ALLOW' }]
  };
  const reviewSidecar = {
    reviewed: false,
    reviewType: 'unreviewed-candidate',
    reviewEvidence: null,
    enforcement: 'not-tested',
    defaultAction: 'SCMP_ACT_ERRNO',
    ...(observedByPhase ? { observedByPhase } : {}),
    observedSyscalls,
    additionalSyscalls,
    allowedSyscalls,
    excludedProbeSyscalls: ['getppid', 'getpgid'],
    ...(options.workbenchAnalysis ? { workbenchAnalysis: options.workbenchAnalysis } : {}),
    requiredReview: [
      'Merge foreground, startup, shutdown, background, uncommon-path and failure/recovery traces',
      'Review architecture, clone/exec, network and filesystem permissions',
      'Verify every entry in additionalSyscalls has an explicit runtime or libc justification',
      'Confirm harmless probe syscalls (getppid, getpgid) remain excluded for negative enforcement testing',
      'Test enforced profile separately; add only demonstrated requirements',
      'AppArmor: use aa-genprof/aa-logprof against same workloads on target host; review before aa-enforce',
      'SELinux: collect AVCs in a dedicated test domain; review audit2allow output, never load it blindly'
    ]
  };
  if (output) {
    fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
    fs.writeFileSync(output, JSON.stringify(profile, null, 2));
    fs.writeFileSync(`${output}.review.json`, JSON.stringify(reviewSidecar, null, 2));
  }
  return {
    candidate: output,
    syscallCount: allowedSyscalls.length,
    observedCount: observedSyscalls.length,
    additionalCount: Object.keys(additionalSyscalls).length,
    enforcement: 'not-tested',
    reviewed: false,
    reviewType: 'unreviewed-candidate',
    profile,
    reviewSidecar
  };
}

export function validateSeccompCandidate(candidatePath, reviewedPath = null) {
  const candidate = JSON.parse(fs.readFileSync(candidatePath, 'utf8'));
  const sidecarPath = `${candidatePath}.review.json`;
  if (!fs.existsSync(sidecarPath)) throw new Error(`Missing review sidecar: ${sidecarPath}`);
  const sidecar = JSON.parse(fs.readFileSync(sidecarPath, 'utf8'));

  if (candidate.defaultAction !== 'SCMP_ACT_ERRNO') {
    throw new Error('Seccomp candidate must use default-deny SCMP_ACT_ERRNO');
  }
  const missingPhases = REQUIRED_PHASES.filter(phase => !Array.isArray(sidecar.observedByPhase?.[phase]) || sidecar.observedByPhase[phase].length === 0);
  if (missingPhases.length) {
    throw new Error(`Seccomp candidate is missing required workload phases: ${missingPhases.join(', ')}`);
  }

  const allowed = [...new Set((candidate.syscalls || []).filter(rule => rule.action === 'SCMP_ACT_ALLOW').flatMap(rule => rule.names || []))].sort();
  const observedSet = new Set(sidecar.observedSyscalls || []);
  const additional = sidecar.additionalSyscalls || {};
  const unjustified = allowed.filter(name => !observedSet.has(name) && (!additional[name] || typeof additional[name] !== 'string' || !additional[name].trim()));
  if (unjustified.length) {
    throw new Error(`Unjustified non-observed syscalls in candidate: ${unjustified.join(', ')}`);
  }

  const forbiddenPresent = allowed.filter(name => FORBIDDEN_CANDIDATE_SYSCALLS.includes(name));
  if (forbiddenPresent.length) {
    throw new Error(`Candidate contains forbidden or negative-probe syscalls: ${forbiddenPresent.join(', ')}`);
  }

  const automatedValidation = {
    passed: true,
    validatedAt: new Date().toISOString(),
    validationType: 'automated-structural-and-policy-check',
    checks: {
      defaultDeny: true,
      phasesComplete: REQUIRED_PHASES,
      allAdditionsJustified: true,
      forbiddenAndProbeSyscallsExcluded: ['getppid', 'getpgid'],
      allowedCount: allowed.length,
      observedCount: observedSet.size,
      additionalCount: Object.keys(additional).length
    }
  };

  // Automated validation never marks a candidate as reviewed: true
  const updatedSidecar = {
    ...sidecar,
    reviewed: false,
    reviewType: 'automated-validation-only',
    reviewEvidence: null,
    automatedValidation
  };
  fs.writeFileSync(sidecarPath, JSON.stringify(updatedSidecar, null, 2));

  let reviewedStatus = null;
  if (reviewedPath) {
    if (!fs.existsSync(reviewedPath) || !fs.existsSync(`${reviewedPath}.review.json`)) {
      throw new Error(`Reviewed seccomp profile not found at ${reviewedPath}; perform explicit permission review before running enforcement`);
    }
    const reviewedProfile = JSON.parse(fs.readFileSync(reviewedPath, 'utf8'));
    const reviewedSidecar = JSON.parse(fs.readFileSync(`${reviewedPath}.review.json`, 'utf8'));
    if (reviewedSidecar.reviewed !== true) {
      throw new Error(`Profile at ${reviewedPath} is not marked reviewed: true`);
    }
    if (!reviewedSidecar.reviewType || ['automated', 'automated-validation-only', 'unreviewed-candidate', 'none'].includes(reviewedSidecar.reviewType)) {
      throw new Error(`Profile at ${reviewedPath} lacks an explicit non-automated reviewType`);
    }
    if (!reviewedSidecar.reviewEvidence || (typeof reviewedSidecar.reviewEvidence === 'string' && !reviewedSidecar.reviewEvidence.trim()) || (typeof reviewedSidecar.reviewEvidence === 'object' && !Object.keys(reviewedSidecar.reviewEvidence).length)) {
      throw new Error(`Profile at ${reviewedPath} lacks reviewEvidence`);
    }
    const reviewedAllowed = [...new Set((reviewedProfile.syscalls || []).filter(r => r.action === 'SCMP_ACT_ALLOW').flatMap(r => r.names || []))].sort();
    if (JSON.stringify(reviewedAllowed) !== JSON.stringify(allowed)) {
      throw new Error('Observed candidate syscalls drifted from the reviewed profile; re-review permissions explicitly');
    }
    reviewedStatus = {
      reviewedPath,
      reviewed: true,
      reviewType: reviewedSidecar.reviewType,
      reviewEvidence: reviewedSidecar.reviewEvidence
    };
  }

  return {
    candidatePath,
    reviewed: false,
    reviewType: 'automated-validation-only',
    automatedValidation,
    reviewedProfileVerification: reviewedStatus,
    allowed,
    observedSet,
    additional,
    candidate,
    sidecar: updatedSidecar
  };
}

export function reviewSeccompCandidate(candidatePath, reviewedPath, options = {}) {
  const { reviewType, reviewEvidence } = options;
  if (!reviewType || typeof reviewType !== 'string' || ['automated', 'automated-validation-only', 'unreviewed-candidate', 'none'].includes(reviewType)) {
    throw new Error('Explicit permission review requires a non-automated reviewType (e.g. manual-permission-review)');
  }
  const hasEvidence = reviewEvidence && (
    (typeof reviewEvidence === 'string' && reviewEvidence.trim().length > 0) ||
    (typeof reviewEvidence === 'object' && Object.keys(reviewEvidence).length > 0)
  );
  if (!hasEvidence) {
    throw new Error('Explicit permission review requires reviewEvidence documenting the reviewed traces and syscall justifications');
  }

  const validation = validateSeccompCandidate(candidatePath);
  const { candidate, sidecar, allowed, observedSet, additional, automatedValidation } = validation;

  const reviewedProfile = {
    defaultAction: 'SCMP_ACT_ERRNO',
    defaultErrnoRet: candidate.defaultErrnoRet ?? 1,
    architectures: candidate.architectures || DEFAULT_ARCHITECTURES,
    syscalls: [{ names: allowed, action: 'SCMP_ACT_ALLOW' }]
  };
  const reviewedSidecar = {
    ...sidecar,
    reviewed: true,
    reviewType,
    reviewedAt: new Date().toISOString(),
    reviewEvidence,
    sourceCandidate: candidatePath,
    allowedSyscalls: allowed,
    automatedValidation,
    reviewChecks: automatedValidation.checks
  };

  if (reviewedPath) {
    fs.mkdirSync(path.dirname(path.resolve(reviewedPath)), { recursive: true });
    fs.writeFileSync(reviewedPath, JSON.stringify(reviewedProfile, null, 2));
    fs.writeFileSync(`${reviewedPath}.review.json`, JSON.stringify(reviewedSidecar, null, 2));
  }

  let reviewedConfig = null;
  if (options.baseConfigPath && options.reviewedConfigPath) {
    const baseRaw = JSON.parse(fs.readFileSync(options.baseConfigPath, 'utf8'));
    const repoRel = path.relative(process.cwd(), path.resolve(reviewedPath)).replace(/\\/g, '/');
    baseRaw.seccompProfile = !repoRel.startsWith('..') ? repoRel : path.resolve(reviewedPath);
    baseRaw.profilesReviewed = true;
    baseRaw.enforcementTests = (baseRaw.enforcementTests || []).map(testDef => {
      if (testDef.category !== 'syscalls' && testDef.control !== 'syscalls') return testDef;
      return {
        ...testDef,
        argv: [
          'docker', 'exec', '{container}', 'python', '-c',
          "import ctypes,errno,os,platform; assert os.getpid()>0; c=ctypes.CDLL(None,use_errno=True); nums={'x86_64':(110,121),'aarch64':(173,155)}[platform.machine()]; assert all(c.syscall(n)==-1 and ctypes.get_errno()==errno.EPERM for n in nums); s=dict(x.split(':',1) for x in open('/proc/1/status') if ':' in x); assert s['Seccomp'].strip()=='2'"
        ]
      };
    });
    fs.mkdirSync(path.dirname(path.resolve(options.reviewedConfigPath)), { recursive: true });
    fs.writeFileSync(options.reviewedConfigPath, JSON.stringify(baseRaw, null, 2));
    reviewedConfig = options.reviewedConfigPath;
  }

  return {
    reviewedProfilePath: reviewedPath,
    reviewedConfigPath: reviewedConfig,
    reviewed: true,
    reviewType,
    reviewEvidence,
    syscallCount: allowed.length,
    observedCount: observedSet.size,
    additionalCount: Object.keys(additional).length,
    excludedProbeSyscalls: ['getppid', 'getpgid']
  };
}

export function ensureWorkbenchFilesystem(image, wbRoot = process.env.BREACHBENCH_WORKBENCH_ROOT || path.join(os.tmpdir(), 'breachbench-workbench'), execute = execCmd) {
  const head = execute('git', ['-C', WORKBENCH, 'rev-parse', 'HEAD']).trim();
  if (head !== PIN) throw new Error(`Unverified work-bench commit: ${head}`);
  const imgMeta = JSON.parse(execute('docker', ['image', 'inspect', image]))[0];
  const imageId = imgMeta?.Id;
  if (!imageId) throw new Error(`Unable to resolve immutable image ID for ${image}`);

  const mergedFs = path.join(path.resolve(wbRoot), 'trace-filesystem');
  const metaFile = `${mergedFs}.meta.json`;
  let cachedMeta = null;
  if (fs.existsSync(metaFile)) {
    try { cachedMeta = JSON.parse(fs.readFileSync(metaFile, 'utf8')); } catch { cachedMeta = null; }
  }

  const cacheValid = Boolean(
    cachedMeta &&
    cachedMeta.imageId === imageId &&
    cachedMeta.workbenchCommit === head &&
    fs.existsSync(mergedFs)
  );
  const cacheInvalidated = Boolean(cachedMeta && !cacheValid);

  if (!cacheValid) {
    fs.rmSync(mergedFs, { recursive: true, force: true });
    fs.rmSync(metaFile, { force: true });
    fs.mkdirSync(mergedFs, { recursive: true });
    execute('go', ['run', '.', 'inspect', '--tag', image, '--output', mergedFs], { cwd: WORKBENCH });
    fs.writeFileSync(metaFile, JSON.stringify({
      imageId,
      image,
      workbenchCommit: head,
      extractedAt: new Date().toISOString()
    }, null, 2));
  }

  return {
    mergedFs,
    metaFile,
    imageId,
    workbenchCommit: head,
    imgMeta,
    cacheHit: cacheValid,
    cacheInvalidated
  };
}

export function checkLsmSupport(options = {}) {
  const execute = options.execute || execCmd;
  const fsMod = options.fsModule || fs;
  const readIfExists = filePath => {
    try {
      return fsMod.existsSync(filePath) ? fsMod.readFileSync(filePath, 'utf8').trim() : null;
    } catch {
      return null;
    }
  };
  const hasTool = tool => {
    try {
      const out = execute('sh', ['-lc', `command -v ${tool}`]);
      return Boolean(out && out.trim());
    } catch {
      return false;
    }
  };

  let dockerSecurityOptions = [];
  try {
    dockerSecurityOptions = JSON.parse(execute('docker', ['info', '--format', '{{json .SecurityOptions}}']) || '[]') || [];
  } catch {
    dockerSecurityOptions = [];
  }

  const kernelVersion = readIfExists('/proc/version');
  const lsmList = readIfExists('/sys/kernel/security/lsm');
  const apparmorParam = readIfExists('/sys/module/apparmor/parameters/enabled');
  const securityfsApparmor = Boolean(fsMod.existsSync('/sys/kernel/security/apparmor'));
  const selinuxfsMounted = Boolean(fsMod.existsSync('/sys/fs/selinux/enforce'));

  const dockerHasSeccomp = dockerSecurityOptions.some(opt => String(opt).includes('name=seccomp'));
  const dockerHasApparmor = dockerSecurityOptions.some(opt => String(opt).includes('name=apparmor'));
  const dockerHasSelinux = dockerSecurityOptions.some(opt => String(opt).includes('name=selinux'));

  const apparmorTools = {
    apparmor_parser: hasTool('apparmor_parser'),
    'aa-status': hasTool('aa-status'),
    'aa-genprof': hasTool('aa-genprof'),
    'aa-logprof': hasTool('aa-logprof'),
    'aa-enforce': hasTool('aa-enforce')
  };
  const selinuxTools = {
    sestatus: hasTool('sestatus'),
    getenforce: hasTool('getenforce'),
    semodule: hasTool('semodule'),
    audit2allow: hasTool('audit2allow')
  };

  const apparmorSupported = apparmorParam === 'Y' && securityfsApparmor && dockerHasApparmor && apparmorTools.apparmor_parser;
  const selinuxSupported = selinuxfsMounted && dockerHasSelinux && selinuxTools.sestatus;

  let candidateAudit = null;
  const slimArtifactPath = options.slimArtifactPath || findSlimApparmorArtifact(fsMod);
  if (slimArtifactPath && fsMod.existsSync(slimArtifactPath)) {
    const content = fsMod.readFileSync(slimArtifactPath, 'utf8');
    candidateAudit = {
      artifactPath: slimArtifactPath,
      verified: false,
      tested: false,
      enforced: false,
      status: 'unverified-artifact-host-unsupported',
      findings: [
        ...(content.includes('network,') ? ['Contains broad "network," rule permitting all socket families despite --network none workload policy'] : []),
        ...(content.includes('/usr/share/ca-certificates/') ? ['Hardcodes individual CA certificate paths observed only during single trace run'] : [])
      ]
    };
  }

  return {
    checkedAt: new Date().toISOString(),
    overallStatus: (apparmorSupported && selinuxSupported)
      ? 'host-supported-enforcement-unverified'
      : 'partial-seccomp-only-apparmor-selinux-unverified',
    host: {
      kernel: kernelVersion,
      lsmList
    },
    dockerSecurityOptions,
    seccomp: {
      supported: dockerHasSeccomp,
      enforced: dockerHasSeccomp
    },
    apparmor: {
      supported: apparmorSupported,
      verified: false,
      tested: false,
      enforced: false,
      status: apparmorSupported ? 'unverified-not-enforced' : 'unverified-on-host',
      checks: {
        kernelModuleEnabled: apparmorParam,
        securityfsApparmor,
        dockerSecurityOption: dockerHasApparmor,
        tools: apparmorTools
      },
      candidateAudit,
      targetHostRequirements: [
        'Linux kernel booted with AppArmor LSM enabled (/sys/module/apparmor/parameters/enabled = Y and /sys/kernel/security/apparmor mounted)',
        'Userspace tools installed (apparmor, apparmor-utils: apparmor_parser, aa-status, aa-genprof, aa-logprof, aa-enforce)',
        'Docker daemon reporting "name=apparmor" in docker info --format "{{json .SecurityOptions}}"',
        'Profile refined with aa-genprof/aa-logprof across startup, foreground, background, uncommon and shutdown workloads, loaded via apparmor_parser -r -W, and verified via /proc/self/attr/current under --security-opt apparmor=<profile>'
      ]
    },
    selinux: {
      supported: selinuxSupported,
      verified: false,
      tested: false,
      enforced: false,
      status: selinuxSupported ? 'unverified-not-enforced' : 'unverified-on-host',
      checks: {
        selinuxfsMounted,
        dockerSecurityOption: dockerHasSelinux,
        tools: selinuxTools
      },
      targetHostRequirements: [
        'Linux kernel booted with SELinux LSM enabled and selinuxfs mounted at /sys/fs/selinux',
        'Userspace policy toolchain installed (policycoreutils, selinux-policy-devel, container-selinux: sestatus, getenforce, semodule, audit2allow)',
        'Docker daemon configured with --selinux-enabled and reporting "name=selinux" in docker info --format "{{json .SecurityOptions}}"',
        'AVCs collected in a dedicated permissive container_t subdomain across all workload phases and reviewed line-by-line before enforcing with --security-opt label=type:<domain>.process'
      ]
    }
  };
}

function findSlimApparmorArtifact(fsMod) {
  const base = path.join(process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local/share'), 'breachbench/tools/slim/.mint-state/images');
  try {
    if (!fsMod.existsSync(base)) return null;
    for (const dir of fsMod.readdirSync(base)) {
      const artDir = path.join(base, dir, 'artifacts');
      if (!fsMod.existsSync(artDir)) continue;
      for (const file of fsMod.readdirSync(artDir)) {
        if (file.endsWith('-apparmor-profile')) return path.join(artDir, file);
      }
    }
  } catch {
    return null;
  }
  return null;
}

export async function captureWorkloadTrace(configFile = 'hardening/demo/config.json', outputDir = '.breachbench/seccomp-demo', options = {}) {
  const execute = options.execute || execCmd;
  const c = loadConfig(configFile);
  const outRoot = path.resolve(outputDir);
  const tracesDir = path.join(outRoot, 'traces');
  fs.mkdirSync(tracesDir, { recursive: true });

  // 1. Verify pinned Container Hardening Work Bench & extract filesystem bound to exact image ID
  const wbRoot = process.env.BREACHBENCH_WORKBENCH_ROOT || path.join(os.tmpdir(), 'breachbench-workbench');
  const wbState = ensureWorkbenchFilesystem(c.image, wbRoot, execute);
  const { mergedFs, imageId, imgMeta, cacheHit, cacheInvalidated } = wbState;

  let neededLibs = ['libpython3.12.so.1.0', 'libc.so.6'];
  try {
    const readelfOut = execute('readelf', [
      '-d',
      path.join(mergedFs, 'usr/local/bin/python3.12'),
      path.join(mergedFs, 'usr/local/lib/libpython3.12.so.1.0')
    ]);
    const parsedLibs = [...readelfOut.matchAll(/\[([^\]]+\.so[^\]]*)\]/g)].map(m => m[1]);
    if (parsedLibs.length) neededLibs = [...new Set(parsedLibs)].sort();
  } catch {
    // Keep default neededLibs if host readelf is unavailable
  }
  const workbenchAnalysis = {
    workbenchCommit: PIN,
    mergedFilesystem: mergedFs,
    image: c.image,
    imageId,
    cacheHit,
    cacheInvalidated,
    user: imgMeta.Config?.User,
    entrypoint: imgMeta.Config?.Entrypoint,
    cmd: imgMeta.Config?.Cmd,
    binary: '/usr/local/bin/python3.12',
    neededSharedLibraries: neededLibs
  };

  // 2. Reproducible multi-phase strace capture (strictly separated from enforcement testing)
  const straceRoot = options.straceRoot || path.join(process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local/share'), 'breachbench/tools/strace');
  if (!fs.existsSync(path.join(straceRoot, 'usr/bin/strace'))) {
    throw new Error(`User-local strace not found at ${straceRoot}; run bash hardening/setup-tools.sh`);
  }

  const tmpTraceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'breachbench-trace-'));
  fs.chmodSync(tmpTraceDir, 0o1777);
  const cname = `breachbench-trace-${Date.now()}`;
  const serverTraceTmp = path.join(tmpTraceDir, 'server.strace');

  const splitLines = text => (text ? text.split('\n').filter(Boolean) : []);
  const phaseLines = { startup: [], foreground: [], background: [], uncommon: [], shutdown: [] };

  try {
    execute('docker', [
      'run', '-d', '--name', cname,
      '--user', c.user,
      '--read-only',
      '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
      '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges:true',
      '--security-opt', 'seccomp=unconfined',
      '--pids-limit', String(c.pids),
      '--memory', c.memory,
      '--cpus', String(c.cpus),
      '--network', 'none',
      '-v', `${straceRoot}:/opt/strace:ro`,
      '-v', `${tmpTraceDir}:/trace:rw`,
      '-e', 'LD_LIBRARY_PATH=/opt/strace/lib',
      '--entrypoint', '/opt/strace/usr/bin/strace',
      c.image,
      '-f', '-s', '0', '-E', 'LD_LIBRARY_PATH', '-o', '/trace/server.strace',
      'python3', '/app/app.py'
    ]);

    const deadline = Date.now() + Math.max(c.startupMs || 1500, 3000);
    while (Date.now() < deadline) {
      if (fs.existsSync(serverTraceTmp)) {
        const current = fs.readFileSync(serverTraceTmp, 'utf8');
        if (current.includes('listen(') && (current.includes('poll(') || current.includes('epoll_wait(') || current.includes('select('))) {
          break;
        }
      }
      await new Promise(r => setTimeout(r, 150));
    }
    await new Promise(r => setTimeout(r, 250));

    let serverSnapshot = splitLines(fs.readFileSync(serverTraceTmp, 'utf8'));
    phaseLines.startup.push(...serverSnapshot);
    let cursor = serverSnapshot.length;

    for (let i = 0; i < c.tests.length; i++) {
      const t = c.tests[i];
      const rawKind = t.category || t.kind;
      const kind = ['foreground', 'background', 'uncommon'].includes(rawKind) ? rawKind : 'foreground';
      const inContainerCmd = t.command || t.argv.slice(t.argv.indexOf('{container}') + 1);
      const clientTraceName = `client-${i}-${kind}.strace`;
      execute('docker', [
        'exec', cname,
        '/opt/strace/usr/bin/strace', '-f', '-s', '0', '-E', 'LD_LIBRARY_PATH',
        '-o', `/trace/${clientTraceName}`,
        ...inContainerCmd
      ]);
      await new Promise(r => setTimeout(r, 150));
      const clientLines = splitLines(fs.readFileSync(path.join(tmpTraceDir, clientTraceName), 'utf8'));
      serverSnapshot = splitLines(fs.readFileSync(serverTraceTmp, 'utf8'));
      const serverDelta = serverSnapshot.slice(cursor);
      cursor = serverSnapshot.length;
      phaseLines[kind].push(...serverDelta, ...clientLines);
    }

    execute('docker', [
      'exec', cname,
      'python3', '-c',
      'import os, signal\nfor pid in os.listdir("/proc"):\n  if pid.isdigit() and int(pid) > 1:\n    comm = open(f"/proc/{pid}/comm", encoding="utf8").read().strip()\n    if comm.startswith("python"): os.kill(int(pid), signal.SIGINT); break'
    ]);

    const stopDeadline = Date.now() + 5000;
    while (Date.now() < stopDeadline) {
      const running = execute('docker', ['inspect', '-f', '{{.State.Running}}', cname]);
      if (running !== 'true') break;
      await new Promise(r => setTimeout(r, 150));
    }
    serverSnapshot = splitLines(fs.readFileSync(serverTraceTmp, 'utf8'));
    phaseLines.shutdown.push(...serverSnapshot.slice(cursor));
    fs.copyFileSync(serverTraceTmp, path.join(tracesDir, 'server-full.strace'));
  } finally {
    try { execute('docker', ['rm', '-f', cname]); } catch {}
    fs.rmSync(tmpTraceDir, { recursive: true, force: true });
  }

  const observedByPhase = {};
  for (const phase of REQUIRED_PHASES) {
    const phaseText = `${phaseLines[phase].join('\n')}\n`;
    fs.writeFileSync(path.join(tracesDir, `${phase}.strace`), phaseText);
    observedByPhase[phase] = parseStrace(phaseText);
  }

  const candidatePath = path.join(outRoot, 'seccomp.candidate.json');
  const candidateResult = buildSeccompCandidate(observedByPhase, candidatePath, { workbenchAnalysis });
  const validationResult = validateSeccompCandidate(candidatePath);
  const lsmReport = checkLsmSupport({ execute });
  const lsmPath = path.join(outRoot, 'lsm-support.json');
  fs.writeFileSync(lsmPath, JSON.stringify(lsmReport, null, 2));

  const observationReport = {
    generatedAt: new Date().toISOString(),
    configFile,
    image: c.image,
    imageId,
    workbenchAnalysis,
    phaseCounts: Object.fromEntries(REQUIRED_PHASES.map(p => [p, observedByPhase[p].length])),
    observedByPhase,
    observedSyscalls: candidateResult.reviewSidecar.observedSyscalls,
    observedCount: candidateResult.observedCount,
    additionalSyscalls: candidateResult.reviewSidecar.additionalSyscalls,
    additionalCount: candidateResult.additionalCount,
    allowedSyscalls: candidateResult.reviewSidecar.allowedSyscalls,
    allowedCount: candidateResult.syscallCount,
    excludedProbeSyscalls: ['getppid', 'getpgid'],
    candidatePath,
    reviewSidecarPath: `${candidatePath}.review.json`,
    lsmSupportPath: lsmPath,
    automatedValidation: validationResult.automatedValidation,
    reviewed: false,
    reviewType: 'automated-validation-only'
  };
  fs.writeFileSync(path.join(outRoot, 'syscall-observation.json'), JSON.stringify(observationReport, null, 2));
  return observationReport;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  const [cmdOrTrace, arg1, arg2] = args;
  if (cmdOrTrace === 'trace') {
    const res = await captureWorkloadTrace(arg1 || 'hardening/demo/config.json', arg2 || '.breachbench/seccomp-demo');
    console.log(JSON.stringify({
      candidate: res.candidatePath,
      imageId: res.imageId,
      observedCount: res.observedCount,
      additionalCount: res.additionalCount,
      syscallCount: res.allowedCount,
      phaseCounts: res.phaseCounts,
      reviewed: res.reviewed,
      reviewType: res.reviewType
    }, null, 2));
  } else if (cmdOrTrace === 'validate') {
    if (!arg1) throw new Error('Usage: node hardening/profiles.mjs validate <candidate.json> [reviewed.json]');
    const res = validateSeccompCandidate(arg1, arg2 || null);
    console.log(JSON.stringify({
      candidatePath: res.candidatePath,
      reviewed: res.reviewed,
      reviewType: res.reviewType,
      automatedValidation: res.automatedValidation,
      reviewedProfileVerification: res.reviewedProfileVerification
    }, null, 2));
  } else if (cmdOrTrace === 'review') {
    const typeIdx = args.indexOf('--review-type');
    const evIdx = args.indexOf('--review-evidence');
    const reviewType = typeIdx > 0 ? args[typeIdx + 1] : null;
    const rawEvidence = evIdx > 0 ? args[evIdx + 1] : null;
    let reviewEvidence = rawEvidence;
    if (rawEvidence && (rawEvidence.startsWith('{') || rawEvidence.endsWith('.json'))) {
      try {
        reviewEvidence = rawEvidence.startsWith('{')
          ? JSON.parse(rawEvidence)
          : JSON.parse(fs.readFileSync(rawEvidence, 'utf8'));
      } catch {
        reviewEvidence = rawEvidence;
      }
    }
    const positional = args.slice(1).filter((_, i, arr) => {
      const prev = i > 0 ? arr[i - 1] : null;
      const cur = arr[i];
      return cur !== '--review-type' && cur !== '--review-evidence' && prev !== '--review-type' && prev !== '--review-evidence';
    });
    const [cand, rev, baseCfg, revCfg] = positional;
    if (!cand || !rev) {
      throw new Error('Usage: node hardening/profiles.mjs review <candidate.json> <reviewed.json> --review-type <type> --review-evidence <evidence> [baseConfig.json] [reviewedConfig.json]');
    }
    const res = reviewSeccompCandidate(cand, rev, {
      reviewType,
      reviewEvidence,
      baseConfigPath: baseCfg,
      reviewedConfigPath: revCfg
    });
    console.log(JSON.stringify(res, null, 2));
  } else if (cmdOrTrace === 'lsm-check') {
    const res = checkLsmSupport();
    if (arg1) {
      fs.mkdirSync(path.dirname(path.resolve(arg1)), { recursive: true });
      fs.writeFileSync(arg1, JSON.stringify(res, null, 2));
    }
    console.log(JSON.stringify(res, null, 2));
  } else {
    if (!cmdOrTrace || !arg1) throw new Error('Usage: node hardening/profiles.mjs workload.strace output.json');
    const text = fs.readFileSync(cmdOrTrace, 'utf8');
    const names = parseStrace(text);
    if (!names.length) throw new Error('No syscalls parsed; use strace -f -o workload.strace');
    const res = buildSeccompCandidate(names, arg1, { additionalSyscalls: {} });
    console.log(JSON.stringify({ candidate: arg1, syscallCount: res.syscallCount, enforcement: 'not-tested', reviewed: false }));
  }
}
