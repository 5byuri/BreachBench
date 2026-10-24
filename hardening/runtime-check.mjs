import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { run } from './lib.mjs';

export function verifyResourceEnforcement(execute = run) {
  const root = path.resolve('.breachbench/resources'); fs.mkdirSync(root, { recursive: true });
  const results = [];
  const probes = {
    cpu: "import time; start=time.monotonic();\nwhile time.monotonic()-start<2: pass\ns=dict(x.split() for x in open('/sys/fs/cgroup/cpu.stat')); assert int(s['nr_throttled'])>0 and int(s['throttled_usec'])>0",
    pids: "import os,time,signal,errno; children=[]\ntry:\n while True:\n  try: p=os.fork()\n  except OSError as e: assert e.errno==errno.EAGAIN; break\n  if p==0: time.sleep(20); os._exit(0)\n  children.append(p)\n assert 0<len(children)<16\n assert open('/sys/fs/cgroup/pids.max').read().strip()=='16'\nfinally:\n for p in children: os.kill(p,signal.SIGTERM); os.waitpid(p,0)",
    memory: 'x=bytearray(256*1024*1024); print(len(x))'
  };
  for (const [control, script] of Object.entries(probes)) {
    const name = `breachbench-resource-${crypto.randomUUID()}`;
    try {
      execute('docker', ['create', '--name', name, '--network', 'none', '--user', '10001:10001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--read-only', '--cpus', '.25', '--pids-limit', '16', '--memory', '64m', '--memory-swap', '64m', 'breachbench/demo:baseline', 'python', '-c', script]);
      execute('docker', ['start', name]);
      execute('docker', ['wait', name]);
      const state = JSON.parse(execute('docker', ['inspect', '--format', '{{json .State}}', name]));
      const passed = control === 'memory' ? state.OOMKilled === true && state.ExitCode === 137 : state.ExitCode === 0;
      results.push({ control, passed, exitCode: state.ExitCode, oomKilled: state.OOMKilled });
    } catch (error) { results.push({ control, passed: false, message: error.message }); }
    finally { try { execute('docker', ['rm', '-f', name]); } catch {} }
  }
  const report = { status: results.every(r => r.passed) ? 'passed' : 'failed', cgroupVersion: 2, results };
  fs.writeFileSync(path.join(root, 'report.json'), JSON.stringify(report, null, 2));
  return report;
}
if (process.argv[1]?.endsWith('runtime-check.mjs')) {
  const report = verifyResourceEnforcement(); console.log(JSON.stringify(report, null, 2)); if (report.status !== 'passed') process.exitCode = 1;
}
