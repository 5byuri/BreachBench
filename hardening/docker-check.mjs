// Standalone Docker readiness check; does not imply a completed hardening report.
import { loadConfig, Workflow } from './lib.mjs';
import { spawnSync } from 'node:child_process';

try {
  const config = loadConfig('hardening/demo/config.json');
  const execute = (exe, args, options = {}) => {
    const result = spawnSync(exe, args, { encoding: 'utf8', timeout: 60000, ...options,
      env: Object.fromEntries(Object.entries(process.env).filter(([key]) => !/GEMINI|GOOGLE_API_KEY/.test(key))) });
    if (result.error || result.status !== 0) {
      // This script uses only the fixed public demo inputs, never arbitrary workload output.
      console.error(result.stderr || result.error?.message || 'Demo command failed');
      throw new Error('Demo command failed');
    }
    return result.stdout;
  };
  const workflow = new Workflow(config, { root: '.breachbench/docker-check', execute });
  const functionality = await workflow.suite(config.image, true, config.tests);
  const enforcement = await workflow.suite(config.image, true, config.enforcementTests);
  console.log(JSON.stringify({ functionality, enforcement }, null, 2));
  if ([...functionality, ...enforcement].some(test => !test.passed)) process.exitCode = 1;
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
