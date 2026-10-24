import fs from 'node:fs';
const config = JSON.parse(fs.readFileSync('hardening/demo/config.json', 'utf8'));
config.candidate = 'breachbench/demo:remediated';
config.runtimePackageInstallation = false;
config.remediations = { removeUnusedPip: true, healthcheckUrl: 'http://127.0.0.1:8080/' };
fs.mkdirSync('.breachbench', { recursive: true });
fs.writeFileSync('.breachbench/remediation-config.json', JSON.stringify(config, null, 2));
