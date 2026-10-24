// Produce a separate config while preserving the normal demo configuration.
import fs from 'node:fs';
const config = JSON.parse(fs.readFileSync('hardening/demo/config.json', 'utf8'));
config.candidate = 'breachbench/demo:slim-candidate';
config.slim = {
  execFile: 'hardening/demo/slim-workload.sh',
  includePaths: ['/app', '/usr/local/lib/python3.12', '/usr/local/bin/python', '/etc/ssl/certs', '/var/lib/dpkg', '/etc/os-release', '/usr/lib/os-release', '/etc/debian_version'],
  removeEnv: ['GPG_KEY', 'PYTHON_SHA256']
};
fs.mkdirSync('.breachbench', { recursive: true });
fs.writeFileSync('.breachbench/slim-config.json', JSON.stringify(config, null, 2));
