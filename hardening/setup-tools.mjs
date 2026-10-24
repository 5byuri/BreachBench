// Download official Linux x86_64 releases into the ignored project toolchain.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';

const root = path.resolve('.breachbench/tools/downloads');
fs.mkdirSync(root, { recursive: true });
async function response(url) {
  const result = await fetch(url, { headers: { 'User-Agent': 'BreachBench-setup' }, signal: AbortSignal.timeout(180000) });
  if (!result.ok) throw new Error(`${url}: HTTP ${result.status}`);
  return result;
}
async function json(url) { return (await response(url)).json(); }
async function download(url, filename, expected, releaseHasNoDigest = false) {
  if ((!expected || !/^[a-f0-9]{64}$/.test(expected)) && !releaseHasNoDigest) throw new Error(`No trusted SHA256 for ${filename}`);
  const target = path.join(root, filename);
  if (!fs.existsSync(target)) await pipeline(Readable.fromWeb((await response(url)).body), fs.createWriteStream(target));
  const hash = crypto.createHash('sha256');
  for await (const chunk of fs.createReadStream(target)) hash.update(chunk);
  const actual = hash.digest('hex');
  if (expected && actual !== expected) throw new Error(`SHA256 mismatch for ${filename}; remove the incomplete download and retry`);
  console.log(expected ? `Verified ${filename}` : `Downloaded ${filename} from official HTTPS release; upstream provides no digest. Recorded SHA256: ${actual}`);
  return { filename, url, sha256: actual, upstreamDigestVerified: Boolean(expected) };
}
const releases = await json('https://go.dev/dl/?mode=json');
const go = releases.find(r => r.version === 'go1.27.3');
if (!go) throw new Error('Expected Go 1.27.3 is not in official release metadata');
const goFile = go.files.find(f => f.os === 'linux' && f.arch === 'amd64' && f.kind === 'archive');
const trivy = await json('https://api.github.com/repos/aquasecurity/trivy/releases/tags/v0.76.1');
const slim = await json('https://api.github.com/repos/slimtoolkit/slim/releases/tags/1.40.11');
const trivyFile = trivy.assets.find(a => a.name === 'trivy_0.76.1_Linux-64bit.tar.gz');
const slimFile = slim.assets.find(a => a.name === 'dist_linux.tar.gz');
const sums = await (await response('https://nodejs.org/dist/v24.11.1/SHASUMS256.txt')).text();
const nodeFile = 'node-v24.11.1-linux-x64.tar.xz';
const nodeHash = sums.split('\n').find(line => line.endsWith(`  ${nodeFile}`))?.split(/\s+/)[0];
const artifacts = [];
artifacts.push(await download(`https://go.dev/dl/${goFile.filename}`, goFile.filename, goFile.sha256));
artifacts.push(await download(trivyFile.browser_download_url, trivyFile.name, trivyFile.digest?.replace(/^sha256:/, '')));
artifacts.push(await download(slimFile.browser_download_url, slimFile.name, slimFile.digest?.replace(/^sha256:/, ''), true));
artifacts.push(await download(`https://nodejs.org/dist/v24.11.1/${nodeFile}`, nodeFile, nodeHash));
fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify({ artifacts }, null, 2));
console.log('Downloads ready; see manifest.json for checksum provenance. Next: run hardening/setup-tools.sh in Ubuntu WSL.');
