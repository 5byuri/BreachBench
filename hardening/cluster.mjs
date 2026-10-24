import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { run, networkPolicy, normalizeTrivy } from './lib.mjs';

export function clusterManifests(namespace, image) {
  const securityContext = { runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, fsGroup: 10001, seccompProfile: { type: 'RuntimeDefault' } };
  const containerSecurity = { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ['ALL'] } };
  const scriptVolume = { name: 'checks', configMap: { name: 'checks' } };
  const secretVolume = { name: 'database-secret', secret: { secretName: 'database-client', defaultMode: 0o440 } };
  const resources = { limits: { cpu: '500m', memory: '128Mi' }, requests: { cpu: '25m', memory: '32Mi' } };
  const pod = (name, role, command, needsSecret = false, env = []) => ({ apiVersion: 'v1', kind: 'Pod', metadata: { name, namespace, labels: { role, ...(role === 'app' ? { app: 'breachbench-candidate' } : {}) } }, spec: {
    serviceAccountName: 'workload', automountServiceAccountToken: false, securityContext, containers: [{ name: 'app', image, imagePullPolicy: 'Never', command, env, securityContext: containerSecurity, resources,
      ...(!['control', 'outsider'].includes(role) ? { readinessProbe: { tcpSocket: { port: role === 'database' ? 5432 : 8080 }, initialDelaySeconds: 1, periodSeconds: 1 } } : {}),
      volumeMounts: [{ name: 'checks', mountPath: '/checks', readOnly: true }, { name: 'tmp', mountPath: '/tmp' }, ...(needsSecret ? [{ name: 'database-secret', mountPath: '/run/secrets/database', readOnly: true }] : [])] }],
    volumes: [scriptVolume, { name: 'tmp', emptyDir: { medium: 'Memory', sizeLimit: '32Mi' } }, ...(needsSecret ? [secretVolume] : [])]
  } });
  const service = (name, role, port) => ({ apiVersion: 'v1', kind: 'Service', metadata: { name, namespace }, spec: { selector: { role }, ports: [{ port, targetPort: port }] } });
  const sleeper = ['python', '-c', 'import time; time.sleep(3600)'];
  return [
    { apiVersion: 'v1', kind: 'Namespace', metadata: { name: namespace, labels: { 'pod-security.kubernetes.io/enforce': 'restricted' } } },
    { apiVersion: 'v1', kind: 'ServiceAccount', metadata: { name: 'workload', namespace }, automountServiceAccountToken: false },
    { apiVersion: 'v1', kind: 'ConfigMap', metadata: { name: 'checks', namespace }, data: { 'dependency.py': fs.readFileSync('hardening/fixtures/dependency.py', 'utf8'), 'probe.py': fs.readFileSync('hardening/fixtures/network-probe.py', 'utf8') } },
    pod('app', 'app', ['python', '/app/app.py'], true),
    pod('control', 'control', sleeper), pod('outsider', 'outsider', sleeper),
    pod('api', 'api', ['python', '/checks/dependency.py']),
    pod('blocked', 'blocked', ['python', '/checks/dependency.py']),
    pod('database', 'database', ['python', '/checks/dependency.py'], true, [{ name: 'PEER', value: 'database' }]),
    service('app', 'app', 8080), service('api', 'api', 8080), service('blocked', 'blocked', 8080), service('database', 'database', 5432)
  ];
}

export function fixturePolicies(namespace) {
  const peer = role => ({ podSelector: { matchLabels: { role } } });
  const policy = (name, selector, spec) => ({ apiVersion: 'networking.k8s.io/v1', kind: 'NetworkPolicy', metadata: { name, namespace }, spec: { podSelector: { matchLabels: selector }, ...spec } });
  return [
    policy('namespace-default-deny', {}, { policyTypes: ['Ingress', 'Egress'], ingress: [], egress: [] }),
    networkPolicy({ namespace, egress: [
      { to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'kube-system' } }, podSelector: { matchLabels: { 'k8s-app': 'kube-dns' } } }], ports: [{ protocol: 'UDP', port: 53 }, { protocol: 'TCP', port: 53 }] },
      { to: [peer('api')], ports: [{ protocol: 'TCP', port: 8080 }] },
      { to: [peer('database')], ports: [{ protocol: 'TCP', port: 5432 }] }
    ], ingress: [{ from: [peer('control')], ports: [{ protocol: 'TCP', port: 8080 }] }] }),
    ...['api', 'database', 'blocked'].map(role => policy(`${role}-ingress`, { role }, { policyTypes: ['Ingress'], ingress: [{ from: [peer('app'), peer('control')], ports: [{ port: role === 'database' ? 5432 : 8080, protocol: 'TCP' }] }] })),
    ...['control', 'outsider'].map(role => policy(`${role}-probe-egress`, { role }, { policyTypes: ['Egress'], egress: [{}] }))
  ];
}

export async function verifyCluster({ output = '.breachbench/cluster', keep = false, execute = run } = {}) {
  const root = path.resolve(output); fs.mkdirSync(root, { recursive: true });
  const name = `breachbench-${crypto.randomBytes(4).toString('hex')}`;
  const namespace = 'breachbench-policy-test';
  const kubeconfig = path.join(root, 'kubeconfig');
  const tools = path.join(process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local/share'), 'breachbench/tools/cluster');
  const k = (...args) => execute(path.join(tools, 'kubectl'), ['--kubeconfig', kubeconfig, '--context', `kind-${name}`, ...args]);
  const apply = (filename, items) => { const file = path.join(root, filename); fs.writeFileSync(file, JSON.stringify({ apiVersion: 'v1', kind: 'List', items }, null, 2)); k('apply', '-f', file); };
  let created = false;
  const report = { status: 'failed', cluster: name, namespace, cni: 'Calico v3.31.0', results: [], deployedToExistingCluster: false, remainingRisks: ['Controlled HTTP/database peers validate policy and credential mechanics, not production dependency behavior', 'IPv4 conformance only; IPv6 requires a dual-stack target test', 'RuntimeDefault seccomp here is separate from the workload-reviewed Docker seccomp test'] };
  const test = (name, operation) => { try { operation(); report.results.push({ name, passed: true }); } catch (error) { report.results.push({ name, passed: false, message: error.message }); throw error; } };
  const probe = (pod, mode, host, port) => k('exec', '-n', namespace, pod, '--', 'python', '/checks/probe.py', mode, host, String(port));
  try {
    const configFile = path.join(root, 'kind.json');
    fs.writeFileSync(configFile, JSON.stringify({ kind: 'Cluster', apiVersion: 'kind.x-k8s.io/v1alpha4', networking: { disableDefaultCNI: true, podSubnet: '192.168.0.0/16', apiServerAddress: '127.0.0.1' }, nodes: [{ role: 'control-plane' }] }));
    console.error('Creating isolated kind cluster with Calico policy enforcement');
    // Mark owned before creation so partial failures also clean up this exact name.
    created = true;
    execute(path.join(tools, 'kind'), ['create', 'cluster', '--name', name, '--image', 'kindest/node:v1.34.0', '--config', configFile, '--kubeconfig', kubeconfig]);
    k('create', '-f', path.join(tools, 'calico-v3.31.0.yaml'));
    k('wait', '--for=condition=Ready', 'nodes', '--all', '--timeout=240s');
    k('rollout', 'status', 'daemonset/calico-node', '-n', 'kube-system', '--timeout=240s');
    k('rollout', 'status', 'deployment/coredns', '-n', 'kube-system', '--timeout=180s');
    const image = 'breachbench/demo:baseline';
    execute(path.join(tools, 'kind'), ['load', 'docker-image', image, '--name', name]);
    const manifests = clusterManifests(namespace, image);
    apply('namespace.json', manifests.slice(0, 3));
    const secret = crypto.randomBytes(32).toString('hex');
    const secretFile = path.join(root, 'ephemeral-database-token');
    const imageArchive = path.join(os.tmpdir(), `${name}-image.tar`);
    try {
      fs.writeFileSync(secretFile, secret, { mode: 0o600 });
      test('runtime credential absent from all saved image layers and metadata', () => {
        execute('docker', ['save', '-o', imageArchive, image]);
        execute('python3', ['hardening/fixtures/check-image-secret.py', imageArchive, secretFile]);
      });
      k('create', 'secret', 'generic', 'database-client', '-n', namespace, `--from-file=token=${secretFile}`);
    } finally { fs.rmSync(secretFile, { force: true }); fs.rmSync(imageArchive, { force: true }); }
    apply('workloads.json', manifests.slice(3));
    console.error('Scanning generated deployment configuration with Trivy');
    const scanDirectory = path.join(root, 'deployment-scan-input'); fs.mkdirSync(scanDirectory, { recursive: true });
    for (const item of [...manifests.filter(item => item.kind === 'Pod'), ...fixturePolicies(namespace)]) fs.writeFileSync(path.join(scanDirectory, `${item.kind}-${item.metadata.name}.json`), JSON.stringify(item, null, 2));
    const scan = JSON.parse(execute('docker', ['run', '--rm', '--mount', `type=bind,source=${scanDirectory},target=/deployment,readonly`, 'aquasec/trivy:0.76.1', 'config', '--include-non-failures', '--format', 'json', '/deployment']));
    report.deploymentScanResources = (scan.Results ?? []).filter(result => result.Type === 'kubernetes').length;
    if (report.deploymentScanResources < manifests.filter(item => item.kind === 'Pod').length) throw new Error('Trivy did not scan every workload Pod');
    report.deploymentConfigurationFindings = normalizeTrivy(scan);
    if (report.deploymentConfigurationFindings.some(f => ['HIGH', 'CRITICAL'].includes(f.severity))) throw new Error('Generated deployment contains HIGH/CRITICAL configuration findings');
    k('wait', '--for=condition=Ready', 'pod', '--all', '-n', namespace, '--timeout=180s');
    const ip = name => JSON.parse(k('get', 'service', name, '-n', namespace, '-o', 'json')).spec.clusterIP;
    const ips = Object.fromEntries(['app', 'api', 'database', 'blocked'].map(name => [name, ip(name)]));
    const kubernetes = JSON.parse(k('get', 'service', 'kubernetes', '-n', 'default', '-o', 'json')).spec.clusterIP;
    test('baseline blocked peer reachable before policy', () => probe('app', 'http', ips.blocked, 8080));
    test('baseline application ingress reachable', () => probe('outsider', 'http', ips.app, 8080));
    test('baseline Kubernetes API reachable by TCP', () => probe('app', 'connected', kubernetes, 443));
    apply('network-policies.json', fixturePolicies(namespace));
    await new Promise(resolve => setTimeout(resolve, 3000));
    test('required DNS allowed over UDP and TCP', () => probe('app', 'dns', `api.${namespace}.svc.cluster.local`, 53));
    test('required API allowed', () => probe('app', 'http', `api.${namespace}.svc.cluster.local`, 8080));
    test('database allowed with scoped credential; wrong credential rejected', () => probe('app', 'database', `database.${namespace}.svc.cluster.local`, 5432));
    test('blocked peer is still alive from control pod', () => probe('control', 'http', ips.blocked, 8080));
    test('unapproved outbound peer denied', () => probe('app', 'denied', ips.blocked, 8080));
    test('Kubernetes API still reachable from control', () => probe('control', 'connected', kubernetes, 443));
    test('unnecessary Kubernetes API egress denied', () => probe('app', 'denied', kubernetes, 443));
    test('explicit ingress allowance succeeds', () => probe('control', 'http', ips.app, 8080));
    test('unapproved ingress denied', () => probe('outsider', 'denied', ips.app, 8080));
    test('secret volume readonly and service-account token absent', () => probe('app', 'secrets', 'unused', 0));
    test('unrelated API pod receives neither secret nor service-account token', () => k('exec', '-n', namespace, 'api', '--', 'python', '-c', "import os; assert not os.path.exists('/run/secrets/database/token'); assert not os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount/token')"));
    test('workload service account cannot list secrets', () => {
      const reviewFile = path.join(root, 'access-review.json');
      fs.writeFileSync(reviewFile, JSON.stringify({ apiVersion: 'authorization.k8s.io/v1', kind: 'SubjectAccessReview', spec: { user: `system:serviceaccount:${namespace}:workload`, groups: ['system:serviceaccounts', `system:serviceaccounts:${namespace}`, 'system:authenticated'], resourceAttributes: { namespace, verb: 'list', resource: 'secrets' } } }));
      const result = k('create', '-f', reviewFile, '-o', 'json');
      if (JSON.parse(result).status?.allowed !== false) throw new Error('Unexpected secret-list permission');
    });
    report.status = 'passed';
  } catch (error) {
    report.error = error.message;
    if (error.diagnostic) fs.writeFileSync(path.join(root, 'tool-error.log'), error.diagnostic, { mode: 0o600 });
  }
  finally {
    if (created && !keep) {
      try { execute(path.join(tools, 'kind'), ['delete', 'cluster', '--name', name]); report.cleanedUp = true; }
      catch (error) { report.cleanedUp = false; report.cleanupError = error.message; report.status = 'failed'; }
    }
    if (!keep) fs.rmSync(kubeconfig, { force: true });
    fs.writeFileSync(path.join(root, 'report.json'), JSON.stringify(report, null, 2));
  }
  return report;
}

if (process.argv[1]?.endsWith('cluster.mjs')) {
  const report = await verifyCluster(); console.log(JSON.stringify(report, null, 2));
  if (report.status !== 'passed') process.exitCode = 1;
}
