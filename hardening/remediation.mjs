// Constrained, reviewable recipes; every change records the findings that prompted it.
export function planRemediation(config, sourceRef, findings) {
  const lines = [`FROM ${sourceRef}`];
  const changes = [];
  if (config.remediations?.removeUnusedPip) {
    if (config.runtimePackageInstallation !== false) throw new Error('Removing pip requires an explicit declaration that the workload never installs packages at runtime');
    const affected = findings.filter(f => f.kind === 'vulnerability' && f.component === 'pip');
    if (affected.length) {
      lines.push('USER 0:0', 'RUN python -m pip uninstall --yes pip');
      changes.push({ recipe: 'remove-unused-pip', findingIds: affected.map(f => f.id), reason: 'Operator declares no runtime package installation; remove the unused installer and re-test foreground/background/uncommon workloads. Historical base layers remain retained for rollback.' });
    }
  }
  if (config.remediations?.removeUnusedPip && config.remediations?.upgradePip) throw new Error('Select removal or upgrade, not both');
  if (config.remediations?.upgradePip) {
    const affected = findings.filter(f => f.kind === 'vulnerability' && f.component === 'pip');
    const versions = affected.map(f => f.fixedVersion ?? f.fix?.match(/^Upgrade to (\d+\.\d+(?:\.\d+)?)$/)?.[1]).filter(v => /^\d+\.\d+(?:\.\d+)?$/.test(v ?? ''));
    versions.sort((a, b) => { const x = a.split('.').map(Number), y = b.split('.').map(Number); for (let i = 0; i < 3; i++) { const difference = (y[i] ?? 0) - (x[i] ?? 0); if (difference) return difference; } return 0; });
    if (versions.length) {
      lines.push('USER 0:0', `RUN python -m pip install --no-cache-dir --disable-pip-version-check --upgrade pip==${versions[0]}`);
      changes.push({ recipe: 'upgrade-pip', targetVersion: versions[0], findingIds: affected.map(f => f.id), reason: 'Use the highest explicit fixed version reported for the installed pip component; functionality is re-tested afterward' });
    }
  }
  lines.push(`USER ${config.user}`);
  if (config.remediations?.healthcheckUrl) {
    const url = config.remediations.healthcheckUrl;
    if (!/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}\/[a-zA-Z0-9/_-]*$/.test(url)) throw new Error('Healthcheck URL must be a literal loopback HTTP endpoint');
    lines.push(`HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 CMD ${JSON.stringify(['python', '-c', `import urllib.request; urllib.request.urlopen(${JSON.stringify(url)}, timeout=2).read()`])}`);
    changes.push({ recipe: 'application-healthcheck', findingIds: findings.filter(f => f.id === 'DS-0026').map(f => f.id), url, reason: 'Check the actual application endpoint rather than process existence' });
  }
  return { dockerfile: lines.join('\n') + '\n', changes, automaticScope: 'Only explicitly enabled recipes are applied. Arbitrary package/runtime upgrades require an agent-authored reviewed context and application tests.' };
}
