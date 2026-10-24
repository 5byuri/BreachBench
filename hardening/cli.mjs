#!/usr/bin/env node
import { loadConfig, Workflow, tools } from './lib.mjs';
import { agent, checkGemini } from './gemini.mjs';
import fs from 'node:fs';

const [command, configFile, ...rest] = process.argv.slice(2);
try {
  if (!command || !configFile || ![...tools, 'run', 'verify', 'gemini', 'gemini-check'].includes(command)) {
    console.log('Usage: node hardening/cli.mjs <run|verify|gemini|gemini-check|' + tools.join('|') + '> config.json [output-directory]');
    process.exit(command ? 1 : 0);
  }
  const config = loadConfig(configFile);
  const workflow = new Workflow(config, { root: rest[0] ?? '.breachbench' });
  let result;
  if (command === 'gemini-check') result = await checkGemini();
  else if (command === 'gemini') result = await agent(workflow);
  else if (command === 'run' || command === 'verify') {
    for (const name of command === 'verify' ? tools.slice(4) : tools) {
      console.error(`Running ${name}`);
      result = await workflow.invoke(name);
    }
  } else result = await workflow.invoke(command);
  console.log(JSON.stringify(result, null, 2));
  if (result.status === 'rejected' || result.passed === false) process.exitCode = 1;
} catch (error) {
  if (error.diagnostic) {
    fs.mkdirSync('.breachbench', { recursive: true });
    fs.writeFileSync('.breachbench/tool-error.log', error.diagnostic, { mode: 0o600 });
    console.error('Tool stderr saved locally to .breachbench/tool-error.log; not sent to Gemini.');
  }
  console.error(JSON.stringify({ status: 'error', message: error.message }));
  process.exitCode = 1;
}
