#!/usr/bin/env node
/**
 * hdc 兼容 wrapper —— 供 devecocli 等工具当普通 hdc 调用。
 * 实现为 hdc-direct（TCP 直连 hdcd，无需 UDS hdc server）。
 *
 * 用法与官方 hdc 子集兼容：
 *   hdc list targets [-v]
 *   hdc tconn <host:port> [-remove]
 *   hdc [-t <key>] shell "<command>"
 *   hdc [-t <key>] file send <local> <remote>
 *   hdc -v / --version / kill / start / checkserver   （no-op 兼容）
 *
 * target 记忆在 ~/.harmony/hdc-direct-targets.json；
 * 无 target 时自动尝试本机无线调试端口（param get persist.hdc.port，本机可直接执行）。
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { HdcSession } from './hdc-direct.mjs';

const STATE_FILE = path.join(os.homedir(), '.harmony', 'hdc-direct-targets.json');
const VERSION_OUT = 'Ver: 3.2.0e-direct (hdc-direct tcp mode)';

function loadTargets() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch { return []; }
}
function saveTargets(list) {
  fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
  fs.writeFileSync(STATE_FILE, JSON.stringify(list, null, 2));
}
function localHdcPort() {
  try {
    const out = execFileSync('param', ['get', 'persist.hdc.port'], { encoding: 'utf8', timeout: 3000 }).trim();
    const m = out.match(/(\d+)/);
    return m ? Number(m[1]) : null;
  } catch { return null; }
}
function defaultTarget() {
  const saved = loadTargets();
  if (saved.length > 0) return saved[0];
  const port = localHdcPort(); // 沙箱/本机可直接读系统参数
  return port ? `127.0.0.1:${port}` : null;
}
function splitKey(key) {
  const [host, port] = key.split(':');
  return [host, Number(port)];
}

async function tryConnect(key) {
  const [host, port] = splitKey(key);
  const s = new HdcSession(host, port);
  try { await s.connect(); return s; } catch (e) { s.close(); throw e; }
}

async function cmdShell(key, command) {
  const s = await tryConnect(key);
  try {
    const out = await s.shell(command, null, Number(process.env.HDC_SHELL_TIMEOUT || 60000));
    process.stdout.write(out);
    return 0;
  } catch (e) {
    process.stderr.write(`[error] ${e.message}\n`);
    return 1;
  } finally { s.close(); }
}

async function main() {
  const argv = process.argv.slice(2);
  // 全局兼容选项
  let key = null;
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '-t' && argv[i + 1]) { key = argv[i + 1]; i++; }
    else if ((argv[i] === '-v' || argv[i] === '--version') && i === 0) { console.log(VERSION_OUT); return 0; }
    else if (argv[i] === '-l' && argv[i + 1]) { i++; } // 日志级别，忽略
    else rest.push(argv[i]);
  }
  const [cmd, ...args] = rest;

  switch (cmd) {
    case undefined:
    case 'help':
      console.log(VERSION_OUT, '— see hdc-direct README');
      return 0;
    case 'kill':
    case 'start':
    case 'checkserver':
      return 0; // 无 server 概念，恒成功
    case 'tconn': {
      const target = args.find((a) => !a.startsWith('-'));
      const remove = args.includes('-remove');
      const list = loadTargets();
      if (remove) { saveTargets(list.filter((x) => x !== target)); console.log(`Disconnected ${target}`); return 0; }
      try {
        const s = await tryConnect(target);
        s.close();
        if (!list.includes(target)) list.push(target);
        saveTargets(list);
        console.log('Connect OK');
        return 0;
      } catch (e) {
        console.log(`[Fail] Connect ${target} failed: ${e.message}`);
        return 1;
      }
    }
    case 'list':
      if (args[0] === 'targets') {
        const list = loadTargets();
        const target = defaultTarget();
        if (list.length === 0 && target && !list.includes(target)) list.push(target);
        if (args.includes('-v')) list.forEach((k) => console.log(`${k}\tConnected\thdc-direct`));
        else list.forEach((k) => console.log(k));
        return 0;
      }
      process.stderr.write('[error] only `list targets` supported\n');
      return 1;
    case 'shell': {
      const target = key || defaultTarget();
      if (!target) { process.stderr.write('[error] no target; run hdc tconn <host:port> first\n'); return 1; }
      return cmdShell(target, args.join(' '));
    }
    case 'file': {
      if (args[0] !== 'send') { process.stderr.write('[error] only `file send` supported\n'); return 1; }
      const target = key || defaultTarget();
      if (!target) { process.stderr.write('[error] no target\n'); return 1; }
      const [, local, remote] = args;
      const s = await tryConnect(target);
      try {
        const r = await s.fileSend(local, remote);
        console.log(r.summary);
        return r.ok ? 0 : 1;
      } catch (e) {
        process.stderr.write(`[error] ${e.message}\n`);
        return 1;
      } finally { s.close(); }
    }
    default: {
      // 未知子命令按 shell 命令转发（官方 hdc 对 shell 的宽松行为）
      const target = key || defaultTarget();
      if (!target) { process.stderr.write(`[error] unknown command '${cmd}' and no target\n`); return 1; }
      return cmdShell(target, rest.join(' '));
    }
  }
}

main().then((code) => process.exit(code ?? 0)).catch((e) => { console.error('[error]', e.message); process.exit(1); });
