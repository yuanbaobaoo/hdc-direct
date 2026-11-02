/**
 * target 状态管理：`~/.harmony/hdc-direct-targets.json` 记录已连接设备，
 * 无 `-t` 时取第一个；为空则探测本机无线调试端口。
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { keyDir } from './auth.js';

export function stateFile(): string {
  return path.join(keyDir(), 'hdc-direct-targets.json');
}

export function loadTargets(): string[] {
  try {
    const raw = JSON.parse(fs.readFileSync(stateFile(), 'utf8'));
    return Array.isArray(raw) ? raw.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

export function saveTargets(list: string[]): void {
  const file = stateFile();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(list, null, 2)}\n`);
}

/** `param get persist.hdc.port`（仅设备/沙箱内可用，开发机上返回 null）。 */
export function localHdcPort(): number | null {
  try {
    const out = execFileSync('param', ['get', 'persist.hdc.port'], {
      encoding: 'utf8',
      timeout: 3000,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const m = out.match(/(\d+)/);
    return m ? Number(m[1]) : null;
  } catch {
    return null;
  }
}

export function defaultTarget(): string | null {
  const saved = loadTargets();
  if (saved.length > 0) return saved[0];
  const port = localHdcPort();
  return port ? `127.0.0.1:${port}` : null;
}

export function splitTarget(target: string): { host: string; port: number } {
  const idx = target.lastIndexOf(':');
  if (idx <= 0) throw new Error(`target must be host:port, got '${target}'`);
  const port = Number(target.slice(idx + 1));
  if (!Number.isInteger(port) || port <= 0 || port > 65535) throw new Error(`invalid port in '${target}'`);
  return { host: target.slice(0, idx), port };
}

export function harmonyHome(): string {
  return process.env.HOME || os.homedir();
}
