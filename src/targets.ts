/**
 * target 状态管理：`~/.harmony/hdc-direct-targets.json` 记录已连接设备，
 * 无 `-t` 时取第一个；为空则探测本机无线调试端口。
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

import { keyDir } from './auth.js';

// 状态文件名（与历史实现保持同名，便于平滑替换）
const STATE_FILE_NAME = 'hdc-direct-targets.json';
// 设备侧无线调试端口的系统参数名
const HDC_PORT_PARAM = 'persist.hdc.port';
// 探测 param 命令的超时（ms）
const PARAM_TIMEOUT_MS = 3000;
// 写状态文件时的缩进空格数（便于人工排查）
const STATE_JSON_INDENT = 2;

/**
 * 状态文件绝对路径。
 *
 * @returns 路径
 */
export function stateFile(): string {
    return path.join(keyDir(), STATE_FILE_NAME);
}

/**
 * 读取已记录的 target 列表；文件缺失或损坏时返回空数组。
 *
 * @returns target 列表（host:port）
 */
export function loadTargets(): string[] {
    try {
        const raw = JSON.parse(fs.readFileSync(stateFile(), 'utf8'));
        return Array.isArray(raw) ? raw.filter((x): x is string => typeof x === 'string') : [];
    } catch {
        return [];
    }
}

/**
 * 写入 target 列表。
 *
 * @param list target 列表（host:port）
 */
export function saveTargets(list: string[]): void {
    const file = stateFile();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, `${JSON.stringify(list, null, STATE_JSON_INDENT)}\n`);
}

/**
 * 读取本机无线调试端口。
 *
 * 仅设备/沙箱内有效（`param` 命令可用）；开发机上返回 null。
 *
 * @returns 端口号或 null
 */
export function localHdcPort(): number | null {
    try {
        const out = execFileSync('param', ['get', HDC_PORT_PARAM], {
            encoding: 'utf8',
            timeout: PARAM_TIMEOUT_MS,
            stdio: ['ignore', 'pipe', 'ignore'],
        });
        const matched = out.match(/(\d+)/);
        return matched ? Number(matched[1]) : null;
    } catch {
        return null;
    }
}

/**
 * 解析默认 target：已记录的第一个，否则本机端口探测结果。
 *
 * @returns host:port 或 null
 */
export function defaultTarget(): string | null {
    const saved = loadTargets();
    if (saved.length > 0) return saved[0];
    const port = localHdcPort();
    return port ? `127.0.0.1:${port}` : null;
}

/**
 * 拆分 host:port。
 *
 * @param target 目标串
 * @returns 主机与端口
 */
export function splitTarget(target: string): { host: string; port: number } {
    const idx = target.lastIndexOf(':');
    if (idx <= 0) throw new Error(`target must be host:port, got '${target}'`);
    const port = Number(target.slice(idx + 1));
    if (!Number.isInteger(port) || port <= 0 || port > 65535) throw new Error(`invalid port in '${target}'`);
    return { host: target.slice(0, idx), port };
}
