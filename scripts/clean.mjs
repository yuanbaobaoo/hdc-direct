#!/usr/bin/env node
/**
 * 清理构建产物：删除 dist/，避免 tsc 覆盖式输出残留已删除模块的旧文件。
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// 仓库根目录（scripts/ 的上一级）
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// 构建输出目录
const dist = path.join(root, 'dist');

fs.rmSync(dist, { recursive: true, force: true });
