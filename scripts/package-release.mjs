#!/usr/bin/env node
/**
 * 打包发布资产：dist/ + package.json + README/LICENSE → dist-release/<name>.tar.gz
 *
 * 资产命名约定（zcode-ohos 按此拉取 GitHub Release）：
 *   hdc-direct-<version>.tar.gz        运行时依赖为零，解包即可用
 *   hdc-direct-<version>.tar.gz.sha256 校验和
 *   hdc-direct-<version>.json          版本元信息（协议版本、支持的 hdcd）
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const outDir = path.join(root, 'dist-release');
const stageName = `hdc-direct-${pkg.version}`;
const stage = path.join(outDir, stageName);

fs.rmSync(stage, { recursive: true, force: true });
fs.mkdirSync(stage, { recursive: true });

// 发布物只含运行所需内容：dist/src（编译产物）、package.json、README、LICENSE
fs.cpSync(path.join(root, 'dist', 'src'), path.join(stage, 'dist', 'src'), { recursive: true });
for (const f of ['package.json', 'README.md', 'LICENSE']) {
  fs.copyFileSync(path.join(root, f), path.join(stage, f));
}

// 版本元信息：供下游（zcode-ohos）判断协议兼容性
fs.writeFileSync(
  path.join(outDir, `${stageName}.json`),
  `${JSON.stringify(
    {
      name: pkg.name,
      version: pkg.version,
      protocol: 'hdcd 3.2.0f verified (2026-11-02, HarmonyOS PC HAD-W32 / OpenHarmony 7.0.0.109)',
      entry: 'dist/src/cli.js',
      runtime: 'node >= 18, zero dependencies',
    },
    null,
    2,
  )}\n`,
);

const tarball = path.join(outDir, `${stageName}.tar.gz`);
fs.rmSync(tarball, { force: true });
execFileSync('tar', ['-czf', tarball, '-C', outDir, stageName], { stdio: 'inherit' });

const digest = createHash('sha256').update(fs.readFileSync(tarball)).digest('hex');
fs.writeFileSync(`${tarball}.sha256`, `${digest}  ${path.basename(tarball)}\n`);

process.stdout.write(`==> ${path.relative(root, tarball)} (${digest.slice(0, 16)}…)\n`);
