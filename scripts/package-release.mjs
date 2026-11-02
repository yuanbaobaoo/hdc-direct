#!/usr/bin/env node
/**
 * 打包发布资产：dist/ + package.json + README/LICENSE → dist-release/<name>.tar.gz
 *
 * 资产命名约定（zcode-ohos 按此拉取 GitHub Release）：
 *   hdc-direct-<version>.tar.gz        运行时依赖为零，解包即可用
 *   hdc-direct-<version>.tar.gz.sha256 校验和
 *   hdc-direct-<version>.json          版本元信息（协议版本、支持的 hdcd）
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

// 仓库根目录
const root = path.resolve(import.meta.dirname, '..');
// package.json 内容（取版本号与包名）
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
// 发布输出目录
const outDir = path.join(root, 'dist-release');
// 产物目录名（解包后的顶层目录）
const stageName = `hdc-direct-${pkg.version}`;
// 产物暂存目录
const stage = path.join(outDir, stageName);
// 协议验证结论：写入版本元信息，供下游判断兼容性
const PROTOCOL_NOTE = 'hdcd 3.2.0f verified (2026-11-02, HarmonyOS PC HAD-W32 / OpenHarmony 7.0.0.109)';
// 运行时要求说明
const RUNTIME_NOTE = 'node >= 18, zero dependencies';
// 发布物包含的文件（运行时所需）
const STAGE_FILES = ['package.json', 'README.md', 'LICENSE'];
// 元信息写盘时的缩进
const META_INDENT = 2;

fs.rmSync(stage, { recursive: true, force: true });
fs.mkdirSync(stage, { recursive: true });

// 发布物只含运行所需内容：dist/src（编译产物）+ 包元信息与文档
fs.cpSync(path.join(root, 'dist', 'src'), path.join(stage, 'dist', 'src'), { recursive: true });
for (const file of STAGE_FILES) {
    fs.copyFileSync(path.join(root, file), path.join(stage, file));
}

// 版本元信息：供下游（zcode-ohos）判断协议兼容性
fs.writeFileSync(
    path.join(outDir, `${stageName}.json`),
    `${JSON.stringify(
        {
            name: pkg.name,
            version: pkg.version,
            protocol: PROTOCOL_NOTE,
            entry: 'dist/src/cli.js',
            runtime: RUNTIME_NOTE,
        },
        null,
        META_INDENT,
    )}\n`,
);

// 打包
const tarball = path.join(outDir, `${stageName}.tar.gz`);
fs.rmSync(tarball, { force: true });
execFileSync('tar', ['-czf', tarball, '-C', outDir, stageName], { stdio: 'inherit' });

// 校验和：下游按此校验资产完整性
const digest = createHash('sha256').update(fs.readFileSync(tarball)).digest('hex');
fs.writeFileSync(`${tarball}.sha256`, `${digest}  ${path.basename(tarball)}\n`);

process.stdout.write(`==> ${path.relative(root, tarball)} (${digest.slice(0, 16)}…)\n`);
