#!/usr/bin/env node
/**
 * 打包发布资产：
 *   - dist-release/hdc-direct-<version>.tgz         npm 包布局（顶层 package/），供 node_modules URL 依赖
 *   - dist-release/hdc-direct-<version>.tgz.sha256  校验和
 *   - dist-release/hdc-direct-<version>.tar.gz      原有的解包即用整包
 *   - dist-release/hdc-direct-<version>.tar.gz.sha256
 *   - dist-release/hdc-direct-<version>.json        版本元信息
 *
 * 先执行 npm pack（会触发 prepare/build），保证两个产物来自同一份 dist/src。
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// 仓库根目录
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// package.json 内容（取版本号与包名）
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
// 发布输出目录
const outDir = path.join(root, 'dist-release');
// 产物目录名（整包解包后的顶层目录）
const stageName = `hdc-direct-${pkg.version}`;
// 整包暂存目录
const stage = path.join(outDir, stageName);
// npm pack 产物文件名（scoped 包会把 / 替换成 -）
const npmFileName = `${pkg.name.replace(/^@/, '').replace('/', '-')}-${pkg.version}.tgz`;
// npm 可执行文件名（Windows 下为 npm.cmd）
const NPM_BIN = process.platform === 'win32' ? 'npm.cmd' : 'npm';
// 协议验证结论：写入版本元信息，供下游判断兼容性
const PROTOCOL_NOTE = 'hdcd 3.2.0f verified (2026-11-02, HarmonyOS PC HAD-W32 / OpenHarmony 7.0.0.109)';
// 运行时要求说明
const RUNTIME_NOTE = 'node >= 18, zero dependencies';
// 整包包含的文件（运行时所需）
const STAGE_FILES = ['package.json', 'README.md', 'LICENSE'];
// 元信息写盘时的缩进
const META_INDENT = 2;

/**
 * 写入 sha256 校验和文件。
 *
 * @param file 需要计算校验和的文件路径
 * @returns 十六进制摘要
 */
function writeSha256(file) {
    const digest = createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    fs.writeFileSync(`${file}.sha256`, `${digest}  ${path.basename(file)}\n`);
    return digest;
}

// npm pack 的 --pack-destination 要求目录已存在
fs.mkdirSync(outDir, { recursive: true });

// 先产出 npm 标准包：prepare 会重新构建 dist，后续整包复用同一份产物
execFileSync(NPM_BIN, ['pack', '--pack-destination', outDir], { cwd: root, stdio: 'inherit' });
const npmTarball = path.join(outDir, npmFileName);
if (!fs.existsSync(npmTarball)) {
    throw new Error(`npm pack 未生成 ${npmFileName}`);
}

fs.rmSync(stage, { recursive: true, force: true });
fs.mkdirSync(stage, { recursive: true });

// 整包只含运行所需内容：dist/src（编译产物）+ 包元信息与文档
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
            npmTarball: npmFileName,
            runtime: RUNTIME_NOTE,
        },
        null,
        META_INDENT,
    )}\n`,
);

// 原有的解包即用整包
const tarball = path.join(outDir, `${stageName}.tar.gz`);
fs.rmSync(tarball, { force: true });
execFileSync('tar', ['-czf', tarball, '-C', outDir, stageName], { stdio: 'inherit' });

// 校验和：下游按此校验资产完整性
const tarDigest = writeSha256(tarball);
const npmDigest = writeSha256(npmTarball);

process.stdout.write(`==> ${path.relative(root, tarball)} (${tarDigest.slice(0, 16)}…)\n`);
process.stdout.write(`==> ${path.relative(root, npmTarball)} (${npmDigest.slice(0, 16)}…)\n`);
