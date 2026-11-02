#!/usr/bin/env node
/**
 * hdc-direct CLI —— 直连 hdcd 的 hdc 客户端（TypeScript 编译产物，零运行时依赖）。
 *
 * 命令面与官方 hdc 对齐，可直接替换 PATH 中的 `hdc` 供 devecocli 等工具调用：
 *   hdc-direct [-t <host:port>] shell "<command>"
 *   hdc-direct [-t <host:port>] file send <local> <remote>
 *   hdc-direct [-t <host:port>] install <local.hap> [--launch <bundle> <ability>]
 *   hdc-direct [-t <host:port>] root
 *   hdc-direct tconn <host:port> [-remove]
 *   hdc-direct list targets [-v]
 *   hdc-direct -v | kill | start | checkserver
 *   hdc-direct [-t <host:port>] <other command>    # 未知命令按 shell 转发
 */
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { HdcSession } from './session.js';
import { defaultTarget, loadTargets, saveTargets, splitTarget } from './targets.js';

// 版本串：与 README「版本矩阵」保持一致，下游据此判断协议兼容性
export const VERSION_OUT = 'Ver: 3.2.0e-direct (hdc-direct tcp mode)';

// CLI 帮助文本（--help / 参数缺失时输出）
const USAGE = `hdc-direct — talk to on-device hdcd directly over TCP

USAGE:
  hdc-direct [-t <host:port>] shell "<command>"
  hdc-direct [-t <host:port>] file send <local> <remote>
  hdc-direct [-t <host:port>] install <local.hap> [--launch <bundle> <ability>]
  hdc-direct [-t <host:port>] root
  hdc-direct tconn <host:port> [-remove]
  hdc-direct list targets [-v]
  hdc-direct -v | kill | start | checkserver
  hdc-direct [-t <host:port>] <other command>   (forwarded as shell)

AUTH:
  keypair at ~/.harmony/hdckey(.pub) (or $HDC_KEY_DIR); auto-generated on first
  run. A new public key triggers a one-time "allow debugging" dialog on the
  device. Keys must be passphrase-free PKCS8 PEM.

ENV:
  HDC_KEY_DIR         key directory (default ~/.harmony)
  HDC_SHELL_TIMEOUT   per-command timeout ms (default 60000)`;

/**
 * 全局选项名：避免同一字面量散落在解析与分发两处。
 */
const OPT = {
    // 指定目标设备
    target: '-t',
    // 日志级别（本实现无对应概念，仅消费其取值）
    logLevel: '-l',
    // 版本查询（短）
    version: '-v',
    // 版本查询（长）
    versionLong: '--version',
    // tconn 移除目标
    remove: '-remove',
    // list targets 详细输出（与版本旗标同为 -v，按位置区分）
    verbose: '-v',
    // install 后拉起应用
    launch: '--launch',
} as const;

/**
 * 子命令名（与官方 hdc 对齐）。
 */
const SUBCOMMAND = {
    // 执行设备 shell
    shell: 'shell',
    // 文件传输
    file: 'file',
    // file 的子动作：上传
    send: 'send',
    // 上传并安装 HAP
    install: 'install',
    // 请求 hdcd 以 root 重启
    root: 'root',
    // 连接并记录目标设备
    tconn: 'tconn',
    // 列出目标设备
    list: 'list',
    // list 的子动作
    targets: 'targets',
    // 帮助
    help: 'help',
} as const;

// 无 server 概念的子命令：直接成功（对齐官方 CLI 行为）
const NOOP_COMMANDS = ['kill', 'start', 'checkserver'];

// 默认启动 ability（install --launch 未指定时使用）
const DEFAULT_ABILITY = 'EntryAbility';

// 设备侧上传中转目录：hdcd 的 file 任务需要设备本地可写路径
const DEVICE_TMP_DIR = '/data/local/tmp';

// 退出码：命令成功
const EXIT_OK = 0;
// 退出码：运行期错误
const EXIT_ERROR = 1;
// 退出码：用法错误
const EXIT_USAGE = 2;

// 连接失败输出前缀（与官方 hdc 的失败文案保持一致）
const FAIL_PREFIX = '[Fail]';

// 错误输出前缀
const ERROR_PREFIX = '[error]';

/**
 * 解析结果：全局 target、剩余参数、是否仅为版本查询。
 */
interface ParsedArgs {
    // 显式 -t 指定的目标设备
    target: string | null;
    // 去掉全局选项后的子命令与参数
    rest: string[];
    // 仅 `-v`/`--version` 单参数时为 true
    versionOnly: boolean;
}

/**
 * 解析全局选项（-t / -l / -v），返回子命令参数。
 *
 * @param argv 不含 node 与脚本路径的原始参数
 * @returns 解析结果
 */
function parseArgs(argv: string[]): ParsedArgs {
    // 显式 target（-t 的值）
    let target: string | null = null;
    // 子命令与其它参数
    const rest: string[] = [];
    // 版本查询标记
    let versionOnly = false;
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === OPT.target) {
            target = argv[++i] ?? null;
            if (!target) throw new Error('-t requires <host:port>');
        } else if (arg === OPT.logLevel) {
            i++; // 日志级别在本实现中无对应概念，跳过取值
        } else if ((arg === OPT.version || arg === OPT.versionLong) && i === 0 && argv.length === 1) {
            versionOnly = true;
        } else {
            rest.push(arg);
        }
    }
    return { target, rest, versionOnly };
}

/**
 * 解析最终目标设备：显式 -t 优先，其次状态文件，最后本机端口探测。
 *
 * @param explicit 显式传入的 target
 * @returns host:port
 */
function resolveTarget(explicit: string | null): string {
    if (explicit) return explicit;
    const fallback = defaultTarget();
    if (!fallback) throw new Error('no target; run `hdc-direct tconn <host:port>` first');
    return fallback;
}

/**
 * 在一条短连接内执行操作，结束后释放连接。
 *
 * 与官方 hdc CLI 一致：一条命令一个连接（daemon 的 task 按 channel 生命周期设计，
 * 同 session 连续复用不可靠）。
 *
 * @param target host:port
 * @param fn 使用会话的操作
 * @returns 操作结果
 */
async function withSession<T>(target: string, fn: (s: HdcSession) => Promise<T>): Promise<T> {
    const { host, port } = splitTarget(target);
    const session = await HdcSession.connect(host, port);
    try {
        return await fn(session);
    } finally {
        session.close();
    }
}

/**
 * `tconn`：探测连接并把 target 记录到状态文件；`-remove` 时移除。
 *
 * @param args 子命令参数
 * @returns 退出码
 */
async function cmdTconn(args: string[]): Promise<number> {
    const target = args.find((a) => !a.startsWith('-'));
    if (!target) throw new Error('tconn requires <host:port>');
    const known = loadTargets();
    if (args.includes(OPT.remove)) {
        saveTargets(known.filter((x) => x !== target));
        process.stdout.write(`Disconnected ${target}\n`);
        return EXIT_OK;
    }
    try {
        await withSession(target, async () => undefined);
    } catch (e) {
        process.stdout.write(`${FAIL_PREFIX} Connect ${target} failed: ${(e as Error).message}\n`);
        return EXIT_ERROR;
    }
    if (!known.includes(target)) known.push(target);
    saveTargets(known);
    process.stdout.write('Connect OK\n');
    return EXIT_OK;
}

/**
 * `list targets`：输出已记录与自动探测到的 target。
 *
 * @param args 子命令参数
 * @returns 退出码
 */
function cmdList(args: string[]): number {
    if (args[0] !== SUBCOMMAND.targets) {
        process.stderr.write(`${ERROR_PREFIX} only \`list targets\` supported\n`);
        return EXIT_ERROR;
    }
    const verbose = args.includes(OPT.verbose);
    const list = loadTargets();
    const fallback = defaultTarget();
    if (fallback && !list.includes(fallback)) list.push(fallback);
    for (const target of list) {
        process.stdout.write(verbose ? `${target}\tConnected\thdc-direct\n` : `${target}\n`);
    }
    return EXIT_OK;
}

/**
 * `install`：上传 HAP 并调用设备 bm 安装，可选拉起应用。
 *
 * @param target host:port
 * @param args 子命令参数
 * @returns 退出码（安装输出含 successfully 视为成功）
 */
async function cmdInstall(target: string, args: string[]): Promise<number> {
    const hap = args[0];
    if (!hap) throw new Error('missing <local.hap>');
    // --launch 指定的启动目标；未给出时不启动
    const launch = args[1] === OPT.launch && args[2] ? { bundle: args[2], ability: args[3] ?? DEFAULT_ABILITY } : null;
    const remote = `${DEVICE_TMP_DIR}/${path.basename(hap)}`;
    await withSession(target, (s) => s.fileSend(hap, remote));
    const installOut = await withSession(target, (s) => s.shellStr(`bm install -p ${remote} -r -d`));
    process.stdout.write(installOut);
    if (launch) {
        const startOut = await withSession(target, (s) =>
            s.shellStr(`aa start -b ${launch.bundle} -a ${launch.ability}`),
        );
        process.stdout.write(startOut);
    }
    await withSession(target, (s) => s.shellStr(`rm -f ${remote}`));
    return installOut.includes('successfully') ? EXIT_OK : EXIT_ERROR;
}

/**
 * CLI 主流程：解析参数并按子命令分发。
 *
 * @param argv 不含 node 与脚本路径的参数
 * @returns 进程退出码
 */
export async function run(argv: string[]): Promise<number> {
    const { target, rest, versionOnly } = parseArgs(argv);
    if (versionOnly) {
        process.stdout.write(`${VERSION_OUT}\n`);
        return EXIT_OK;
    }
    const cmd = rest[0];
    const args = rest.slice(1);
    if (!cmd || cmd === SUBCOMMAND.help) {
        process.stderr.write(`${USAGE}\n`);
        return cmd ? EXIT_OK : EXIT_USAGE;
    }

    if (NOOP_COMMANDS.includes(cmd)) return EXIT_OK;

    switch (cmd) {
        case SUBCOMMAND.tconn:
            return cmdTconn(args);

        case SUBCOMMAND.list:
            return cmdList(args);

        case SUBCOMMAND.shell: {
            const out = await withSession(resolveTarget(target), (s) => s.shell(args.join(' ')));
            process.stdout.write(out);
            return EXIT_OK;
        }

        case SUBCOMMAND.file: {
            if (args[0] !== SUBCOMMAND.send || args.length < 3) {
                process.stderr.write(`${USAGE}\n`);
                return EXIT_USAGE;
            }
            const summary = await withSession(resolveTarget(target), (s) => s.fileSend(args[1], args[2]));
            process.stdout.write(`${summary}\n`);
            return EXIT_OK;
        }

        case SUBCOMMAND.install:
            return cmdInstall(resolveTarget(target), args);

        case SUBCOMMAND.root: {
            const resp = await withSession(resolveTarget(target), (s) => s.requestRootRestart());
            process.stdout.write(`${resp}\n`);
            return EXIT_OK;
        }

        // 未知子命令按 shell 命令整体转发（官方 hdc 对 shell 的宽松行为）
        default: {
            const out = await withSession(resolveTarget(target), (s) => s.shell(rest.join(' ')));
            process.stdout.write(out);
            return EXIT_OK;
        }
    }
}

/**
 * 进程入口：执行 CLI 并把异常映射为退出码。
 *
 * @returns 进程退出码
 */
async function runEntry(): Promise<number> {
    try {
        return await run(process.argv.slice(2));
    } catch (e) {
        process.stderr.write(`${ERROR_PREFIX} ${(e as Error).message}\n`);
        return EXIT_ERROR;
    }
}

// 作为 CLI 直接执行时启动；被 import 时仅导出函数
const isEntry =
    process.argv[1] !== undefined && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isEntry) {
    process.exit(await runEntry());
}
