#!/usr/bin/env node
/**
 * hdc-direct CLI —— 直连 hdcd 的 hdc 客户端（零依赖 Node / TypeScript 编译产物）。
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

import { HdcSession } from './session.js';
import { defaultTarget, loadTargets, saveTargets, splitTarget } from './targets.js';

export const VERSION_OUT = 'Ver: 3.2.0e-direct (hdc-direct tcp mode)';

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

interface ParsedArgs {
  target: string | null;
  rest: string[];
  versionOnly: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  let target: string | null = null;
  const rest: string[] = [];
  let versionOnly = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-t') {
      target = argv[++i] ?? null;
      if (!target) throw new Error('-t requires <host:port>');
    } else if (a === '-l') {
      i++; // 日志级别，忽略
    } else if ((a === '-v' || a === '--version') && i === 0 && argv.length === 1) {
      versionOnly = true;
    } else {
      rest.push(a);
    }
  }
  return { target, rest, versionOnly };
}

function resolveTarget(explicit: string | null): string {
  if (explicit) return explicit;
  const t = defaultTarget();
  if (!t) throw new Error('no target; run `hdc-direct tconn <host:port>` first');
  return t;
}

/** 每条命令一个短连接（与官方 hdc CLI 一致）。 */
async function withSession<T>(target: string, fn: (s: HdcSession) => Promise<T>): Promise<T> {
  const { host, port } = splitTarget(target);
  const session = await HdcSession.connect(host, port);
  try {
    return await fn(session);
  } finally {
    session.close();
  }
}

async function cmdTconn(args: string[]): Promise<number> {
  const target = args.find((a) => !a.startsWith('-'));
  if (!target) throw new Error('tconn requires <host:port>');
  const list = loadTargets();
  if (args.includes('-remove')) {
    saveTargets(list.filter((x) => x !== target));
    process.stdout.write(`Disconnected ${target}\n`);
    return 0;
  }
  try {
    await withSession(target, async () => undefined);
  } catch (e) {
    process.stdout.write(`[Fail] Connect ${target} failed: ${(e as Error).message}\n`);
    return 1;
  }
  if (!list.includes(target)) list.push(target);
  saveTargets(list);
  process.stdout.write('Connect OK\n');
  return 0;
}

function cmdList(args: string[]): number {
  if (args[0] !== 'targets') {
    process.stderr.write('[error] only `list targets` supported\n');
    return 1;
  }
  const verbose = args.includes('-v');
  const list = loadTargets();
  const fallback = defaultTarget();
  if (fallback && !list.includes(fallback)) list.push(fallback);
  for (const t of list) {
    process.stdout.write(verbose ? `${t}\tConnected\thdc-direct\n` : `${t}\n`);
  }
  return 0;
}

export async function run(argv: string[]): Promise<number> {
  const { target, rest, versionOnly } = parseArgs(argv);
  if (versionOnly) {
    process.stdout.write(`${VERSION_OUT}\n`);
    return 0;
  }
  const cmd = rest[0];
  const args = rest.slice(1);
  if (!cmd || cmd === 'help') {
    process.stderr.write(`${USAGE}\n`);
    return cmd ? 0 : 2;
  }

  switch (cmd) {
    // 无 server 概念，恒成功（对齐官方 CLI 行为）
    case 'kill':
    case 'start':
    case 'checkserver':
      return 0;

    case 'tconn':
      return cmdTconn(args);

    case 'list':
      return cmdList(args);

    case 'shell': {
      const out = await withSession(resolveTarget(target), (s) => s.shell(args.join(' ')));
      process.stdout.write(out);
      return 0;
    }

    case 'file': {
      if (args[0] !== 'send' || args.length < 3) {
        process.stderr.write(`${USAGE}\n`);
        return 2;
      }
      const summary = await withSession(resolveTarget(target), (s) => s.fileSend(args[1], args[2]));
      process.stdout.write(`${summary}\n`);
      return 0;
    }

    case 'install': {
      const hap = args[0];
      if (!hap) throw new Error('missing <local.hap>');
      const launch =
        args[1] === '--launch' && args[2]
          ? { bundle: args[2], ability: args[3] ?? 'EntryAbility' }
          : null;
      const remote = `/data/local/tmp/${path.basename(hap)}`;
      const t = resolveTarget(target);
      await withSession(t, (s) => s.fileSend(hap, remote));
      const installOut = await withSession(t, (s) => s.shellStr(`bm install -p ${remote} -r -d`));
      process.stdout.write(installOut);
      if (launch) {
        const startOut = await withSession(t, (s) => s.shellStr(`aa start -b ${launch.bundle} -a ${launch.ability}`));
        process.stdout.write(startOut);
      }
      await withSession(t, (s) => s.shellStr(`rm -f ${remote}`));
      return installOut.includes('successfully') ? 0 : 1;
    }

    case 'root': {
      const resp = await withSession(resolveTarget(target), (s) => s.requestRootRestart());
      process.stdout.write(`${resp}\n`);
      return 0;
    }

    // 未知子命令按 shell 命令整体转发（官方 hdc 对 shell 的宽松行为）
    default: {
      const out = await withSession(resolveTarget(target), (s) => s.shell(rest.join(' ')));
      process.stdout.write(out);
      return 0;
    }
  }
}

const isEntry = process.argv[1] && import.meta.url === new URL(`file://${path.resolve(process.argv[1])}`).href;
if (isEntry) {
  run(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((e: unknown) => {
      process.stderr.write(`[error] ${(e as Error).message}\n`);
      process.exit(1);
    });
}
