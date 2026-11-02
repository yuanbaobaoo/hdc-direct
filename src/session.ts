/**
 * TCP 直连 hdcd 的会话：握手认证 + shell + file send。
 *
 * 生命周期与官方 hdc CLI 一致：一条命令一个短连接（认证 ~50ms）。
 * daemon 的 task 按 channel 生命周期设计，同 session 连续复用不可靠。
 */
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';

import { loadOrCreateKey, signToken } from './auth.js';
import {
  AUTH,
  BLOCK_SIZE,
  CMD,
  FrameReader,
  PAYLOAD_PREFIX_RESERVE,
  VERSION_STR,
  buildFrame,
  encodeHandshake,
  parseHandshake,
  pbString,
  pbVarint,
  tlvAppend,
  type Frame,
} from './proto.js';

/**
 * channelId 必须是无符号正数：负值经 varint 编码会被截断为低 7 位，
 * 响应 channelId 与本地记录不再匹配（实测会导致约一半命令“假超时”）。
 */
export function newChannelId(): number {
  return Math.floor(Math.random() * 0x7fffffff) + 1;
}

/** 帧队列：socket 数据推入，按谓词异步取帧，超时抛错。 */
class FrameQueue {
  private frames: Frame[] = [];
  private notify: (() => void) | null = null;

  push(f: Frame): void {
    this.frames.push(f);
    const n = this.notify;
    this.notify = null;
    n?.();
  }

  async next(pred: (f: Frame) => boolean, timeoutMs: number, what: string): Promise<Frame> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const idx = this.frames.findIndex(pred);
      if (idx >= 0) return this.frames.splice(idx, 1)[0];
      const remain = deadline - Date.now();
      if (remain <= 0) throw new Error(`timeout waiting for ${what}`);
      await new Promise<void>((resolve) => {
        const raiser = (): void => resolve();
        this.notify = raiser;
        setTimeout(() => {
          if (this.notify === raiser) {
            this.notify = null;
            resolve();
          }
        }, remain);
      });
    }
  }
}

export interface SessionOptions {
  /** 单条命令整体超时（ms），默认 60000 */
  timeoutMs?: number;
  /** 连接超时（ms），默认 10000 */
  connectTimeoutMs?: number;
}

export class HdcSession {
  private reader = new FrameReader();
  private queue = new FrameQueue();
  private sessionId = Math.floor(Math.random() * 0xffff) + 1;
  private closed = false;

  private constructor(
    private readonly sock: net.Socket,
    private readonly timeoutMs: number,
  ) {
    sock.on('data', (chunk: Buffer) => {
      try {
        this.reader.feed(chunk);
        for (let f = this.reader.nextFrame(); f; f = this.reader.nextFrame()) this.queue.push(f);
      } catch (e) {
        this.destroy();
        this.queue.push({ channelId: 0xffffffff, commandFlag: 0xffff, data: Buffer.from(String(e)) });
      }
    });
    sock.on('error', () => this.destroy());
    sock.on('close', () => {
      this.closed = true;
    });
  }

  /** 建连并完成 daemon 认证（hello → 公钥 → 挑战签名 → AUTH_OK）。 */
  static async connect(host: string, port: number, opts: SessionOptions = {}): Promise<HdcSession> {
    const timeoutMs = opts.timeoutMs ?? Number(process.env.HDC_SHELL_TIMEOUT || 60000);
    const sock = net.connect({ host, port });
    sock.setNoDelay(true);
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        sock.destroy();
        reject(new Error(`connect ${host}:${port} timeout`));
      }, opts.connectTimeoutMs ?? 10000);
      sock.once('connect', () => {
        clearTimeout(timer);
        resolve();
      });
      sock.once('error', (e) => {
        clearTimeout(timer);
        reject(new Error(`connect ${host}:${port}: ${e.message}`));
      });
    });

    const session = new HdcSession(sock, timeoutMs);
    try {
      await session.handshake(host, port);
    } catch (e) {
      session.destroy();
      throw e;
    }
    return session;
  }

  private async handshake(host: string, port: number): Promise<void> {
    const key = loadOrCreateKey();
    const connectKey = `${host}:${port}`;

    // 1) hello：version 必须非空；supportfeatures 不声明 heartbeat
    //    （声明后 daemon 开启心跳校验，host 需每 5s 发 CMD_HEARTBEAT_MSG）
    const helloBuf = Buffer.concat([
      tlvAppend('authtype', '1'),
      tlvAppend('supportfeatures', 'Ver: 3.2.0e,TCP,mac'),
    ]);
    this.send(
      buildFrame(
        0,
        CMD.KERNEL_HANDSHAKE,
        encodeHandshake({ authType: AUTH.NONE, sessionId: this.sessionId, connectKey, buf: helloBuf }),
      ),
    );
    let hs = parseHandshake((await this.wait(0, undefined, 'handshake hello')).data);
    if (hs.authType !== AUTH.PUBLICKEY) {
      throw new Error(`expect AUTH_PUBLICKEY, got ${hs.authType}`);
    }

    // 2) 提交 hostname \x0C 公钥
    const payload = Buffer.concat([Buffer.from(`${hostnameStr()}\x0C`, 'latin1'), Buffer.from(key.pubPem, 'latin1')]);
    this.send(
      buildFrame(0, CMD.KERNEL_HANDSHAKE, encodeHandshake({ authType: AUTH.PUBLICKEY, buf: payload })),
    );
    hs = parseHandshake((await this.wait(0, undefined, 'handshake pubkey')).data);
    if (hs.authType !== AUTH.SIGNATURE) {
      throw new Error(`expect AUTH_SIGNATURE, got ${hs.authType}`);
    }

    // 3) RSA-PSS(SHA-512) 签名回传
    const sig = signToken(key.privPem, hs.buf);
    this.send(
      buildFrame(0, CMD.KERNEL_HANDSHAKE, encodeHandshake({ authType: AUTH.SIGNATURE, buf: sig })),
    );
    hs = parseHandshake((await this.wait(0, undefined, 'handshake auth')).data);
    if (hs.authType !== AUTH.OK) {
      const msg = hs.buf.toString('utf8').slice(0, 200);
      throw new Error(`auth failed (type=${hs.authType}): ${msg}`);
    }

    // 4) daemon 发 cid=0 CHANNEL_CLOSE(data=01)，回 data=00（抓包行为）
    await this.wait(0, CMD.KERNEL_CHANNEL_CLOSE, 'handshake close');
    this.send(buildFrame(0, CMD.KERNEL_CHANNEL_CLOSE, Buffer.from([0])));
  }

  private send(buf: Buffer): void {
    if (this.closed) throw new Error('connection closed');
    this.sock.write(buf);
  }

  private wait(channelId: number, commandFlag: number | undefined, what: string): Promise<Frame> {
    return this.queue.next(
      (f) => f.channelId === channelId && (commandFlag === undefined || f.commandFlag === commandFlag),
      this.timeoutMs,
      what,
    );
  }

  /** 执行一条 shell 命令并收集输出（官方客户端把整条命令包在双引号内）。 */
  async shell(cmd: string): Promise<Buffer> {
    const channelId = newChannelId();
    this.send(buildFrame(channelId, CMD.UNITY_EXECUTE, Buffer.from(`"${cmd}"`, 'latin1')));
    const out: Buffer[] = [];
    for (;;) {
      const f = await this.wait(channelId, undefined, `shell "${cmd.slice(0, 40)}"`);
      if (f.commandFlag === CMD.KERNEL_ECHO_RAW || f.commandFlag === CMD.KERNEL_ECHO) {
        out.push(f.data);
      } else if (f.commandFlag === CMD.KERNEL_CHANNEL_CLOSE) {
        // 官方客户端对同一 channelId 连发两次 close(00)（抓包实证），
        // daemon 的 task 清理依赖第二次 close
        this.send(buildFrame(channelId, CMD.KERNEL_CHANNEL_CLOSE, Buffer.from([0])));
        this.send(buildFrame(channelId, CMD.KERNEL_CHANNEL_CLOSE, Buffer.from([0])));
        break;
      }
    }
    return Buffer.concat(out);
  }

  async shellStr(cmd: string): Promise<string> {
    return (await this.shell(cmd)).toString('utf8');
  }

  /**
   * 上传本地文件到设备路径，返回 daemon 的总结消息。
   *
   * 时序：WAKEUP_SLAVETASK 空帧 → FILE_CHECK(TransferConfig) → FILE_BEGIN →
   * 分块 FILE_DATA（TransferPayload 补零至固定 64B 前缀 + 数据）→
   * FILE_FINISH=01 → 回 00 → ECHO 总结 → close。
   */
  async fileSend(localPath: string, remotePath: string): Promise<string> {
    const data = fs.readFileSync(localPath);
    const st = fs.statSync(localPath);
    const channelId = newChannelId();

    // 1) 前导空帧
    this.send(buildFrame(channelId, CMD.KERNEL_WAKEUP_SLAVETASK));

    // 2) FILE_CHECK + TransferConfig
    const cfg = Buffer.from([
      ...pbVarint(1, data.length), // fileSize
      ...pbVarint(2, Math.floor(st.atimeMs / 1000)), // atime
      ...pbVarint(3, Math.floor(st.mtimeMs / 1000)), // mtime
      ...pbString(4, ''), // options
      ...pbString(5, remotePath), // path（远端）
      ...pbString(6, path.basename(localPath)), // optionalName
      ...pbVarint(7, 0), // updateIfNew
      ...pbVarint(8, 0), // compressType=NONE
      ...pbVarint(9, 0), // holdTimestamp
      ...pbString(10, ''), // functionName
      ...pbString(11, path.dirname(path.resolve(localPath))), // clientCwd
      ...pbString(12, ''),
      ...pbString(13, ''),
    ]);
    this.send(buildFrame(channelId, CMD.FILE_CHECK, cfg));
    await this.wait(channelId, CMD.FILE_BEGIN, 'file begin');

    // 3) 分块 FILE_DATA。index 是文件字节偏移而非块序号：
    //    daemon 侧 uv_fs_write(..., offset=index) 直接用它定位（transfer.cpp SimpleFileIO）。
    for (let offset = 0; offset < data.length; offset += BLOCK_SIZE) {
      const chunk = data.subarray(offset, Math.min(offset + BLOCK_SIZE, data.length));
      const pld = Buffer.from([
        ...pbVarint(1, offset),
        ...pbVarint(2, 0),
        ...pbVarint(3, chunk.length),
        ...pbVarint(4, chunk.length),
      ]);
      const prefix = Buffer.concat([pld, Buffer.alloc(PAYLOAD_PREFIX_RESERVE - pld.length)]);
      this.send(buildFrame(channelId, CMD.FILE_DATA, Buffer.concat([prefix, chunk])));
    }
    if (data.length === 0) {
      const pld = Buffer.from([...pbVarint(1, 0), ...pbVarint(2, 0), ...pbVarint(3, 0), ...pbVarint(4, 0)]);
      this.send(
        buildFrame(channelId, CMD.FILE_DATA, Buffer.concat([pld, Buffer.alloc(PAYLOAD_PREFIX_RESERVE - pld.length)])),
      );
    }

    // 4) 等 FINISH=01，回 00；收 ECHO 总结与 close
    const fin = await this.wait(channelId, CMD.FILE_FINISH, 'file finish');
    const ok = fin.data.length > 0 && fin.data[0] === 1;
    this.send(buildFrame(channelId, CMD.FILE_FINISH, Buffer.from([0])));
    let summary = '';
    try {
      summary = (await this.wait(channelId, CMD.KERNEL_ECHO, 'file summary')).data.toString('utf8').trim();
    } catch {
      /* 总结帧缺失不影响结果判定 */
    }
    try {
      await this.wait(channelId, CMD.KERNEL_CHANNEL_CLOSE, 'file close');
    } catch {
      /* 同上 */
    }
    this.send(buildFrame(channelId, CMD.KERNEL_CHANNEL_CLOSE, Buffer.from([0])));
    this.send(buildFrame(channelId, CMD.KERNEL_CHANNEL_CLOSE, Buffer.from([0])));
    if (!ok) throw new Error(`file transfer failed: ${summary || '(no summary)'}`);
    return summary;
  }

  /**
   * 请求 hdcd 以 root 重启（等价官方 `hdc root`），返回 daemon 即时响应。
   * 需设备 `const.debuggable=1`，否则返回 "Cannot set root run mode in
   * undebuggable version."。
   */
  async requestRootRestart(): Promise<string> {
    const channelId = newChannelId();
    this.send(buildFrame(channelId, CMD.UNITY_ROOTRUN));
    const out: Buffer[] = [];
    for (;;) {
      const f = await this.wait(channelId, undefined, 'root restart');
      if (f.commandFlag === CMD.KERNEL_ECHO || f.commandFlag === CMD.KERNEL_ECHO_RAW) {
        out.push(f.data);
      } else if (f.commandFlag === CMD.KERNEL_CHANNEL_CLOSE) {
        this.send(buildFrame(channelId, CMD.KERNEL_CHANNEL_CLOSE, Buffer.from([0])));
        this.send(buildFrame(channelId, CMD.KERNEL_CHANNEL_CLOSE, Buffer.from([0])));
        break;
      }
    }
    return Buffer.concat(out).toString('utf8').trim();
  }

  /** 优雅断开：FIN 关闭（RST 会让 daemon 的 session 清理卡在 busy 状态）。 */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.sock.end();
    } catch {
      /* ignore */
    }
    const s = this.sock;
    setTimeout(() => {
      try {
        s.destroy();
      } catch {
        /* ignore */
      }
    }, 3000).unref();
  }

  private destroy(): void {
    this.closed = true;
    try {
      this.sock.destroy();
    } catch {
      /* ignore */
    }
  }
}

function hostnameStr(): string {
  try {
    const h = fs.readFileSync('/etc/hostname', 'utf8').trim();
    if (h) return h;
  } catch {
    /* fall through */
  }
  return process.env.HOSTNAME || 'hdc-direct';
}
