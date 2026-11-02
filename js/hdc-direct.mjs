#!/usr/bin/env node
/**
 * hdc-direct — 纯 TCP 直连 hdcd 的最小 hdc 客户端（Node，零依赖）。
 *
 * 背景：OpenHarmony/harmonyOS PC 上官方 hdc 采用 client→UDS server→TCP daemon 架构，
 * 在 HAP 沙箱（develop_tools_debug_hap SELinux 域）里 UDS bind 被禁止，server 起不来。
 * 本工具跳过 hdc server，直接实现 host↔daemon 的 TCP 协议（developtools_hdc 开源，
 * 真机 hdcd 3.2.0e），使沙箱内也能完成 shell / file send / bm install。
 *
 * 协议参考：抓包（2026-11-02 与真机 HAD-W32 hdcd 3.2.0e 实测）+ developtools_hdc 源码。
 * 帧: "HW" + reserve(2B=0) + protocolVer(1B=1) + headSize(BE16) + dataSize(BE32)
 *     + PayloadProtect protobuf(channelId=1, commandFlag=2, checkSum=3, vCode=4=9) + data
 * 认证: hello → daemon 索要公钥(AUTH_PUBLICKEY) → host 发 hostname\x0C<hdckey.pub>
 *       → daemon 发 token(AUTH_SIGNATURE) → host 回 RSA-SHA256 签名 base64 → AUTH_OK
 */

import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

// ---------- 常量（对齐 define_enum.h / session.h） ----------
const PROTOCOL_VER = 0x01;
const VCODE = 0x09;
const CMD_KERNEL_HANDSHAKE = 1;
const CMD_KERNEL_CHANNEL_CLOSE = 2;
const CMD_KERNEL_ECHO = 9;
const CMD_KERNEL_ECHO_RAW = 10;
const CMD_KERNEL_WAKEUP = 12; // file 任务前导空帧（抓包 flag=0x0c）
const CMD_UNITY_EXECUTE = 1001;
const CMD_FILE_CHECK = 3001;
const CMD_FILE_BEGIN = 3002;
const CMD_FILE_DATA = 3003;
const CMD_FILE_FINISH = 3004;

const AUTH_NONE = 0, AUTH_TOKEN = 1, AUTH_SIGNATURE = 2, AUTH_PUBLICKEY = 3, AUTH_OK = 4, AUTH_FAIL = 5;

const BANNER = 'OHOS HDC';
const VERSION_STR = 'Ver: 3.2.0e7fdbc1aa8c5fefaa'; // 与真机 hdcd 协商一致（抓包原样）
const BLOCK_SIZE = 60 * 1024 - 64; // 稳妥块大小（daemon 上限 511KB）

// ---------- protobuf / varint 编码 ----------
function varint(n) {
  const out = [];
  let v = BigInt(n);
  do {
    let b = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) b |= 0x80;
    out.push(b);
  } while (v > 0n);
  return out;
}
function pbVarint(field, value) { return [...varint((field << 3) | 0), ...varint(value)]; }
function pbString(field, s) {
  const bytes = Buffer.from(s, 'latin1');
  return [...varint((field << 3) | 2), ...varint(bytes.length), ...bytes];
}
// SessionHandShake: banner=1 authType=2 sessionId=3 connectKey=4 buf=5 version=6
function encodeHandshake({ banner = BANNER, authType = 0, sessionId = 0, connectKey = '', buf = '', version = VERSION_STR }) {
  return Buffer.from([
    ...pbString(1, banner),
    ...pbVarint(2, authType),
    ...pbVarint(3, sessionId),
    ...pbString(4, connectKey),
    ...pbString(5, buf),
    ...pbString(6, version),
  ]);
}
// PayloadProtect: channelId=1 commandFlag=2 checkSum=3 vCode=4
function encodeProtect(channelId, commandFlag) {
  return Buffer.from([...pbVarint(1, channelId), ...pbVarint(2, commandFlag), ...pbVarint(3, 0), ...pbVarint(4, VCODE)]);
}

function buildFrame(channelId, commandFlag, data = Buffer.alloc(0)) {
  const protect = encodeProtect(channelId, commandFlag);
  const head = Buffer.alloc(11);
  head.write('HW', 0, 'latin1');
  head.writeUInt8(PROTOCOL_VER, 4);
  head.writeUInt16BE(protect.length, 5);
  head.writeUInt32BE(data.length, 7);
  return Buffer.concat([head, protect, data]);
}

// ---------- protobuf 轻量解码（够用即可） ----------
function pbDecode(buf) {
  const fields = [];
  let i = 0;
  while (i < buf.length) {
    let tag = 0n, shift = 0n;
    for (;;) {
      const b = buf[i++]; tag |= BigInt(b & 0x7f) << shift; shift += 7n;
      if (!(b & 0x80)) break;
    }
    const field = Number(tag >> 3n), wire = Number(tag & 7n);
    if (wire === 0) {
      let v = 0n, s = 0n;
      for (;;) {
        const b = buf[i++]; v |= BigInt(b & 0x7f) << s; s += 7n;
        if (!(b & 0x80)) break;
      }
      fields.push({ field, value: v });
    } else if (wire === 2) {
      let len = 0n, s = 0n;
      for (;;) {
        const b = buf[i++]; len |= BigInt(b & 0x7f) << s; s += 7n;
        if (!(b & 0x80)) break;
      }
      fields.push({ field, bytes: buf.subarray(i, i + Number(len)) });
      i += Number(len);
    } else {
      throw new Error(`unsupported wire type ${wire}`);
    }
  }
  return fields;
}

// ---------- TLV（tag 16B 定长 + len 16B 定长 + value，base.cpp TlvAppend） ----------
function tlvAppend(tag, val) {
  const t = tag.padEnd(16, ' ').slice(0, 16);
  const l = String(val.length).padEnd(16, ' ').slice(0, 16);
  return Buffer.from(t + l + val, 'latin1');
}

// ---------- 分帧流解析 ----------
class FrameReader {
  constructor() { this.buf = Buffer.alloc(0); this.frames = []; }
  push(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    for (;;) {
      if (this.buf.length < 11) break;
      if (this.buf.subarray(0, 2).toString('latin1') !== 'HW') throw new Error('frame magic mismatch');
      const headSize = this.buf.readUInt16BE(5);
      const dataSize = this.buf.readUInt32BE(7);
      const total = 11 + headSize + dataSize;
      if (this.buf.length < total) break;
      const protectBytes = this.buf.subarray(11, 11 + headSize);
      const data = this.buf.subarray(11 + headSize, total);
      const pf = {};
      for (const f of pbDecode(protectBytes)) pf[f.field] = f.value ?? 0n;
      this.frames.push({ channelId: Number(pf[1] ?? 0), commandFlag: Number(pf[2] ?? 0), data });
      this.buf = this.buf.subarray(total);
    }
  }
  wait(timeoutMs = 15000) {
    const deadline = Date.now() + timeoutMs;
    return new Promise((resolve, reject) => {
      const tick = () => {
        const idx = this.frames.findIndex((f) => !f.__consumed);
        if (idx >= 0) { this.frames[idx].__consumed = true; return resolve(this.frames[idx]); }
        if (Date.now() > deadline) return reject(new Error('frame wait timeout'));
        setTimeout(tick, 10);
      };
      tick();
    });
  }
  async waitWhere(pred, timeoutMs = 15000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const idx = this.frames.findIndex((f) => !f.__consumed && pred(f));
      if (idx >= 0) { this.frames[idx].__consumed = true; return this.frames[idx]; }
      if (Date.now() > deadline) throw new Error('frame waitWhere timeout');
      await new Promise((r) => setTimeout(r, 10));
    }
  }
}

// ---------- 密钥 ----------
function keyPaths() {
  const home = process.env.HOME || os.homedir();
  const dir = path.join(home, '.harmony');
  return { dir, priv: path.join(dir, 'hdckey'), pub: path.join(dir, 'hdckey.pub') };
}
function loadOrCreateKey() {
  const { dir, priv, pub } = keyPaths();
  if (fs.existsSync(priv) && fs.existsSync(pub)) {
    return { privPem: fs.readFileSync(priv, 'utf8'), pubPem: fs.readFileSync(pub, 'utf8') };
  }
  fs.mkdirSync(dir, { recursive: true });
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  // hdckey.pub 为 PEM 文本且公钥串 625B（PKCS1 DER base64 长度），设备端仅作白名单比对
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  fs.writeFileSync(priv, privPem, { mode: 0o600 });
  fs.writeFileSync(pub, pubPem, { mode: 0o600 });
  return { privPem, pubPem };
}

// ---------- 会话 ----------
class HdcSession {
  constructor(host, port) {
    this.host = host; this.port = port;
    this.sessionId = (Math.random() * 0xffff) | 1;
    this.daemonVersion = VERSION_STR; // 与官方 host 行为一致：版本不一致时 daemon 仅记日志（真机实测）
    this.reader = new FrameReader();
    this.sock = null;
  }
  async connect() {
    const { privPem, pubPem } = loadOrCreateKey();
    await new Promise((resolve, reject) => {
      this.sock = net.connect({ host: this.host, port: this.port }, resolve);
      this.sock.on('error', reject);
      this.sock.on('data', (c) => { try { this.reader.push(c); } catch (e) { this.sock.destroy(); } });
    });

    // 1) hello（version 必须非空，空值触发 daemon "version too low" 拒绝；
    //    版本不一致仅记日志。supportfeatures 不声明 heartbeat——声明后
    //    daemon 开启心跳校验，host 需每 5s 发 CMD_HEARTBEAT_MSG，不发会被判不健康）
    const helloBuf = Buffer.concat([
      tlvAppend('authtype', '1'),
      tlvAppend('supportfeatures', 'Ver: 3.2.0e,TCP,mac'),
    ]);
    this.send(0, CMD_KERNEL_HANDSHAKE, encodeHandshake({
      authType: AUTH_NONE, sessionId: this.sessionId,
      connectKey: `${this.host}:${this.port}`, buf: helloBuf.toString('latin1'),
    }));
    let f = await this.reader.wait();
    let hs = this.parseHandshake(f);
    if (hs.authType !== AUTH_PUBLICKEY) throw new Error(`expect AUTH_PUBLICKEY, got ${hs.authType}`);

    // 2) 提交公钥 hostname\x0C<pub>
    this.send(0, CMD_KERNEL_HANDSHAKE, encodeHandshake({
      authType: AUTH_PUBLICKEY, sessionId: 0, connectKey: '', version: this.daemonVersion,
      buf: `${os.hostname()}\x0C${pubPem}`,
    }));
    f = await this.reader.wait();
    hs = this.parseHandshake(f);
    if (hs.authType !== AUTH_SIGNATURE) throw new Error(`expect AUTH_SIGNATURE, got ${hs.authType}`);

    // 3) 签名 token（RSA-PSS salt=digest + SHA-512，base64；见 auth.cpp RsaSign）
    const token = Buffer.from(hs.buf, 'latin1');
    const sig = crypto.sign('sha512', token, {
      key: crypto.createPrivateKey(privPem),
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALT_LENGTH_DIGEST,
    }).toString('base64');
    this.send(0, CMD_KERNEL_HANDSHAKE, encodeHandshake({
      authType: AUTH_SIGNATURE, sessionId: 0, connectKey: '', buf: sig, version: this.daemonVersion,
    }));
    f = await this.reader.wait();
    hs = this.parseHandshake(f);
    if (hs.authType !== AUTH_OK) throw new Error(`auth failed: type=${hs.authType} buf=${hs.buf.slice(0, 200)}`);

    // 4) daemon 发 channelId=0 CHANNEL_CLOSE data=01，回 data=00（抓包行为）
    f = await this.reader.waitWhere((x) => x.commandFlag === CMD_KERNEL_CHANNEL_CLOSE);
    this.send(0, CMD_KERNEL_CHANNEL_CLOSE, Buffer.from([0]));
    return hs;
  }
  parseHandshake(f) {
    const out = { authType: 0, buf: '', version: '' };
    for (const fld of pbDecode(f.data)) {
      if (fld.field === 2) out.authType = Number(fld.value);
      if (fld.field === 5) out.buf = fld.bytes.toString('latin1');
      if (fld.field === 6) out.version = fld.bytes.toString('latin1');
    }
    return out;
  }
  send(channelId, commandFlag, data) {
    this.sock.write(buildFrame(channelId, commandFlag, data));
  }
  // 必须是无符号正数：负数会被 varint 编码截断为低 7 位，导致响应 channelId
  // 与本地记录不匹配（曾引发 ~50% 命令"超时"的偶发假象）
  newChannelId() { return Math.floor(Math.random() * 0x7ffffffe) + 1; }

  async shell(cmd, onChunk, timeoutMs = Number(process.env.HDC_SHELL_TIMEOUT || 60000)) {
    const channelId = this.newChannelId();
    const chunks = [];
    // 官方客户端把整条命令包在双引号内（抓包行为），daemon 交给 sh 解释
    this.send(channelId, CMD_UNITY_EXECUTE, Buffer.from(`"${cmd}"`, 'latin1'));
    for (;;) {
      const f = await this.reader.waitWhere((x) => x.channelId === channelId, timeoutMs);
      if (f.commandFlag === CMD_KERNEL_ECHO_RAW || f.commandFlag === CMD_KERNEL_ECHO) {
        chunks.push(f.data); onChunk && onChunk(f.data);
      } else if (f.commandFlag === CMD_KERNEL_CHANNEL_CLOSE) {
        // 官方客户端对同一 channelId 连发两次 CHANNEL_CLOSE(00)（抓包实证），
        // daemon 侧 task 清理依赖第二次 close，缺发会导致同 session 后续 channel 无响应
        this.send(channelId, CMD_KERNEL_CHANNEL_CLOSE, Buffer.from([0]));
        this.send(channelId, CMD_KERNEL_CHANNEL_CLOSE, Buffer.from([0]));
        // daemon 侧 TaskClassDeleteRetry 异步清理与紧贴的新命令存在竞争（抓 hilog 实证：
        // close 后 <5ms 发新命令会 12s 空窗），官方客户端命令间隔 ~1s。等待清理完成。
        await new Promise((r) => setTimeout(r, Number(process.env.HDC_TASK_GAP_MS || 150)));
        break;
      }
    }
    return Buffer.concat(chunks);
  }

  async fileSend(localPath, remotePath) {
    const st = fs.statSync(localPath);
    const channelId = this.newChannelId();
    // 1) 前导空帧（flag=12）
    this.send(channelId, CMD_KERNEL_WAKEUP, Buffer.alloc(0));
    // 2) FILE_CHECK + TransferConfig
    const cfg = Buffer.from([
      ...pbVarint(1, st.size),                     // fileSize
      ...pbVarint(2, Math.floor(st.atimeMs / 1000)),
      ...pbVarint(3, Math.floor(st.mtimeMs / 1000)),
      ...pbString(4, ''),                          // options
      ...pbString(5, remotePath),                  // path(远端)
      ...pbString(6, path.basename(localPath)),    // optionalName
      ...pbVarint(7, 0),                           // updateIfNew
      ...pbVarint(8, 0),                           // compressType=NONE
      ...pbVarint(9, 0),                           // holdTimestamp
      ...pbString(10, ''),                         // functionName
      ...pbString(11, path.dirname(path.resolve(localPath))), // clientCwd
      ...pbString(12, ''), ...pbString(13, ''),    // reserve
    ], 'latin1');
    this.send(channelId, CMD_FILE_CHECK, cfg);
    const begin = await this.reader.waitWhere((x) => x.channelId === channelId && x.commandFlag === CMD_FILE_BEGIN);
    // 3) 分块 FILE_DATA：TransferPayload protobuf 补零至固定 64B 前缀 + 数据
    const fd = fs.openSync(localPath, 'r');
    try {
      let offset = 0, sent = 0;
      const chunk = Buffer.alloc(BLOCK_SIZE);
      for (;;) {
        const n = fs.readSync(fd, chunk, 0, BLOCK_SIZE, null);
        if (n <= 0) break;
        // TransferPayload.index 是文件字节偏移而非块序号：daemon 侧
        // uv_fs_write(..., offset=index) 直接用它定位（transfer.cpp SimpleFileIO）
        const pld = Buffer.from([...pbVarint(1, offset), ...pbVarint(2, 0), ...pbVarint(3, n), ...pbVarint(4, n)]);
        const prefix = Buffer.concat([pld, Buffer.alloc(64 - pld.length)]);
        this.send(channelId, CMD_FILE_DATA, Buffer.concat([prefix, chunk.subarray(0, n)]));
        offset += n; sent += n;
      }
      // 4) 等 FINISH(3004)=01，回 00
      const fin = await this.reader.waitWhere((x) => x.channelId === channelId && x.commandFlag === CMD_FILE_FINISH, 120000);
      this.send(channelId, CMD_FILE_FINISH, Buffer.from([0]));
      const ok = fin.data.length > 0 && fin.data[0] === 1;
      // 5) ECHO 总结 + 收尾
      const summary = await this.reader.waitWhere((x) => x.channelId === channelId && x.commandFlag === CMD_KERNEL_ECHO, 10000);
      const close = await this.reader.waitWhere((x) => x.channelId === channelId && x.commandFlag === CMD_KERNEL_CHANNEL_CLOSE, 10000);
      this.send(channelId, CMD_KERNEL_CHANNEL_CLOSE, Buffer.from([0]));
      this.send(channelId, CMD_KERNEL_CHANNEL_CLOSE, Buffer.from([0]));
      return { ok, sent, summary: summary.data.toString('utf8').trim(), extra: begin.data.toString('hex') };
    } finally {
      fs.closeSync(fd);
    }
  }
  close() {
    // FIN 优雅断开：RST 会让 daemon 的 session 清理卡在 busy 状态
    // （hilog: FreeSession loop is busy → 僵尸 session 堵塞后续 task），必须 end()
    if (!this.sock) return;
    try { this.sock.end(); } catch {}
    const s = this.sock;
    setTimeout(() => { try { s.destroy(); } catch {} }, 3000).unref();
  }
}

// ---------- CLI ----------
function usage() {
  console.log(`usage:
  hdc-direct <host:port> shell "<command>"
  hdc-direct <host:port> file send <local> <remote>
  hdc-direct <host:port> install <local.hap> [--launch <bundle> <ability>]
env:
  HDC_KEY_DIR  密钥目录（默认 ~/.harmony，内含 hdckey/hdckey.pub）`);
}

async function main() {
  const args = process.argv.slice(2);
  const target = args[0];
  if (!target || !target.includes(':')) { usage(); process.exit(2); }
  const [host, portStr] = target.split(':');

  // 与官方 hdc CLI 一致：每条命令一个短连接 session（认证 ~60ms）。
  // daemon 的 task 按 channel 生命周期设计，同 session 连续复用不可靠。
  const run = async (fn) => {
    const t0 = Date.now();
    const session = new HdcSession(host, parseInt(portStr, 10));
    try {
      const hs = await session.connect();
      process.stderr.write(`[auth] ${hs.version} ${hs.buf.includes('SUCCESS') ? 'OK' : ''} (${Date.now() - t0}ms)\n`);
      return await fn(session);
    } finally {
      session.close();
    }
  };

  try {
    const cmd = args[1];
    if (cmd === 'shell') {
      const out = await run((s) => s.shell(args.slice(2).join(' ')));
      process.stdout.write(out);
    } else if (cmd === 'file' && args[2] === 'send') {
      const r = await run((s) => s.fileSend(args[3], args[4]));
      process.stdout.write(r.summary + '\n');
      process.exitCode = r.ok ? 0 : 1;
    } else if (cmd === 'install') {
      const hap = args[2];
      const launch = args[3] === '--launch' ? { bundle: args[4], ability: args[5] || 'EntryAbility' } : null;
      const remote = `/data/local/tmp/${path.basename(hap)}`;
      const r = await run((s) => s.fileSend(hap, remote));
      if (!r.ok) throw new Error('file send failed: ' + r.summary);
      const out = await run((s) => s.shell(`bm install -p ${remote} -r -d`));
      process.stdout.write(out.toString('utf8'));
      if (launch) {
        const out2 = await run((s) => s.shell(`aa start -b ${launch.bundle} -a ${launch.ability}`));
        process.stdout.write(out2.toString('utf8'));
      }
      await run((s) => s.shell(`rm -f ${remote}`));
    } else {
      usage(); process.exitCode = 2;
    }
  } catch (e) {
    console.error('[error]', e.message);
    process.exitCode = 1;
  }
}
export { HdcSession, FrameReader, buildFrame, encodeHandshake };

const isEntry = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isEntry) main();
