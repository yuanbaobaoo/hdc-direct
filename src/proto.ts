/**
 * hdc 有线协议：帧头、PayloadProtect / SessionHandShake 的 protobuf 子集编码、TLV。
 *
 * 帧布局（developtools_hdc `src/common/session.h` PayloadHead，packed，大端）：
 * ```
 * "HW" | reserve(2B)=0 | protocolVer(1B)=1 | headSize(BE16) | dataSize(BE32)
 *      | PayloadProtect protobuf | data
 * ```
 * `headSize` 是 protect 序列化长度；`dataSize` 只计 data（不含 protect）。
 *
 * 协议事实全部来自 developtools_hdc 开源代码 + 真机 hdcd 3.2.0f 抓包对照，
 * `test/proto.golden.test.ts` 用抓包字节锁死编码结果。
 */

export const PROTOCOL_VER = 0x01;
export const VCODE = 0x09;
export const BANNER = 'OHOS HDC';

/**
 * 与官方 host 3.2.0e 一致。daemon 校验版本非空（空值触发 "version too low"
 * 拒绝）；与 daemon 版本不一致仅记录日志（真机 hdcd 3.2.0f 实测）。
 */
export const VERSION_STR = 'Ver: 3.2.0e7fdbc1aa8c5fefaa';

/** commandFlag（define_enum.h） */
export const CMD = {
  KERNEL_HANDSHAKE: 1,
  KERNEL_CHANNEL_CLOSE: 2,
  KERNEL_ECHO: 9,
  KERNEL_ECHO_RAW: 10,
  KERNEL_WAKEUP_SLAVETASK: 12, // file 任务前导空帧（抓包实证）
  UNITY_EXECUTE: 1001,
  UNITY_ROOTRUN: 1007, // 空 payload 开启 root，"r" 关闭
  FILE_CHECK: 3001,
  FILE_BEGIN: 3002,
  FILE_DATA: 3003,
  FILE_FINISH: 3004,
} as const;

/** SessionHandShake.authType */
export const AUTH = {
  NONE: 0,
  TOKEN: 1,
  SIGNATURE: 2,
  PUBLICKEY: 3,
  OK: 4,
  FAIL: 5,
} as const;

/** daemon 单块上限 511KB；用稳定档 60KB-64（transfer.h payloadPrefixReserve） */
export const BLOCK_SIZE = 60 * 1024 - 64;
/** TransferPayload 序列化占用的固定前缀长度（补零到该长度） */
export const PAYLOAD_PREFIX_RESERVE = 64;

export interface Frame {
  channelId: number;
  commandFlag: number;
  data: Buffer;
}

// ---------- varint / protobuf ----------

export function putVarint(value: number | bigint): number[] {
  const out: number[] = [];
  let v = BigInt(value);
  do {
    let b = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) b |= 0x80;
    out.push(b);
  } while (v > 0n);
  return out;
}

export function pbVarint(field: number, value: number | bigint): number[] {
  return [...putVarint((field << 3) | 0), ...putVarint(value)];
}

export function pbBytes(field: number, bytes: Buffer): number[] {
  return [...putVarint((field << 3) | 2), ...putVarint(bytes.length), ...bytes];
}

export function pbString(field: number, s: string): number[] {
  return pbBytes(field, Buffer.from(s, 'latin1'));
}

export interface PbField {
  field: number;
  value?: bigint;
  bytes?: Buffer;
}

/** 轻量 protobuf 解码：仅 varint 与 length-delimited 两种 wire type。 */
export function pbDecode(buf: Buffer): PbField[] {
  const fields: PbField[] = [];
  let i = 0;
  while (i < buf.length) {
    let tag = 0n;
    let shift = 0n;
    for (;;) {
      const b = buf[i++];
      tag |= BigInt(b & 0x7f) << shift;
      shift += 7n;
      if (!(b & 0x80)) break;
    }
    const field = Number(tag >> 3n);
    const wire = Number(tag & 7n);
    if (wire === 0) {
      let v = 0n;
      let s = 0n;
      for (;;) {
        const b = buf[i++];
        v |= BigInt(b & 0x7f) << s;
        s += 7n;
        if (!(b & 0x80)) break;
      }
      fields.push({ field, value: v });
    } else if (wire === 2) {
      let len = 0n;
      let s = 0n;
      for (;;) {
        const b = buf[i++];
        len |= BigInt(b & 0x7f) << s;
        s += 7n;
        if (!(b & 0x80)) break;
      }
      const n = Number(len);
      fields.push({ field, bytes: buf.subarray(i, i + n) });
      i += n;
    } else {
      throw new Error(`unsupported wire type ${wire}`);
    }
  }
  return fields;
}

// ---------- 帧 ----------

/** PayloadProtect: channelId=1 commandFlag=2 checkSum=3 vCode=4 */
export function encodeProtect(channelId: number, commandFlag: number): Buffer {
  return Buffer.from([
    ...pbVarint(1, channelId),
    ...pbVarint(2, commandFlag),
    ...pbVarint(3, 0), // ENABLE_IO_CHECKSUM=false
    ...pbVarint(4, VCODE),
  ]);
}

export function buildFrame(channelId: number, commandFlag: number, data: Buffer = Buffer.alloc(0)): Buffer {
  const protect = encodeProtect(channelId, commandFlag);
  const head = Buffer.alloc(11);
  head.write('HW', 0, 'latin1');
  head.writeUInt8(PROTOCOL_VER, 4);
  head.writeUInt16BE(protect.length, 5);
  head.writeUInt32BE(data.length, 7);
  return Buffer.concat([head, protect, data]);
}

/** 流式分帧：`feed` 追加字节，`nextFrame` 在凑齐完整帧时返回，否则 null。 */
export class FrameReader {
  private buf: Buffer = Buffer.alloc(0);

  feed(chunk: Buffer): void {
    this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
  }

  nextFrame(): Frame | null {
    if (this.buf.length < 11) return null;
    if (this.buf.subarray(0, 2).toString('latin1') !== 'HW') throw new Error('frame magic mismatch');
    const headSize = this.buf.readUInt16BE(5);
    const dataSize = this.buf.readUInt32BE(7);
    const total = 11 + headSize + dataSize;
    if (this.buf.length < total) return null;

    const protect = this.buf.subarray(11, 11 + headSize);
    const data = Buffer.from(this.buf.subarray(11 + headSize, total));
    this.buf = this.buf.subarray(total);

    let channelId = 0;
    let commandFlag = 0;
    for (const f of pbDecode(protect)) {
      if (f.field === 1) channelId = Number(f.value ?? 0n);
      if (f.field === 2) commandFlag = Number(f.value ?? 0n);
    }
    return { channelId, commandFlag, data };
  }
}

// ---------- SessionHandShake ----------

export interface Handshake {
  authType: number;
  buf: Buffer;
  version: string;
}

export interface HandshakeInit {
  banner?: string;
  authType?: number;
  sessionId?: number;
  connectKey?: string;
  buf?: Buffer | string;
  version?: string;
}

export function encodeHandshake(init: HandshakeInit = {}): Buffer {
  const {
    banner = BANNER,
    authType = AUTH.NONE,
    sessionId = 0,
    connectKey = '',
    buf = Buffer.alloc(0),
    version = VERSION_STR,
  } = init;
  const payload = typeof buf === 'string' ? Buffer.from(buf, 'latin1') : buf;
  return Buffer.from([
    ...pbString(1, banner),
    ...pbVarint(2, authType),
    ...pbVarint(3, sessionId),
    ...pbString(4, connectKey),
    ...pbBytes(5, payload),
    ...pbString(6, version),
  ]);
}

export function parseHandshake(data: Buffer): Handshake {
  const hs: Handshake = { authType: AUTH.NONE, buf: Buffer.alloc(0), version: '' };
  for (const f of pbDecode(data)) {
    if (f.field === 2) hs.authType = Number(f.value ?? 0n);
    if (f.field === 5) hs.buf = Buffer.from(f.bytes ?? []);
    if (f.field === 6) hs.version = (f.bytes ?? Buffer.alloc(0)).toString('latin1');
  }
  return hs;
}

// ---------- TLV（base.cpp TlvAppend：tag 16B 定长 + len 16B 定长 + value） ----------

export function tlvAppend(tag: string, val: string): Buffer {
  const t = tag.padEnd(16, ' ').slice(0, 16);
  const l = String(val.length).padEnd(16, ' ').slice(0, 16);
  return Buffer.from(t + l + val, 'latin1');
}
