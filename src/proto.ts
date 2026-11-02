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

// 协议版本号（PayloadHead.protocolVer，抓包恒为 1）
export const PROTOCOL_VER = 0x01;
// PayloadProtect.vCode 静态校验值（session.h payloadProtectStaticVcode）
export const VCODE = 0x09;
// 帧头固定长度（PayloadHead，packed）
const FRAME_HEAD_SIZE = 11;
// 帧起始标识（PACKET_FLAG，session.h）
const PACKET_FLAG = 'HW';
// 握手 banner（HANDSHAKE_MESSAGE，banner 不匹配时 daemon 直接丢帧）
export const BANNER = 'OHOS HDC';

/**
 * 与官方 host 3.2.0e 一致。daemon 校验版本非空（空值触发 "version too low"
 * 拒绝）；与 daemon 版本不一致仅记录日志（真机 hdcd 3.2.0f 实测）。
 */
export const VERSION_STR = 'Ver: 3.2.0e7fdbc1aa8c5fefaa';

/**
 * commandFlag（define_enum.h）
 */
export const CMD = {
    // 内核握手（认证四步都走该命令字）
    KERNEL_HANDSHAKE: 1,
    // 通道关闭：任务收尾与握手后由 daemon 发起
    KERNEL_CHANNEL_CLOSE: 2,
    // 通用回显（任务总结信息走该命令字）
    KERNEL_ECHO: 9,
    // 原始输出（shell 的 stdout/stderr 走该命令字）
    KERNEL_ECHO_RAW: 10,
    // file 任务前导空帧（抓包实证，官方客户端必发）
    KERNEL_WAKEUP_SLAVETASK: 12,
    // 执行 shell 命令
    UNITY_EXECUTE: 1001,
    // 切换 hdcd 运行模式：空 payload 开启 root，"r" 关闭
    UNITY_ROOTRUN: 1007,
    // file 任务：接收方向由客户端发起（daemon 读远端文件并回传）
    FILE_INIT: 3000,
    // file 任务：参数检查 / 传输开始 / 数据块 / 结束
    FILE_CHECK: 3001,
    FILE_BEGIN: 3002,
    FILE_DATA: 3003,
    FILE_FINISH: 3004,
} as const;

/**
 * SessionHandShake.authType（daemon 认证状态机取值）
 */
export const AUTH = {
    // 客户端发起，尚未认证
    NONE: 0,
    // 旧版令牌认证（本项目不使用）
    TOKEN: 1,
    // daemon 下发挑战，等待客户端签名
    SIGNATURE: 2,
    // daemon 索要客户端公钥
    PUBLICKEY: 3,
    // 认证通过
    OK: 4,
    // 认证失败
    FAIL: 5,
} as const;

/**
 * daemon 单块上限 511KB；用稳定档 60KB-64（transfer.h payloadPrefixReserve）
 */
export const BLOCK_SIZE = 60 * 1024 - 64;
/**
 * TransferPayload 序列化占用的固定前缀长度（不足补零，transfer.h payloadPrefixReserve）
 */
export const PAYLOAD_PREFIX_RESERVE = 64;

/**
 * 解码后的帧。
 */
export interface Frame {
    // PayloadProtect.channelId：任务通道标识
    channelId: number;
    // PayloadProtect.commandFlag：命令字（见 CMD）
    commandFlag: number;
    // 帧载荷（不含 protect 头）
    data: Buffer;
}

/**
 * 编码一个 varint（protobuf 可变长整数）。
 *
 * @param value 非负整数
 * @returns 编码后的字节数组
 */
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

/**
 * 编码 varint 类型的 protobuf 字段（wire type 0）。
 *
 * @param field 字段号
 * @param value 字段值
 * @returns 编码后的字节数组
 */
export function pbVarint(field: number, value: number | bigint): number[] {
    return [...putVarint((field << 3) | 0), ...putVarint(value)];
}

/**
 * 编码 length-delimited 类型的 protobuf 字段（wire type 2）。
 *
 * @param field 字段号
 * @param bytes 字段字节内容
 * @returns 编码后的字节数组
 */
export function pbBytes(field: number, bytes: Buffer): number[] {
    return [...putVarint((field << 3) | 2), ...putVarint(bytes.length), ...bytes];
}

/**
 * 编码字符串字段（按 latin1 原样写入，保证与 C++ 侧字节一致）。
 *
 * @param field 字段号
 * @param s 字段内容
 * @returns 编码后的字节数组
 */
export function pbString(field: number, s: string): number[] {
    return pbBytes(field, Buffer.from(s, 'latin1'));
}

/**
 * 解码得到的单个 protobuf 字段。
 */
export interface PbField {
    // 字段号
    field: number;
    // wire type 0 时的整数值
    value?: bigint;
    // wire type 2 时的字节内容
    bytes?: Buffer;
}

/**
 * 轻量 protobuf 解码：仅支持 varint 与 length-delimited 两种 wire type。
 *
 * @param buf 待解码字节
 * @returns 字段列表
 */
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
            let value = 0n;
            let s = 0n;
            for (;;) {
                const b = buf[i++];
                value |= BigInt(b & 0x7f) << s;
                s += 7n;
                if (!(b & 0x80)) break;
            }
            fields.push({ field, value });
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

/**
 * 编码 PayloadProtect（channelId=1 / commandFlag=2 / checkSum=3 / vCode=4）。
 *
 * @param channelId 通道标识
 * @param commandFlag 命令字
 * @returns protect 字节
 */
export function encodeProtect(channelId: number, commandFlag: number): Buffer {
    return Buffer.from([
        ...pbVarint(1, channelId),
        ...pbVarint(2, commandFlag),
        ...pbVarint(3, 0), // ENABLE_IO_CHECKSUM=false，校验和恒为 0
        ...pbVarint(4, VCODE),
    ]);
}

/**
 * 组装一个完整帧。
 *
 * @param channelId 通道标识
 * @param commandFlag 命令字
 * @param data 载荷
 * @returns 可直接写入 socket 的字节
 */
export function buildFrame(channelId: number, commandFlag: number, data: Buffer = Buffer.alloc(0)): Buffer {
    const protect = encodeProtect(channelId, commandFlag);
    const head = Buffer.alloc(11);
    head.write('HW', 0, 'latin1');
    head.writeUInt8(PROTOCOL_VER, 4);
    head.writeUInt16BE(protect.length, 5);
    head.writeUInt32BE(data.length, 7);
    return Buffer.concat([head, protect, data]);
}

/**
 * 流式分帧器：TCP 流可能任意切分或合并帧。
 */
export class FrameReader {
    // 尚未消费的字节缓存
    private buf: Buffer = Buffer.alloc(0);

    /**
     * 追加一段 socket 数据。
     *
     * @param chunk 新到达的字节
     */
    feed(chunk: Buffer): void {
        this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
    }

    /**
     * 取下一个完整帧。
     *
     * @returns 完整帧；数据不足时返回 null
     */
    nextFrame(): Frame | null {
        if (this.buf.length < FRAME_HEAD_SIZE) return null;
        if (this.buf.subarray(0, 2).toString('latin1') !== PACKET_FLAG) throw new Error('frame magic mismatch');
        // protect 序列化长度（随 varint 值变化）
        const headSize = this.buf.readUInt16BE(5);
        // 载荷长度（不含 protect）
        const dataSize = this.buf.readUInt32BE(7);
        // 整帧长度
        const total = FRAME_HEAD_SIZE + headSize + dataSize;
        if (this.buf.length < total) return null;

        // PayloadProtect 字节（解析出通道与命令字）
        const protect = this.buf.subarray(FRAME_HEAD_SIZE, FRAME_HEAD_SIZE + headSize);
        // 帧载荷
        const data = Buffer.from(this.buf.subarray(FRAME_HEAD_SIZE + headSize, total));
        this.buf = this.buf.subarray(total);

        // 通道标识（protect 字段 1）
        let channelId = 0;
        // 命令字（protect 字段 2）
        let commandFlag = 0;
        for (const f of pbDecode(protect)) {
            if (f.field === 1) channelId = Number(f.value ?? 0n);
            if (f.field === 2) commandFlag = Number(f.value ?? 0n);
        }
        return { channelId, commandFlag, data };
    }
}

/**
 * 解析后的 SessionHandShake（只取本实现关心的字段）。
 */
export interface Handshake {
    // 认证状态机取值（见 AUTH）
    authType: number;
    // 认证载荷：公钥阶段的 hostname\x0C 公钥、签名阶段的 base64 签名、daemon 阶段的 TLV
    buf: Buffer;
    // daemon 版本串
    version: string;
}

/**
 * 握手帧构造参数。
 */
export interface HandshakeInit {
    // banner，默认 BANNER
    banner?: string;
    // 认证状态机取值
    authType?: number;
    // 会话 id（仅 hello 帧有效）
    sessionId?: number;
    // connectKey（仅 hello 帧有效，形如 host:port）
    connectKey?: string;
    // 认证载荷（字符串按 latin1 写入）
    buf?: Buffer | string;
    // 版本串，默认 VERSION_STR
    version?: string;
}

/**
 * 编码 SessionHandShake（banner=1 / authType=2 / sessionId=3 / connectKey=4 / buf=5 / version=6）。
 *
 * @param init 构造参数
 * @returns 握手帧载荷
 */
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

/**
 * 解析 SessionHandShake 载荷。
 *
 * @param data 握手帧载荷
 * @returns 解析结果
 */
export function parseHandshake(data: Buffer): Handshake {
    const hs: Handshake = { authType: AUTH.NONE, buf: Buffer.alloc(0), version: '' };
    for (const f of pbDecode(data)) {
        if (f.field === 2) hs.authType = Number(f.value ?? 0n);
        if (f.field === 5) hs.buf = Buffer.from(f.bytes ?? []);
        if (f.field === 6) hs.version = (f.bytes ?? Buffer.alloc(0)).toString('latin1');
    }
    return hs;
}

/**
 * 追加一个 TLV 项（base.cpp TlvAppend：tag 16B 定长 + len 16B 定长 + value）。
 *
 * @param tag 标签（不足 16 字节补空格）
 * @param val 值
 * @returns TLV 字节
 */
export function tlvAppend(tag: string, val: string): Buffer {
    const paddedTag = tag.padEnd(16, ' ').slice(0, 16);
    const paddedLen = String(val.length).padEnd(16, ' ').slice(0, 16);
    return Buffer.from(paddedTag + paddedLen + val, 'latin1');
}
