/**
 * TCP 直连 hdcd 的会话：握手认证 + shell + file send。
 *
 * 生命周期与官方 hdc CLI 一致：一条命令一个短连接（认证约 50ms）。
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
    pbDecode,
    pbString,
    pbVarint,
    tlvAppend,
    type Frame,
} from './proto.js';

// 默认单条命令超时（ms）
const DEFAULT_TIMEOUT_MS = 60000;
// 默认连接超时（ms）
const DEFAULT_CONNECT_TIMEOUT_MS = 10000;
// channelId 上界（必须保持为正数，见 newChannelId 注释）
const CHANNEL_ID_MAX = 0x7fffffff;
// 会话 id 上界（握手期使用，daemon 仅用于区分并发握手）
const SESSION_ID_MAX = 0xffff;
// 关闭连接后等待对端 FIN 的宽限期（ms）
const CLOSE_GRACE_MS = 3000;
// 解析错误哨兵帧的 channelId：不会与真实通道碰撞
const ERROR_CHANNEL_ID = 0xffffffff;
// 解析错误哨兵帧的 commandFlag
const ERROR_COMMAND_FLAG = 0xffff;
// 文件任务完成标志（daemon FILE_FINISH payload 首字节）
const FILE_FINISH_OK = 1;
// 通道关闭应答标志（CHANNEL_CLOSE payload）
const CHANNEL_CLOSE_ACK = 0;

/**
 * 生成无符号正数的 channelId。
 *
 * 必须为正：负值经 varint 编码会被截断为低 7 位，响应 channelId 与本地记录
 * 不再匹配（实测会导致约一半命令“假超时”）。
 *
 * @returns 通道标识
 */
export function newChannelId(): number {
    return Math.floor(Math.random() * CHANNEL_ID_MAX) + 1;
}

/**
 * 帧队列：socket 数据推入，按谓词异步取帧，超时抛错。
 */
class FrameQueue {
    // 已到达但尚未被消费的帧
    private frames: Frame[] = [];
    // 等待新帧的唤醒回调
    private notify: (() => void) | null = null;

    /**
     * 推入一帧并唤醒等待者。
     *
     * @param frame 新到达的帧
     */
    push(frame: Frame): void {
        this.frames.push(frame);
        const pending = this.notify;
        this.notify = null;
        pending?.();
    }

    /**
     * 等待满足谓词的帧。
     *
     * @param pred 帧匹配条件
     * @param timeoutMs 超时时间
     * @param what 超时错误中描述等待目标
     * @returns 匹配的帧
     */
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
                }, remain).unref();
            });
        }
    }
}

/**
 * 会话可调参数。
 */
export interface SessionOptions {
    // 单条命令整体超时（ms），默认 60000
    timeoutMs?: number;
    // 连接超时（ms），默认 10000
    connectTimeoutMs?: number;
}

/**
 * 与 hdcd 的一条 TCP 会话。
 */
export class HdcSession {
    // 流式分帧器
    private reader = new FrameReader();
    // 待消费帧队列
    private queue = new FrameQueue();
    // 握手会话 id
    private sessionId = Math.floor(Math.random() * SESSION_ID_MAX) + 1;
    // 连接是否已断开
    private closed = false;
    // socket 句柄
    private readonly sock: net.Socket;
    // 单条命令超时
    private readonly timeoutMs: number;

    /**
     * 绑定 socket 并注册数据/关闭回调（不发起握手）。
     *
     * @param sock 已连接的 socket
     * @param timeoutMs 单条命令超时
     */
    private constructor(sock: net.Socket, timeoutMs: number) {
        this.sock = sock;
        this.timeoutMs = timeoutMs;
        sock.on('data', (chunk: Buffer) => {
            try {
                this.reader.feed(chunk);
                for (let f = this.reader.nextFrame(); f; f = this.reader.nextFrame()) this.queue.push(f);
            } catch (e) {
                // 解析失败时投递哨兵帧，让等待中的调用以可读错误结束
                this.destroy();
                this.queue.push({
                    channelId: ERROR_CHANNEL_ID,
                    commandFlag: ERROR_COMMAND_FLAG,
                    data: Buffer.from(String(e)),
                });
            }
        });
        sock.on('error', () => this.destroy());
        sock.on('close', () => {
            this.closed = true;
        });
    }

    /**
     * 建连并完成 daemon 认证（hello → 公钥 → 挑战签名 → AUTH_OK）。
     *
     * @param host 设备地址
     * @param port hdcd 监听端口
     * @param opts 超时等选项
     * @returns 已完成认证的会话
     */
    static async connect(host: string, port: number, opts: SessionOptions = {}): Promise<HdcSession> {
        const timeoutMs = opts.timeoutMs ?? Number(process.env.HDC_SHELL_TIMEOUT || DEFAULT_TIMEOUT_MS);
        const sock = net.connect({ host, port });
        sock.setNoDelay(true);
        await new Promise<void>((resolve, reject) => {
            const timer = setTimeout(() => {
                sock.destroy();
                reject(new Error(`connect ${host}:${port} timeout`));
            }, opts.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS);
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

    /**
     * 执行 daemon 认证握手。
     *
     * @param host 设备地址（写入 connectKey）
     * @param port hdcd 端口（写入 connectKey）
     */
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

        // 2) 提交 hostname \x0C 公钥（分隔符为 0x0C，daemon GetHostPubkeyInfo 解析）
        const payload = Buffer.concat([
            Buffer.from(`${hostnameStr()}\x0C`, 'latin1'),
            Buffer.from(key.pubPem, 'latin1'),
        ]);
        this.send(buildFrame(0, CMD.KERNEL_HANDSHAKE, encodeHandshake({ authType: AUTH.PUBLICKEY, buf: payload })));
        hs = parseHandshake((await this.wait(0, undefined, 'handshake pubkey')).data);
        if (hs.authType !== AUTH.SIGNATURE) {
            throw new Error(`expect AUTH_SIGNATURE, got ${hs.authType}`);
        }

        // 3) RSA-PSS(SHA-512) 签名回传，daemon 用白名单公钥验签
        const signature = signToken(key.privPem, hs.buf);
        this.send(buildFrame(0, CMD.KERNEL_HANDSHAKE, encodeHandshake({ authType: AUTH.SIGNATURE, buf: signature })));
        hs = parseHandshake((await this.wait(0, undefined, 'handshake auth')).data);
        if (hs.authType !== AUTH.OK) {
            const msg = hs.buf.toString('utf8').slice(0, 200);
            throw new Error(`auth failed (type=${hs.authType}): ${msg}`);
        }

        // 4) daemon 发 cid=0 CHANNEL_CLOSE(data=01)，回 data=00（抓包行为）
        await this.wait(0, CMD.KERNEL_CHANNEL_CLOSE, 'handshake close');
        this.send(buildFrame(0, CMD.KERNEL_CHANNEL_CLOSE, Buffer.from([CHANNEL_CLOSE_ACK])));
    }

    /**
     * 写入一帧。
     *
     * @param buf 完整帧字节
     */
    private send(buf: Buffer): void {
        if (this.closed) throw new Error('connection closed');
        this.sock.write(buf);
    }

    /**
     * 等待指定通道（可选命令字）的帧。
     *
     * @param channelId 通道标识
     * @param commandFlag 命令字过滤，undefined 表示不过滤
     * @param what 超时错误中描述等待目标
     * @returns 匹配的帧
     */
    private wait(channelId: number, commandFlag: number | undefined, what: string): Promise<Frame> {
        return this.queue.next(
            (f) => f.channelId === channelId && (commandFlag === undefined || f.commandFlag === commandFlag),
            this.timeoutMs,
            what,
        );
    }

    /**
     * 执行一条 shell 命令并收集输出。
     *
     * 官方客户端把整条命令包在双引号内交给设备 shell 解释。
     *
     * @param cmd 命令文本
     * @returns 命令输出
     */
    async shell(cmd: string): Promise<Buffer> {
        const channelId = newChannelId();
        this.send(buildFrame(channelId, CMD.UNITY_EXECUTE, Buffer.from(`"${cmd}"`, 'latin1')));
        const out: Buffer[] = [];
        for (;;) {
            const frame = await this.wait(channelId, undefined, `shell "${cmd.slice(0, 40)}"`);
            if (frame.commandFlag === CMD.KERNEL_ECHO_RAW || frame.commandFlag === CMD.KERNEL_ECHO) {
                out.push(frame.data);
            } else if (frame.commandFlag === CMD.KERNEL_CHANNEL_CLOSE) {
                // 官方客户端对同一 channelId 连发两次 close(00)（抓包实证），
                // daemon 的 task 清理依赖第二次 close
                this.send(buildFrame(channelId, CMD.KERNEL_CHANNEL_CLOSE, Buffer.from([CHANNEL_CLOSE_ACK])));
                this.send(buildFrame(channelId, CMD.KERNEL_CHANNEL_CLOSE, Buffer.from([CHANNEL_CLOSE_ACK])));
                break;
            }
        }
        return Buffer.concat(out);
    }

    /**
     * 执行 shell 命令并返回 UTF-8 文本。
     *
     * @param cmd 命令文本
     * @returns 命令输出
     */
    async shellStr(cmd: string): Promise<string> {
        return (await this.shell(cmd)).toString('utf8');
    }

    /**
     * 上传本地文件到设备路径。
     *
     * 时序：WAKEUP_SLAVETASK 空帧 → FILE_CHECK(TransferConfig) → FILE_BEGIN →
     * 分块 FILE_DATA（TransferPayload 补零至固定 64B 前缀 + 数据）→
     * FILE_FINISH=01 → 回 00 → ECHO 总结 → close。
     *
     * @param localPath 本地文件路径
     * @param remotePath 设备目标路径
     * @returns daemon 返回的传输总结
     */
    async fileSend(localPath: string, remotePath: string): Promise<string> {
        const data = fs.readFileSync(localPath);
        // 本地文件 stat：atime/mtime 写入 TransferConfig，供 daemon 保留时间戳
        const st = fs.statSync(localPath);
        const channelId = newChannelId();

        // 1) 前导空帧（官方客户端行为）
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
            ...pbString(12, ''), // reserve1
            ...pbString(13, ''), // reserve2
        ]);
        this.send(buildFrame(channelId, CMD.FILE_CHECK, cfg));
        await this.wait(channelId, CMD.FILE_BEGIN, 'file begin');

        // 3) 分块 FILE_DATA。index 是文件字节偏移而非块序号：
        //    daemon 侧 uv_fs_write(..., offset=index) 直接用它定位（transfer.cpp SimpleFileIO）。
        const chunkCount = Math.max(1, Math.ceil(data.length / BLOCK_SIZE));
        for (let n = 0; n < chunkCount; n++) {
            const offset = n * BLOCK_SIZE;
            const chunk = data.subarray(offset, Math.min(offset + BLOCK_SIZE, data.length));
            const pld = Buffer.from([
                ...pbVarint(1, offset),
                ...pbVarint(2, 0),
                ...pbVarint(3, chunk.length),
                ...pbVarint(4, chunk.length),
            ]);
            // TransferPayload 必须补零到固定 64B 前缀（daemon 按该长度切分）
            const prefix = Buffer.concat([pld, Buffer.alloc(PAYLOAD_PREFIX_RESERVE - pld.length)]);
            this.send(buildFrame(channelId, CMD.FILE_DATA, Buffer.concat([prefix, chunk])));
        }

        // 4) 等 FINISH=01，回 00；收 ECHO 总结与 close
        const fin = await this.wait(channelId, CMD.FILE_FINISH, 'file finish');
        const ok = fin.data.length > 0 && fin.data[0] === FILE_FINISH_OK;
        this.send(buildFrame(channelId, CMD.FILE_FINISH, Buffer.from([CHANNEL_CLOSE_ACK])));
        // 总结帧与关闭帧缺失不影响结果判定（以 FINISH 标志为准）
        let summary = '';
        try {
            summary = (await this.wait(channelId, CMD.KERNEL_ECHO, 'file summary')).data.toString('utf8').trim();
        } catch {
            summary = '';
        }
        try {
            await this.wait(channelId, CMD.KERNEL_CHANNEL_CLOSE, 'file close');
        } catch {
            // 忽略：后续仍会主动发送 close
        }
        this.send(buildFrame(channelId, CMD.KERNEL_CHANNEL_CLOSE, Buffer.from([CHANNEL_CLOSE_ACK])));
        this.send(buildFrame(channelId, CMD.KERNEL_CHANNEL_CLOSE, Buffer.from([CHANNEL_CLOSE_ACK])));
        if (!ok) throw new Error(`file transfer failed: ${summary || '(no summary)'}`);
        return summary;
    }

    /**
     * 从设备下载文件到本地。
     *
     * 时序：FILE_INIT("recv <remote> <local>") → daemon 以 master 身份打开远端文件、
     * 回 FILE_CHECK(TransferConfig) → 客户端回 FILE_BEGIN(空) → 收 FILE_DATA
     * （同样 64B 前缀 + 数据）→ 收满 fileSize 字节后客户端主动发 FILE_FINISH(01)
     * → daemon 回 00 → ECHO 总结 → close。
     *
     * 方向与 fileSend 相反：fileSend 由客户端发 FILE_CHECK，daemon 当 slave 写文件；
     * fileRecv 由客户端发 FILE_INIT，daemon 当 master 读文件（hdc file.cpp 实证）。
     * master 发完数据不会主动结束（源码："Only slave receives complete talents Finish"），
     * 必须由客户端按 fileSize 判定收满并先发 FINISH。
     *
     * @param remotePath 设备源路径
     * @param localPath 本地目标路径
     * @returns daemon 返回的传输总结
     */
    async fileRecv(remotePath: string, localPath: string): Promise<string> {
        const channelId = newChannelId();

        // 1) FILE_INIT：daemon 侧按 "recv remote local" 解析（argv 末项是 client 本地路径）
        this.send(buildFrame(channelId, CMD.FILE_INIT, Buffer.from(`recv ${remotePath} ${localPath}`)));

        // 2) daemon 回 FILE_CHECK + TransferConfig：field 1 = fileSize
        const check = await this.wait(channelId, CMD.FILE_CHECK, 'file check');
        const fileSizeField = pbDecode(check.data).find((f) => f.field === 1);
        const fileSize = Number(fileSizeField?.value ?? 0n);

        // 3) FILE_BEGIN 空 payload：daemon 用默认缓冲大小开始发送
        this.send(buildFrame(channelId, CMD.FILE_BEGIN, Buffer.alloc(0)));

        // 4) 收数据块：daemon 不会发 FINISH，收满 fileSize 即结束（空文件直接跳到 5）
        const chunks: Buffer[] = [];
        let received = 0;
        while (received < fileSize) {
            const frame = await this.wait(channelId, undefined, 'file data');
            if (frame.commandFlag !== CMD.FILE_DATA) continue;
            // 前缀是 TransferPayload（index/compressSize 等），文件内容在其后
            const chunk = frame.data.subarray(PAYLOAD_PREFIX_RESERVE);
            chunks.push(chunk);
            received += chunk.length;
        }

        // 5) 客户端主动 FINISH(01)，daemon 回 00 后结束任务（master 侧不发 ECHO/总结）
        this.send(buildFrame(channelId, CMD.FILE_FINISH, Buffer.from([FILE_FINISH_OK])));
        const fin = await this.wait(channelId, CMD.FILE_FINISH, 'file finish ack');
        const ok = fin.data.length > 0 && fin.data[0] === CHANNEL_CLOSE_ACK;

        const data = Buffer.concat(chunks);
        // 大小校验：避免半包静默落盘
        if (!ok || data.length !== fileSize) {
            throw new Error(`file recv failed (${data.length}/${fileSize} bytes)`);
        }
        fs.writeFileSync(localPath, data);
        return `FileTransfer finish, Size:${data.length}`;
    }

    /**
     * 请求 hdcd 以 root 重启（等价官方 `hdc root`）。
     *
     * 需设备 `const.debuggable=1`，否则 daemon 返回
     * "Cannot set root run mode in undebuggable version."。
     *
     * @returns daemon 的即时响应文本
     */
    async requestRootRestart(): Promise<string> {
        const channelId = newChannelId();
        this.send(buildFrame(channelId, CMD.UNITY_ROOTRUN));
        const out: Buffer[] = [];
        for (;;) {
            const frame = await this.wait(channelId, undefined, 'root restart');
            if (frame.commandFlag === CMD.KERNEL_ECHO || frame.commandFlag === CMD.KERNEL_ECHO_RAW) {
                out.push(frame.data);
            } else if (frame.commandFlag === CMD.KERNEL_CHANNEL_CLOSE) {
                this.send(buildFrame(channelId, CMD.KERNEL_CHANNEL_CLOSE, Buffer.from([CHANNEL_CLOSE_ACK])));
                this.send(buildFrame(channelId, CMD.KERNEL_CHANNEL_CLOSE, Buffer.from([CHANNEL_CLOSE_ACK])));
                break;
            }
        }
        return Buffer.concat(out).toString('utf8').trim();
    }

    /**
     * 优雅断开：FIN 关闭。
     *
     * RST 会让 daemon 的 session 清理卡在 busy 状态，因此优先 `end()`，
     * 宽限期后再强制销毁。
     */
    close(): void {
        if (this.closed) return;
        this.closed = true;
        const sock = this.sock;
        try {
            sock.end();
        } catch {
            this.destroy();
            return;
        }
        setTimeout(() => {
            try {
                sock.destroy();
            } catch {
                // 已销毁，忽略
            }
        }, CLOSE_GRACE_MS).unref();
    }

    /**
     * 立即销毁连接（错误路径使用）。
     */
    private destroy(): void {
        this.closed = true;
        try {
            this.sock.destroy();
        } catch {
            // 已销毁，忽略
        }
    }
}

/**
 * 取本机 hostname（daemon 记录并展示给用户的开发者标识）。
 *
 * @returns hostname，取不到时回退 'hdc-direct'
 */
function hostnameStr(): string {
    try {
        const name = fs.readFileSync('/etc/hostname', 'utf8').trim();
        if (name) return name;
    } catch {
        // 无 /etc/hostname 时回退环境变量
    }
    return process.env.HOSTNAME || 'hdc-direct';
}
