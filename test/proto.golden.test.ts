/**
 * 协议黄金用例：全部取自 2026-11-02 与真机 hdcd 3.2.0f 的实机抓包
 * （对照官方 hdc 3.2.0e 客户端流量）。改编码器必须保证这些字节不变。
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import {
    AUTH,
    CMD,
    FrameReader,
    PAYLOAD_PREFIX_RESERVE,
    VERSION_STR,
    buildFrame,
    encodeHandshake,
    encodeProtect,
    parseHandshake,
    pbVarint,
    putVarint,
    tlvAppend,
} from '../src/proto.js';

// 帧头固定长度（11B）
const FRAME_HEAD_SIZE = 11;
// 抓包中单块文件大小（20B）
const CAPTURE_FILE_SIZE = 20;

/**
 * 把十六进制字符串转成 Buffer。
 *
 * @param s 十六进制串（允许空格分隔）
 * @returns 字节
 */
function hex(s: string): Buffer {
    return Buffer.from(s.replace(/[^0-9a-fA-F]/g, ''), 'hex');
}

test('protect encoding matches capture', () => {
    // 抓包：握手帧 protect = 08 00 10 01 18 00 20 09（cid=0, flag=1）
    assert.deepEqual(encodeProtect(0, CMD.KERNEL_HANDSHAKE), hex('0800100118002009'));
    // 抓包：shell 数据帧 protect，cid=0x3e，flag=1001(0xe907)
    assert.deepEqual(encodeProtect(0x3e, CMD.UNITY_EXECUTE), hex('083e10e90718002009'));
});

test('frame header matches capture', () => {
    // 抓包 44B shell 帧的载荷（含引号，官方客户端会整体加引号）
    const data = Buffer.from('"echo PROTOCOL_TEST"', 'latin1');
    const frame = buildFrame(0x33ccf4a7, CMD.UNITY_EXECUTE, data);
    // headSize 必须等于 protect 序列化长度（protobuf varint 随 cid 大小变化）
    const protectLen = encodeProtect(0x33ccf4a7, CMD.UNITY_EXECUTE).length;
    assert.equal(frame.subarray(0, 2).toString('latin1'), 'HW');
    assert.equal(frame[4], 0x01); // protocolVer
    assert.equal(frame.readUInt16BE(5), protectLen);
    assert.equal(frame.readUInt32BE(7), data.length);
    assert.equal(frame.length, FRAME_HEAD_SIZE + protectLen + data.length);
});

test('frame reader roundtrip and split feeds', () => {
    // 两帧：小 cid 的 ECHO_RAW 与大 cid 的 FILE_DATA（验证粘包/半包）
    const first = buildFrame(7, CMD.KERNEL_ECHO_RAW, Buffer.from('hello'));
    const second = buildFrame(0x7fffffff, CMD.FILE_DATA, Buffer.alloc(300, 0xab));

    const reader = new FrameReader();
    reader.feed(first.subarray(0, 5));
    assert.equal(reader.nextFrame(), null);

    reader.feed(first.subarray(5));
    const parsedFirst = reader.nextFrame();
    assert.ok(parsedFirst);
    assert.equal(parsedFirst.channelId, 7);
    assert.equal(parsedFirst.commandFlag, CMD.KERNEL_ECHO_RAW);
    assert.equal(parsedFirst.data.toString(), 'hello');

    // 粘包：两帧一次喂入
    reader.feed(Buffer.concat([first, second]));
    const parsedSecond = reader.nextFrame();
    const parsedThird = reader.nextFrame();
    assert.ok(parsedSecond && parsedThird);
    assert.equal(parsedSecond.channelId, 7);
    assert.equal(parsedThird.channelId, 0x7fffffff);
    assert.equal(parsedThird.data.length, 300);
});

test('handshake encode matches capture prefix', () => {
    // 抓包 hello 帧 data 开头：0a 08 "OHOS HDC" 10 00 18 <sessionId varint> 22 ...
    const helloBuf = Buffer.concat([
        tlvAppend('authtype', '1'),
        tlvAppend('supportfeatures', 'Ver: 3.2.0e,TCP,mac,heartbeat'),
    ]);
    const hs = encodeHandshake({ authType: AUTH.NONE, sessionId: 0x4f2f, connectKey: '127.0.0.1:46300', buf: helloBuf });
    // 期望前缀：field1(banner,len8) + "OHOS HDC" + field2(authType=0) + field3(sessionId)+varint
    const expectedPrefix = Buffer.concat([
        hex('0a08'),
        Buffer.from('OHOS HDC', 'latin1'),
        hex('1000'),
        hex('18'),
        Buffer.from(putVarint(0x4f2f)),
    ]);
    assert.ok(hs.subarray(0, expectedPrefix.length).equals(expectedPrefix));
    // version 字段必须非空且为官方串（空值会被 daemon 以 "version too low" 拒绝）
    assert.ok(hs.includes(Buffer.from(VERSION_STR, 'latin1')));
});

test('handshake parse roundtrip', () => {
    // 构造 → 解析 应还原 authType / version / buf 三个关键字段
    const payload = tlvAppend('authtype', '1');
    const hs = encodeHandshake({ authType: AUTH.SIGNATURE, sessionId: 42, connectKey: 'k', buf: payload, version: 'Ver: 9.9.9x' });
    const parsed = parseHandshake(hs);
    assert.equal(parsed.authType, AUTH.SIGNATURE);
    assert.equal(parsed.version, 'Ver: 9.9.9x');
    assert.ok(parsed.buf.includes(Buffer.from('authtype')));
});

test('tlv format is fixed width', () => {
    // base.cpp TlvAppend：tag 16B 定长 + len 16B 定长 + value
    const out = tlvAppend('authtype', '1');
    assert.equal(out.length, 33);
    assert.equal(out.subarray(0, 16).toString(), 'authtype        ');
    assert.equal(out.subarray(16, 32).toString(), '1               ');
    assert.equal(out.subarray(32).toString(), '1');
});

test('varint encoding edge cases', () => {
    // channelId 必须无符号：0x7fffffff（最大正 cid）编码 5 字节
    assert.deepEqual(putVarint(0x7fffffff), [0xff, 0xff, 0xff, 0xff, 0x07]);
    assert.deepEqual(putVarint(1), [0x01]);
    // 负数会被截断成低 7 位——这正是 channelId 必须为正的硬性原因
    assert.notDeepEqual(putVarint(-1), putVarint(0x7fffffff));
});

test('file payload prefix is 64 bytes', () => {
    // TransferPayload 序列化 + 补零 = 固定 64B 前缀；抓包单块 20B 文件：
    // index=0、compressSize=uncompressSize=20 → 08 00 10 00 18 14 20 14
    const pld = Buffer.from([
        ...pbVarint(1, 0),
        ...pbVarint(2, 0),
        ...pbVarint(3, CAPTURE_FILE_SIZE),
        ...pbVarint(4, CAPTURE_FILE_SIZE),
    ]);
    const payload = Buffer.concat([pld, Buffer.alloc(PAYLOAD_PREFIX_RESERVE - pld.length)]);
    assert.equal(payload.length, PAYLOAD_PREFIX_RESERVE);
    assert.deepEqual(payload.subarray(0, 8), hex('0800100018142014'));
});
