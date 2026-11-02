/**
 * 协议黄金用例：全部取自 2026-11-02 与真机 hdcd 3.2.0f 的实机抓包
 * （对照官方 hdc 3.2.0e 客户端流量）。改编码器必须保这些字节不变。
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
  const data = Buffer.from('"echo PROTOCOL_TEST"', 'latin1');
  const frame = buildFrame(0x33ccf4a7, CMD.UNITY_EXECUTE, data);
  assert.equal(frame.subarray(0, 2).toString('latin1'), 'HW');
  assert.equal(frame[4], 0x01);
  assert.equal(frame.readUInt16BE(5), 13); // protect 长度
  assert.equal(frame.readUInt32BE(7), data.length);
  assert.equal(frame.length, 11 + 13 + data.length);
});

test('frame reader roundtrip and split feeds', () => {
  const f1 = buildFrame(7, CMD.KERNEL_ECHO_RAW, Buffer.from('hello'));
  const f2 = buildFrame(0x7fffffff, CMD.FILE_DATA, Buffer.alloc(300, 0xab));

  const r = new FrameReader();
  r.feed(f1.subarray(0, 5));
  assert.equal(r.nextFrame(), null);
  r.feed(f1.subarray(5));
  const a = r.nextFrame();
  assert.ok(a);
  assert.equal(a.channelId, 7);
  assert.equal(a.commandFlag, CMD.KERNEL_ECHO_RAW);
  assert.equal(a.data.toString(), 'hello');

  // 粘包：两帧一次喂入
  r.feed(Buffer.concat([f1, f2]));
  const b = r.nextFrame();
  const c = r.nextFrame();
  assert.ok(b && c);
  assert.equal(b.channelId, 7);
  assert.equal(c.channelId, 0x7fffffff);
  assert.equal(c.data.length, 300);
});

test('handshake encode matches capture prefix', () => {
  // 抓包 hello 帧 data 开头：0a 08 "OHOS HDC" 10 00 18 <sessionId varint> 22 ...
  const buf = Buffer.concat([
    tlvAppend('authtype', '1'),
    tlvAppend('supportfeatures', 'Ver: 3.2.0e,TCP,mac,heartbeat'),
  ]);
  const hs = encodeHandshake({ authType: AUTH.NONE, sessionId: 0x4f2f, connectKey: '127.0.0.1:46300', buf });
  const expectedPrefix = Buffer.concat([
    hex('0a08'), // field1(banner) len8
    Buffer.from('OHOS HDC', 'latin1'),
    hex('1000'), // field2(authType) = 0
    hex('18'), // field3(sessionId)
    Buffer.from(putVarint(0x4f2f)), // sessionId varint
  ]);
  assert.ok(hs.subarray(0, expectedPrefix.length).equals(expectedPrefix));
  // version 字段必须非空且为官方串
  assert.ok(hs.includes(Buffer.from(VERSION_STR, 'latin1')));
});

test('handshake parse roundtrip', () => {
  const buf = tlvAppend('authtype', '1');
  const hs = encodeHandshake({ authType: AUTH.SIGNATURE, sessionId: 42, connectKey: 'k', buf, version: 'Ver: 9.9.9x' });
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
  const pld = Buffer.from([...pbVarint(1, 0), ...pbVarint(2, 0), ...pbVarint(3, 20), ...pbVarint(4, 20)]);
  const payload = Buffer.concat([pld, Buffer.alloc(PAYLOAD_PREFIX_RESERVE - pld.length)]);
  assert.equal(payload.length, 64);
  assert.deepEqual(payload.subarray(0, 8), hex('0800100018142014'));
});
