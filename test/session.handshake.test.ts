/**
 * 回归：daemon 已信任公钥时会在 pubkey 阶段直接回 AUTH_OK（不再下发签名挑战，
 * 也不发收尾 CHANNEL_CLOSE）。0.3.0 只接受 AUTH_SIGNATURE，会误报
 * `expect AUTH_SIGNATURE, got 4`（HarmonyOS 真机 2026-11-20 实测）。
 */
import assert from 'node:assert/strict';
import net from 'node:net';
import test from 'node:test';

import { AUTH, CMD, FrameReader, buildFrame, encodeHandshake, parseHandshake } from '../src/proto.js';
import { HdcSession } from '../src/session.js';

function startTrustedKeyDaemon(): Promise<{ port: number; close: () => void }> {
    return new Promise((resolve) => {
        const server = net.createServer((sock) => {
            const reader = new FrameReader();
            sock.on('data', (chunk) => {
                reader.feed(chunk);
                for (let f = reader.nextFrame(); f; f = reader.nextFrame()) {
                    if (f.channelId === 0 && f.commandFlag === CMD.KERNEL_HANDSHAKE) {
                        const hs = parseHandshake(f.data);
                        if (hs.authType === AUTH.NONE) {
                            sock.write(
                                buildFrame(
                                    0,
                                    CMD.KERNEL_HANDSHAKE,
                                    encodeHandshake({ authType: AUTH.PUBLICKEY }),
                                ),
                            );
                        } else if (hs.authType === AUTH.PUBLICKEY) {
                            // 关键：直接放行，既不发 SIGNATURE 挑战，也不发收尾 CLOSE
                            sock.write(
                                buildFrame(
                                    0,
                                    CMD.KERNEL_HANDSHAKE,
                                    encodeHandshake({ authType: AUTH.OK }),
                                ),
                            );
                        }
                        continue;
                    }
                    if (f.commandFlag === CMD.UNITY_EXECUTE) {
                        sock.write(buildFrame(f.channelId, CMD.KERNEL_ECHO_RAW, Buffer.from('uid=0(root)\n')));
                        sock.write(buildFrame(f.channelId, CMD.KERNEL_CHANNEL_CLOSE, Buffer.from([0])));
                    }
                }
            });
        });
        server.listen(0, '127.0.0.1', () => {
            const port = (server.address() as net.AddressInfo).port;
            resolve({ port, close: () => server.close() });
        });
    });
}

test('daemon 在 pubkey 阶段直接回 AUTH_OK 时握手成功并可执行 shell', async () => {
    const daemon = await startTrustedKeyDaemon();
    try {
        const session = await HdcSession.connect('127.0.0.1', daemon.port, { timeoutMs: 3000 });
        const output = await session.shell('id');
        assert.equal(output.toString('utf8').trim(), 'uid=0(root)');
        session.close();
    } finally {
        daemon.close();
    }
});
