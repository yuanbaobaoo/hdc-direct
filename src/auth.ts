/**
 * hdckey 密钥对管理与 daemon 挑战签名。
 *
 * daemon 认证（developtools_hdc `src/common/auth.cpp`）：
 * host 发送 `hostname\x0C<hdckey.pub PEM>` → daemon 下发 token →
 * host 用 `~/.harmony/hdckey` 做 **RSA-PSS（salt=digest）+ SHA-512** 签名，
 * base64 回传；daemon 对照 `/data/service/el1/public/hdc/hdc_keys` 白名单验签。
 *
 * 私钥必须是无口令 PKCS8 PEM：带口令的私钥（例如 hap_installer 的原始私钥）
 * 会让 OpenSSL 抛 `07880109 interrupted or cancelled`，需换成无口令密钥对。
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// 生成的 RSA 密钥位数（与 daemon 白名单期望的 625 字节公钥串对应）
const KEY_BITS = 3072;
// 私钥文件权限：仅当前用户可读写
const KEY_FILE_MODE = 0o600;

/**
 * 密钥对内容。
 */
export interface KeyPair {
    // 私钥 PEM（PKCS8，无口令）
    privPem: string;
    // 公钥 PEM（SPKI）
    pubPem: string;
    // 本次是否新生成（新公钥会触发设备端授权弹窗）
    created?: boolean;
}

/**
 * 密钥目录：`$HDC_KEY_DIR` 优先，否则 `~/.harmony`。
 *
 * @returns 目录绝对路径
 */
export function keyDir(): string {
    if (process.env.HDC_KEY_DIR) return process.env.HDC_KEY_DIR;
    return path.join(process.env.HOME || os.homedir(), '.harmony');
}

/**
 * 私钥与公钥的完整路径。
 *
 * @returns 目录与两个文件的路径
 */
export function keyPaths(): { dir: string; priv: string; pub: string } {
    const dir = keyDir();
    return { dir, priv: path.join(dir, 'hdckey'), pub: path.join(dir, 'hdckey.pub') };
}

/**
 * 读取 `~/.harmony/hdckey(.pub)`；不存在则生成 3072 位新密钥对并落盘。
 *
 * 新公钥首次连接时设备弹一次「允许调试」授权，允许后被加入白名单。
 *
 * @returns 密钥对内容
 */
export function loadOrCreateKey(): KeyPair {
    const { dir, priv, pub } = keyPaths();
    if (fs.existsSync(priv) && fs.existsSync(pub)) {
        return { privPem: fs.readFileSync(priv, 'utf8'), pubPem: fs.readFileSync(pub, 'utf8') };
    }
    fs.mkdirSync(dir, { recursive: true });
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: KEY_BITS });
    const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    // hdckey.pub 为 PEM 文本（公钥串 625B，daemon 按该长度做白名单比对）
    const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    fs.writeFileSync(priv, privPem, { mode: KEY_FILE_MODE });
    fs.writeFileSync(pub, pubPem, { mode: KEY_FILE_MODE });
    return { privPem, pubPem, created: true };
}

/**
 * 对 daemon 挑战 token 做 RSA-PSS(SHA-512, salt=digest) 签名，返回 base64。
 *
 * 与 auth.cpp `RsaSign`（`RSA_PKCS1_PSS_PADDING` + `RSA_PSS_SALTLEN_DIGEST`）对齐。
 *
 * @param privPem 私钥 PEM
 * @param token daemon 下发的挑战字节
 * @returns base64 签名
 */
export function signToken(privPem: string, token: Buffer): string {
    return crypto
        .sign('sha512', token, {
            key: crypto.createPrivateKey(privPem),
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
        })
        .toString('base64');
}
