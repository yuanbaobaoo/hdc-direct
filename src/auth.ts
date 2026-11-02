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

export interface KeyPair {
  privPem: string;
  pubPem: string;
  created?: boolean;
}

export function keyDir(): string {
  if (process.env.HDC_KEY_DIR) return process.env.HDC_KEY_DIR;
  return path.join(process.env.HOME || os.homedir(), '.harmony');
}

export function keyPaths(): { dir: string; priv: string; pub: string } {
  const dir = keyDir();
  return { dir, priv: path.join(dir, 'hdckey'), pub: path.join(dir, 'hdckey.pub') };
}

/**
 * 读取 `~/.harmony/hdckey(.pub)`；不存在则生成 3072 位新密钥对并落盘。
 * 新公钥首次连接时设备弹一次「允许调试」授权，允许后被加入白名单。
 */
export function loadOrCreateKey(): KeyPair {
  const { dir, priv, pub } = keyPaths();
  if (fs.existsSync(priv) && fs.existsSync(pub)) {
    return { privPem: fs.readFileSync(priv, 'utf8'), pubPem: fs.readFileSync(pub, 'utf8') };
  }
  fs.mkdirSync(dir, { recursive: true });
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  // hdckey.pub 为 PEM 文本（公钥串 625B，daemon 按该长度做白名单比对）
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  fs.writeFileSync(priv, privPem, { mode: 0o600 });
  fs.writeFileSync(pub, pubPem, { mode: 0o600 });
  return { privPem, pubPem, created: true };
}

/**
 * 对 daemon 挑战 token 做 RSA-PSS(SHA-512, salt=digest) 签名，返回 base64。
 * 与 auth.cpp `RsaSign`（`RSA_PKCS1_PSS_PADDING` + `RSA_PSS_SALTLEN_DIGEST`）对齐。
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
