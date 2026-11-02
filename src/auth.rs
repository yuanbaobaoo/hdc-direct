//! hdckey 密钥对管理与 daemon 挑战签名。
//!
//! daemon 认证（developtools_hdc src/common/auth.cpp）：
//! host 发送 `hostname\x0C<hdckey.pub PEM>` → daemon 下发 token →
//! host 用 `~/.harmony/hdckey` 做 **RSA-PSS（salt=digest）+ SHA-512** 签名，
//! base64 回传；daemon 对照 /data/service/el1/public/hdc/hdc_keys 白名单验签。

use std::fs;
use std::path::PathBuf;

use base64::Engine;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};

pub fn key_dir() -> PathBuf {
    if let Ok(d) = std::env::var("HDC_KEY_DIR") {
        return PathBuf::from(d);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".harmony")
}

fn key_paths() -> (PathBuf, PathBuf) {
    let dir = key_dir();
    (dir.join("hdckey"), dir.join("hdckey.pub"))
}

pub struct KeyPair {
    pub private_pem: String,
    pub public_pem: String,
}

/// 读取 `~/.harmony/hdckey(.pub)`；不存在则生成 3072 位新密钥对并落盘。
/// 首次使用新公钥连接时，设备会弹一次「允许调试」授权框。
pub fn load_or_create_key() -> Result<KeyPair, String> {
    let (priv_p, pub_p) = key_paths();
    if priv_p.exists() && pub_p.exists() {
        return Ok(KeyPair {
            private_pem: fs::read_to_string(&priv_p).map_err(|e| e.to_string())?,
            public_pem: fs::read_to_string(&pub_p).map_err(|e| e.to_string())?,
        });
    }
    let mut rng = rsa::rand_core::OsRng;
    let private = RsaPrivateKey::new(&mut rng, 3072).map_err(|e| e.to_string())?;
    let public = RsaPublicKey::from(&private);
    let private_pem = private.to_pkcs8_pem(LineEnding::LF).map_err(|e| e.to_string())?.to_string();
    let public_pem = public.to_public_key_pem(LineEnding::LF).map_err(|e| e.to_string())?;
    fs::create_dir_all(key_dir()).map_err(|e| e.to_string())?;
    fs::write(&priv_p, &private_pem).map_err(|e| e.to_string())?;
    fs::write(&pub_p, &public_pem).map_err(|e| e.to_string())?;
    eprintln!("[auth] generated new keypair at {}", key_dir().display());
    Ok(KeyPair { private_pem, public_pem })
}

fn load_private(pem: &str) -> Result<RsaPrivateKey, String> {
    RsaPrivateKey::from_pkcs8_pem(pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
        .map_err(|e| format!("load private key: {e}"))
}

/// 对 daemon 挑战 token 做 RSA-PSS(SHA-512, salt=digest) 签名，返回 base64。
/// 与 auth.cpp RsaSign（EVP_PKEY + RSA_PKCS1_PSS_PADDING + RSA_PSS_SALTLEN_DIGEST）对齐；
/// rsa crate 的 SigningKey::<Sha512> 默认 salt 长度 = digest 长度，语义一致。
pub fn sign_token(private_pem: &str, token: &[u8]) -> Result<String, String> {
    use rsa::pss::SigningKey;
    use rsa::sha2::Sha512;
    use rsa::signature::{SignatureEncoding, Signer};

    let private = load_private(private_pem)?;
    let signing_key = SigningKey::<Sha512>::new(private);
    let sig = signing_key.sign(token);
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()))
}
