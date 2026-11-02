//! TCP 直连 hdcd 的会话：握手认证 + shell + file send。
//!
//! 生命周期约定（与官方 hdc CLI 一致，一命令一短连接）：
//! hello → daemon 索要公钥 → 提交 hostname\x0C 公钥 → daemon 下发 token →
//! RSA-PSS 签名回传 → AUTH_OK → cid=0 close 01/00 交互 → 业务 task。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::auth;
use crate::proto::*;

pub struct HdcSession {
    stream: TcpStream,
    reader: FrameReader,
    session_id: u32,
}

/// 简易 LCG：channelId 必须是无符号正数（负值会被 varint 截断为低 7 位，
/// 导致响应与本地记录不匹配——JS PoC 阶段 ~50% “偶发超时”的根因）。
fn rand_u32() -> u32 {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e3779b9);
    let x = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    ((x >> 33) as u32 & 0x7fff_ffff).max(1)
}

impl HdcSession {
    pub fn connect(host: &str, port: u16) -> Result<HdcSession, String> {
        let addr = format!("{host}:{port}");
        let stream = TcpStream::connect(&addr).map_err(|e| format!("connect {addr}: {e}"))?;
        stream.set_nodelay(true).ok();
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .map_err(|e| e.to_string())?;
        let mut s = HdcSession { stream, reader: FrameReader::default(), session_id: rand_u32() };

        let key = auth::load_or_create_key()?;

        // 1) hello：version 必须非空；supportfeatures 不声明 heartbeat（声明后
        //    daemon 开启心跳校验，host 需每 5s 发 CMD_HEARTBEAT_MSG）
        let mut hello_buf = Vec::new();
        tlv_append(&mut hello_buf, "authtype", "1");
        tlv_append(&mut hello_buf, "supportfeatures", "Ver: 3.2.0e,TCP,mac");
        s.send_raw(&build_frame(
            0,
            CMD_KERNEL_HANDSHAKE,
            &encode_handshake(AUTH_NONE, s.session_id, &addr, &hello_buf, VERSION_STR),
        ))?;

        let f = s.wait_frame(0, None)?;
        let hs = parse_handshake(&f.data)?;
        if hs.auth_type != AUTH_PUBLICKEY {
            return Err(format!("expect AUTH_PUBLICKEY, got {}", hs.auth_type));
        }

        // 2) 提交 hostname \x0C 公钥
        let hostname = hostname_str();
        let mut payload = hostname.into_bytes();
        payload.push(0x0C);
        payload.extend_from_slice(key.public_pem.as_bytes());
        s.send_raw(&build_frame(
            0,
            CMD_KERNEL_HANDSHAKE,
            &encode_handshake(AUTH_PUBLICKEY, 0, "", &payload, VERSION_STR),
        ))?;

        let f = s.wait_frame(0, None)?;
        let hs = parse_handshake(&f.data)?;
        if hs.auth_type != AUTH_SIGNATURE {
            return Err(format!("expect AUTH_SIGNATURE, got {}", hs.auth_type));
        }

        // 3) RSA-PSS(SHA-512) 签名回传
        let sig = auth::sign_token(&key.private_pem, &hs.buf)?;
        s.send_raw(&build_frame(
            0,
            CMD_KERNEL_HANDSHAKE,
            &encode_handshake(AUTH_SIGNATURE, 0, "", sig.as_bytes(), VERSION_STR),
        ))?;

        let f = s.wait_frame(0, None)?;
        let hs = parse_handshake(&f.data)?;
        if hs.auth_type != AUTH_OK {
            let msg = String::from_utf8_lossy(&hs.buf);
            return Err(format!("auth failed (type={}): {}", hs.auth_type, &msg[..msg.len().min(200)]));
        }

        // 4) daemon 发 cid=0 CHANNEL_CLOSE data=01，回 data=00（抓包行为）
        let f = s.wait_frame(0, Some(CMD_KERNEL_CHANNEL_CLOSE))?;
        let _ = f;
        s.send_raw(&build_frame(0, CMD_KERNEL_CHANNEL_CLOSE, &[0]))?;
        Ok(s)
    }

    fn send_raw(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.stream.write_all(bytes).map_err(|e| e.to_string())
    }

    /// 等待下一帧；`want_flag` 过滤 commandFlag，`channel` 过滤 channelId（None 仅对握手期 cid=0）。
    fn wait_frame(&mut self, channel: u32, want_flag: Option<u16>) -> Result<Frame, String> {
        loop {
            if let Some(f) = self.reader.next_frame()? {
                if f.channel_id == channel && want_flag.map_or(true, |w| f.command_flag == w) {
                    return Ok(f);
                }
                // 其他 channel 的帧（如 jdwp 推送 cid=0）丢弃
                continue;
            }
            let mut chunk = [0u8; 64 * 1024];
            let n = self.stream.read(&mut chunk).map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("connection closed by daemon".into());
            }
            self.reader.feed(&chunk[..n]);
        }
    }

    /// 执行一条 shell 命令并收集输出。官方客户端把整条命令包在双引号内。
    pub fn shell(&mut self, cmd: &str) -> Result<Vec<u8>, String> {
        let channel = rand_u32();
        let quoted = format!("\"{cmd}\"");
        self.send_raw(&build_frame(channel, CMD_UNITY_EXECUTE, quoted.as_bytes()))?;
        let mut out = Vec::new();
        loop {
            let f = self.wait_frame(channel, None)?;
            match f.command_flag {
                CMD_KERNEL_ECHO_RAW | CMD_KERNEL_ECHO => out.extend_from_slice(&f.data),
                CMD_KERNEL_CHANNEL_CLOSE => {
                    // 官方对同一 channelId 连发两次 close(00)（抓包实证），
                    // daemon 的 task 清理依赖第二次 close
                    self.send_raw(&build_frame(channel, CMD_KERNEL_CHANNEL_CLOSE, &[0]))?;
                    self.send_raw(&build_frame(channel, CMD_KERNEL_CHANNEL_CLOSE, &[0]))?;
                    return Ok(out);
                }
                _ => {}
            }
        }
    }

    /// 上传本地文件到设备路径。返回 daemon 的总结消息。
    pub fn file_send(&mut self, local: &str, remote: &str) -> Result<String, String> {
        let data = std::fs::read(local).map_err(|e| format!("read {local}: {e}"))?;
        let name = std::path::Path::new(local)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let channel = rand_u32();

        // 1) 前导空帧（WAKEUP_SLAVETASK，抓包实证）
        self.send_raw(&build_frame(channel, CMD_KERNEL_WAKEUP_SLAVETASK, &[]))?;

        // 2) FILE_CHECK + TransferConfig
        let mut cfg = Vec::new();
        pb_varint(&mut cfg, 1, data.len() as u64); // fileSize
        pb_varint(&mut cfg, 2, 0); // atime
        pb_varint(&mut cfg, 3, 0); // mtime
        pb_string(&mut cfg, 4, ""); // options
        pb_string(&mut cfg, 5, remote); // path（远端）
        pb_string(&mut cfg, 6, &name); // optionalName
        pb_varint(&mut cfg, 7, 0); // updateIfNew
        pb_varint(&mut cfg, 8, 0); // compressType=NONE
        pb_varint(&mut cfg, 9, 0); // holdTimestamp
        pb_string(&mut cfg, 10, ""); // functionName
        let cwd = std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        pb_string(&mut cfg, 11, &cwd); // clientCwd
        pb_string(&mut cfg, 12, "");
        pb_string(&mut cfg, 13, "");
        self.send_raw(&build_frame(channel, CMD_FILE_CHECK, &cfg))?;

        // 3) 等 FILE_BEGIN
        self.wait_frame(channel, Some(CMD_FILE_BEGIN))?;

        // 4) 分块 FILE_DATA。TransferPayload(index=字节偏移, compressType=0,
        //    compressSize=n, uncompressSize=n) 序列化后补零到固定 64B 前缀。
        //    index 是文件偏移而非块序号：daemon 侧 uv_fs_write(..., offset=index)。
        let mut offset = 0usize;
        for chunk in data.chunks(BLOCK_SIZE) {
            let mut pld = Vec::new();
            pb_varint(&mut pld, 1, offset as u64);
            pb_varint(&mut pld, 2, 0);
            pb_varint(&mut pld, 3, chunk.len() as u64);
            pb_varint(&mut pld, 4, chunk.len() as u64);
            let mut frame_data = Vec::with_capacity(PAYLOAD_PREFIX_RESERVE + chunk.len());
            frame_data.extend_from_slice(&pld);
            frame_data.resize(PAYLOAD_PREFIX_RESERVE, 0);
            frame_data.extend_from_slice(chunk);
            self.send_raw(&build_frame(channel, CMD_FILE_DATA, &frame_data))?;
            offset += chunk.len();
        }

        // 5) 等 FINISH=01，回 00；收 ECHO 总结与 close
        let fin = self.wait_frame(channel, Some(CMD_FILE_FINISH))?;
        let ok = fin.data.first() == Some(&1);
        self.send_raw(&build_frame(channel, CMD_FILE_FINISH, &[0]))?;
        let summary = self
            .wait_frame(channel, Some(CMD_KERNEL_ECHO))
            .map(|f| String::from_utf8_lossy(&f.data).into_owned())
            .unwrap_or_default();
        let _ = self.wait_frame(channel, Some(CMD_KERNEL_CHANNEL_CLOSE));
        self.send_raw(&build_frame(channel, CMD_KERNEL_CHANNEL_CLOSE, &[0]))?;
        self.send_raw(&build_frame(channel, CMD_KERNEL_CHANNEL_CLOSE, &[0]))?;
        if !ok {
            return Err(format!("file transfer failed: {summary}"));
        }
        Ok(summary)
    }

    pub fn shell_str(&mut self, cmd: &str) -> Result<String, String> {
        let out = self.shell(cmd)?;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }
}

fn hostname_str() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "hdc-direct".into())
}
