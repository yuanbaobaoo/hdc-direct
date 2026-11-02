//! hdc wire protocol: frame header, PayloadProtect / SessionHandShake 的
//! protobuf 子集编码（字段少，手写比引 prost 更轻），TLV。
//!
//! 帧布局（developtools_hdc src/common/session.h PayloadHead，packed，大端）：
//! ```text
//! "HW" | reserve(2B)=0 | protocolVer(1B)=1 | headSize(BE16) | dataSize(BE32)
//!      | PayloadProtect protobuf | data
//! ```
//! `headSize` 是 protect 序列化长度；`dataSize` 只计 data（不含 protect）。

pub const PROTOCOL_VER: u8 = 0x01;
pub const VCODE: u64 = 0x09;
pub const BANNER: &str = "OHOS HDC";
/// 与官方 host 3.2.0e 一致。daemon 校验版本非空（空值触发 "version too low"
/// 拒绝）；不匹配仅记录日志（真机 hdcd 3.2.0f 实测）。
pub const VERSION_STR: &str = "Ver: 3.2.0e7fdbc1aa8c5fefaa";

// commandFlag（define_enum.h）
pub const CMD_KERNEL_HANDSHAKE: u16 = 1;
pub const CMD_KERNEL_CHANNEL_CLOSE: u16 = 2;
pub const CMD_KERNEL_ECHO: u16 = 9;
pub const CMD_KERNEL_ECHO_RAW: u16 = 10;
pub const CMD_KERNEL_WAKEUP_SLAVETASK: u16 = 12; // file 任务前导空帧（抓包实证）
pub const CMD_UNITY_EXECUTE: u16 = 1001;
pub const CMD_UNITY_ROOTRUN: u16 = 1007; // 空 payload 开启 root，"r" 关闭（daemon 侧自检 const.debuggable）
pub const CMD_FILE_CHECK: u16 = 3001;
pub const CMD_FILE_BEGIN: u16 = 3002;
pub const CMD_FILE_DATA: u16 = 3003;
pub const CMD_FILE_FINISH: u16 = 3004;

// SessionHandShake.authType
pub const AUTH_NONE: u64 = 0;
pub const AUTH_SIGNATURE: u64 = 2;
pub const AUTH_PUBLICKEY: u64 = 3;
pub const AUTH_OK: u64 = 4;

/// daemon 侧单块上限（MAX_SIZE_IOBUF 511KB）；用稳定档 60KB-64
pub const BLOCK_SIZE: usize = 60 * 1024 - 64;
/// TransferPayload 序列化占用的固定前缀长度（transfer.h payloadPrefixReserve）
pub const PAYLOAD_PREFIX_RESERVE: usize = 64;

// ---------- varint / protobuf ----------

pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn put_tag(out: &mut Vec<u8>, field: u32, wire: u8) {
    put_varint(out, ((field as u64) << 3) | wire as u64);
}

pub fn pb_varint(out: &mut Vec<u8>, field: u32, v: u64) {
    put_tag(out, field, 0);
    put_varint(out, v);
}

pub fn pb_bytes(out: &mut Vec<u8>, field: u32, b: &[u8]) {
    put_tag(out, field, 2);
    put_varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

pub fn pb_string(out: &mut Vec<u8>, field: u32, s: &str) {
    pb_bytes(out, field, s.as_bytes());
}

/// 轻量 protobuf 解码：仅 varint 与 length-delimited 两种 wire type。
#[derive(Debug)]
pub enum PbValue {
    Varint(u64),
    Bytes(Vec<u8>),
}

pub fn pb_decode(buf: &[u8]) -> Result<Vec<(u32, PbValue)>, String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < buf.len() {
        let (tag, n) = read_varint(buf, i)?;
        i += n;
        let field = (tag >> 3) as u32;
        match tag & 7 {
            0 => {
                let (v, n) = read_varint(buf, i)?;
                i += n;
                out.push((field, PbValue::Varint(v)));
            }
            2 => {
                let (len, n) = read_varint(buf, i)?;
                i += n;
                let len = len as usize;
                if i + len > buf.len() {
                    return Err("length-delimited overflow".into());
                }
                out.push((field, PbValue::Bytes(buf[i..i + len].to_vec())));
                i += len;
            }
            w => return Err(format!("unsupported wire type {w}")),
        }
    }
    Ok(out)
}

fn read_varint(buf: &[u8], mut i: usize) -> Result<(u64, usize), String> {
    let mut v = 0u64;
    let mut shift = 0u32;
    let mut n = 0usize;
    loop {
        if i >= buf.len() {
            return Err("varint truncated".into());
        }
        let b = buf[i];
        i += 1;
        n += 1;
        v |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok((v, n));
        }
        shift += 7;
        if shift >= 64 {
            return Err("varint too long".into());
        }
    }
}

// ---------- 帧 ----------

/// PayloadProtect: channelId=1 commandFlag=2 checkSum=3 vCode=4
pub fn encode_protect(channel_id: u32, command_flag: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(12);
    pb_varint(&mut p, 1, channel_id as u64);
    pb_varint(&mut p, 2, command_flag as u64);
    pb_varint(&mut p, 3, 0); // ENABLE_IO_CHECKSUM=false
    pb_varint(&mut p, 4, VCODE);
    p
}

pub fn build_frame(channel_id: u32, command_flag: u16, data: &[u8]) -> Vec<u8> {
    let protect = encode_protect(channel_id, command_flag);
    let mut out = Vec::with_capacity(11 + protect.len() + data.len());
    out.extend_from_slice(b"HW");
    out.extend_from_slice(&[0, 0]); // reserve
    out.push(PROTOCOL_VER);
    out.extend_from_slice(&(protect.len() as u16).to_be_bytes());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&protect);
    out.extend_from_slice(data);
    out
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub channel_id: u32,
    pub command_flag: u16,
    pub data: Vec<u8>,
}

/// 流式分帧：feed 追加字节，`next_frame` 在凑齐完整帧时弹出。
#[derive(Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    pub fn feed(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    pub fn next_frame(&mut self) -> Result<Option<Frame>, String> {
        if self.buf.len() < 11 {
            return Ok(None);
        }
        if &self.buf[0..2] != b"HW" {
            return Err("frame magic mismatch".into());
        }
        let head_size = u16::from_be_bytes([self.buf[5], self.buf[6]]) as usize;
        let data_size = u32::from_be_bytes(self.buf[7..11].try_into().unwrap()) as usize;
        let total = 11 + head_size + data_size;
        if self.buf.len() < total {
            return Ok(None);
        }
        let protect = self.buf[11..11 + head_size].to_vec();
        let data = self.buf[11 + head_size..total].to_vec();
        self.buf.drain(..total);

        let mut channel_id = 0u32;
        let mut command_flag = 0u16;
        for (f, v) in pb_decode(&protect)? {
            match (f, v) {
                (1, PbValue::Varint(v)) => channel_id = v as u32,
                (2, PbValue::Varint(v)) => command_flag = v as u16,
                _ => {}
            }
        }
        Ok(Some(Frame { channel_id, command_flag, data }))
    }
}

// ---------- SessionHandShake ----------

pub struct Handshake {
    pub auth_type: u64,
    pub buf: Vec<u8>,
    pub version: String,
}

pub fn encode_handshake(
    auth_type: u64,
    session_id: u32,
    connect_key: &str,
    buf: &[u8],
    version: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    pb_string(&mut out, 1, BANNER);
    pb_varint(&mut out, 2, auth_type);
    pb_varint(&mut out, 3, session_id as u64);
    pb_string(&mut out, 4, connect_key);
    pb_bytes(&mut out, 5, buf);
    pb_string(&mut out, 6, version);
    out
}

pub fn parse_handshake(data: &[u8]) -> Result<Handshake, String> {
    let mut hs = Handshake { auth_type: AUTH_NONE, buf: Vec::new(), version: String::new() };
    for (f, v) in pb_decode(data)? {
        match (f, v) {
            (2, PbValue::Varint(v)) => hs.auth_type = v,
            (5, PbValue::Bytes(v)) => hs.buf = v,
            (6, PbValue::Bytes(v)) => hs.version = String::from_utf8_lossy(&v).into_owned(),
            _ => {}
        }
    }
    Ok(hs)
}

// ---------- TLV（base.cpp TlvAppend：tag 16B 定长 + len 16B 定长 + value） ----------

pub fn tlv_append(out: &mut Vec<u8>, tag: &str, val: &str) {
    let mut t = tag.as_bytes().to_vec();
    t.resize(16, b' ');
    out.extend_from_slice(&t);
    let len_str = format!("{}", val.len());
    let mut l = len_str.as_bytes().to_vec();
    l.resize(16, b' ');
    out.extend_from_slice(&l);
    out.extend_from_slice(val.as_bytes());
}
