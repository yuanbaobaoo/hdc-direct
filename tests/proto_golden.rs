//! 协议黄金用例：全部取自 2026-11-02 与真机 hdcd 3.2.0f 的实机抓包
//! （对照官方 hdc 3.2.0e 客户端流量）。改编码器必须保这些字节不变。

use hdc_direct::proto::*;

fn hex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    clean.as_bytes().chunks(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap()).collect()
}

#[test]
fn protect_encoding_matches_capture() {
    // 抓包：握手帧 protect = 08 00 10 01 18 00 20 09（cid=0, flag=1）
    assert_eq!(encode_protect(0, CMD_KERNEL_HANDSHAKE), hex("0800100118002009"));
    // 抓包：shell 数据帧 protect，cid=varint(0x...)，flag=1001(0xe907)
    assert_eq!(
        encode_protect(0x3e, CMD_UNITY_EXECUTE),
        hex("083e10e90718002009")
    );
}

#[test]
fn frame_header_matches_capture() {
    // 抓包 44B shell 帧："echo PROTOCOL_TEST"（20B 数据，含引号）
    let data = b"\"echo PROTOCOL_TEST\"";
    let frame = build_frame(0x33ccf4a7, CMD_UNITY_EXECUTE, data);
    // 帧头：HW + reserve + ver=1 + headSize(13=0x0d) + dataSize(20=0x14)
    assert_eq!(&frame[0..2], b"HW");
    assert_eq!(frame[4], 0x01);
    assert_eq!(&frame[5..7], &0x000d_u16.to_be_bytes());
    assert_eq!(&frame[7..11], &(data.len() as u32).to_be_bytes());
    assert_eq!(frame.len(), 11 + 13 + data.len());
}

#[test]
fn frame_reader_roundtrip_and_split() {
    let f1 = build_frame(7, CMD_KERNEL_ECHO_RAW, b"hello");
    let f2 = build_frame(0x7fffffff, CMD_FILE_DATA, &[0xAB; 300]);
    let mut r = FrameReader::default();
    // 半包喂入
    r.feed(&f1[..5]);
    assert!(r.next_frame().unwrap().is_none());
    r.feed(&f1[5..]);
    let got = r.next_frame().unwrap().unwrap();
    assert_eq!(got.channel_id, 7);
    assert_eq!(got.command_flag, CMD_KERNEL_ECHO_RAW);
    assert_eq!(got.data, b"hello");
    // 粘包：两帧一次喂入
    let mut both = f1.clone();
    both.extend_from_slice(&f2);
    r.feed(&both);
    let a = r.next_frame().unwrap().unwrap();
    let b = r.next_frame().unwrap().unwrap();
    assert_eq!(a.channel_id, 7);
    assert_eq!(b.channel_id, 0x7fffffff);
    assert_eq!(b.data.len(), 300);
}

#[test]
fn handshake_encode_matches_capture_prefix() {
    // 抓包 hello 帧前缀（167B 帧的 data 开头）：
    // 0a 08 "OHOS HDC" 10 00 18 <sessionId> 22 0f "127.0.0.1:46300" ...
    let mut buf = Vec::new();
    tlv_append(&mut buf, "authtype", "1");
    tlv_append(&mut buf, "supportfeatures", "Ver: 3.2.0e,TCP,mac,heartbeat");
    let hs = encode_handshake(AUTH_NONE, 0x4F2F, "127.0.0.1:46300", &buf, VERSION_STR);
    assert!(hs.starts_with(&hex("0a084f484f5320484443100018")));
    // version 字段（field 6）必须非空且以官方串开头
    assert!(hs.windows(VERSION_STR.len()).any(|w| w == VERSION_STR.as_bytes()));
}

#[test]
fn handshake_parse_roundtrip() {
    let mut buf = Vec::new();
    tlv_append(&mut buf, "authtype", "1");
    let hs = encode_handshake(AUTH_SIGNATURE, 42, "k", &buf, "Ver: 9.9.9x");
    let parsed = parse_handshake(&hs).unwrap();
    assert_eq!(parsed.auth_type, AUTH_SIGNATURE);
    assert_eq!(parsed.version, "Ver: 9.9.9x");
    assert!(parsed.buf.windows(8).any(|w| w == b"authtype"));
}

#[test]
fn tlv_format_is_fixed_width() {
    // base.cpp TlvAppend：tag 16B 定长 + len 16B 定长 + value
    let mut out = Vec::new();
    tlv_append(&mut out, "authtype", "1");
    assert_eq!(out.len(), 33); // 16 + 16 + 1
    assert_eq!(&out[..16], b"authtype        ");
    assert_eq!(&out[16..32], b"1               ");
    assert_eq!(&out[32..], b"1");
}

#[test]
fn varint_encoding_edge_cases() {
    // channelId 必须无符号：0x7fffffff（最大正 cid）编码 5 字节
    let mut v = Vec::new();
    put_varint(&mut v, 0x7fffffff);
    assert_eq!(v, vec![0xFF, 0xFF, 0xFF, 0xFF, 0x07]);
    let mut v = Vec::new();
    put_varint(&mut v, 1);
    assert_eq!(v, vec![0x01]);
}

#[test]
fn file_payload_prefix_is_64_bytes() {
    // TransferPayload 序列化 + 补零 = 固定 64B 前缀（transfer.h payloadPrefixReserve）。
    // 抓包对照：20B 文件单块时 index=0、compressSize=uncompressSize=20。
    let mut pld = Vec::new();
    pb_varint(&mut pld, 1, 0); // index = 字节偏移
    pb_varint(&mut pld, 2, 0); // compressType = NONE
    pb_varint(&mut pld, 3, 20);
    pb_varint(&mut pld, 4, 20);
    let mut frame_data = pld.clone();
    frame_data.resize(PAYLOAD_PREFIX_RESERVE, 0);
    assert_eq!(frame_data.len(), 64);
    assert_eq!(&frame_data[..8], &hex("0800100018142014")[..]);
}
