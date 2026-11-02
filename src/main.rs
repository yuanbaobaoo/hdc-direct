//! hdc-direct —— 直连 hdcd 的 hdc 客户端（Rust 单二进制）。
//!
//! 背景：OpenHarmony/harmonyOS PC 上官方 hdc 走 client→UDS server→TCP daemon，
//! HAP 沙箱（develop_tools_debug_hap SELinux 域）禁止绑 UDS，server 起不来。
//! 本工具跳过 server，直接说 host↔daemon 的 TCP 协议，使沙箱内也能
//! shell / file send / bm install。

mod auth;
mod proto;
mod session;

use session::HdcSession;

const USAGE: &str = "hdc-direct — talk to on-device hdcd directly over TCP

USAGE:
  hdc-direct <host:port> shell \"<command>\"
  hdc-direct <host:port> file send <local> <remote>
  hdc-direct <host:port> install <local.hap> [--launch <bundle> <ability>]

AUTH:
  keypair at ~/.harmony/hdckey(.pub) (or $HDC_KEY_DIR); auto-generated on
  first run. A new public key triggers a one-time \"allow debugging\" dialog
  on the device.

ENV:
  HDC_KEY_DIR  key directory (default ~/.harmony)";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = run(&args).unwrap_or_else(|e| {
        eprintln!("[error] {e}");
        1
    });
    std::process::exit(code);
}

fn run(args: &[String]) -> Result<i32, String> {
    if args.len() < 2 {
        eprintln!("{USAGE}");
        return Ok(2);
    }
    let target = &args[0];
    let (host, port) = split_target(target)?;

    match args[1].as_str() {
        "shell" => {
            let cmd = args[2..].join(" ");
            let mut s = HdcSession::connect(&host, port)?;
            let out = s.shell(&cmd)?;
            use std::io::Write;
            std::io::stdout().write_all(&out).map_err(|e| e.to_string())?;
            Ok(0)
        }
        "file" => {
            if args.get(2).map(|s| s.as_str()) != Some("send") || args.len() < 5 {
                eprintln!("{USAGE}");
                return Ok(2);
            }
            let mut s = HdcSession::connect(&host, port)?;
            let summary = s.file_send(&args[3], &args[4])?;
            println!("{summary}");
            Ok(0)
        }
        "install" => {
            let hap = args.get(2).ok_or("missing <local.hap>")?.clone();
            let launch = if args.get(3).map(|s| s.as_str()) == Some("--launch") {
                Some((args[4].clone(), args.get(5).cloned().unwrap_or_else(|| "EntryAbility".into())))
            } else {
                None
            };
            let remote = format!("/data/local/tmp/{}", file_name(&hap));
            let mut s = HdcSession::connect(&host, port)?;
            s.file_send(&hap, &remote)?;
            let out = s.shell_str(&format!("bm install -p {remote} -r -d"))?;
            print!("{out}");
            if let Some((bundle, ability)) = launch {
                let out = s.shell_str(&format!("aa start -b {bundle} -a {ability}"))?;
                print!("{out}");
            }
            let _ = s.shell_str(&format!("rm -f {remote}"));
            Ok(0)
        }
        _ => {
            eprintln!("{USAGE}");
            Ok(2)
        }
    }
}

fn split_target(target: &str) -> Result<(String, u16), String> {
    let (h, p) = target
        .rsplit_once(':')
        .ok_or_else(|| format!("target must be host:port, got '{target}'"))?;
    Ok((h.to_string(), p.parse().map_err(|_| "invalid port")?))
}

fn file_name(p: &str) -> String {
    std::path::Path::new(p)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "upload.bin".into())
}
