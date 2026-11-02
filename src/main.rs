//! hdc-direct —— 直连 hdcd 的 hdc 客户端（Rust 单二进制）。
//!
//! CLI 与官方 hdc 兼容（对齐 js/hdc-direct.mjs + js/hdc-wrapper.mjs 的完整命令面）：
//!   hdc-direct [-t <key>] shell "<command>"
//!   hdc-direct [-t <key>] file send <local> <remote>
//!   hdc-direct [-t <key>] install <local.hap> [--launch <bundle> <ability>]
//!   hdc-direct [-t <key>] root          # 请求 hdcd 以 root 重启（需 debuggable 设备）
//!   hdc-direct tconn <host:port> [-remove]
//!   hdc-direct list targets [-v]
//!   hdc-direct -v | kill | start | checkserver    # no-op 兼容
//!   hdc-direct [-t <key>] <其它命令>              # 按 shell 命令转发
//!
//! 无 `-t` 时使用默认 target：`~/.harmony/hdc-direct-targets.json` 中第一个；
//! 为空时自动探测本机无线调试端口（`param get persist.hdc.port`）。

mod auth;
mod proto;
mod session;

use std::io::Write as _;
use std::path::PathBuf;

use session::HdcSession;

const VERSION_OUT: &str = "Ver: 3.2.0e-direct (hdc-direct tcp mode)";
const USAGE: &str = "hdc-direct — talk to on-device hdcd directly over TCP

USAGE:
  hdc-direct [-t <host:port>] shell \"<command>\"
  hdc-direct [-t <host:port>] file send <local> <remote>
  hdc-direct [-t <host:port>] install <local.hap> [--launch <bundle> <ability>]
  hdc-direct [-t <host:port>] root
  hdc-direct tconn <host:port> [-remove]
  hdc-direct list targets [-v]
  hdc-direct -v | kill | start | checkserver
  hdc-direct [-t <host:port>] <other command>   (forwarded as shell)

AUTH:
  keypair at ~/.harmony/hdckey(.pub) (or $HDC_KEY_DIR); auto-generated on
  first run. A new public key triggers a one-time \"allow debugging\" dialog
  on the device. Keys with passphrase are not supported — replace with an
  unencrypted PKCS8 PEM.

ENV:
  HDC_KEY_DIR         key directory (default ~/.harmony)
  HDC_SHELL_TIMEOUT   shell command timeout ms (default 60000)";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = run(&args).unwrap_or_else(|e| {
        eprintln!("[error] {e}");
        1
    });
    std::process::exit(code);
}

// ---------- targets 状态（与 js/hdc-wrapper.mjs 共用同一文件） ----------

fn state_file() -> PathBuf {
    let dir = std::env::var("HDC_KEY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".harmony")
        });
    dir.join("hdc-direct-targets.json")
}

fn load_targets() -> Vec<String> {
    let Ok(s) = std::fs::read_to_string(state_file()) else { return Vec::new() };
    // 极简 JSON 字符串数组解析（元素均为 host:port，无转义）
    s.split('"')
        .filter(|p| p.contains(':') && !p.trim_start().starts_with('['))
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

fn save_targets(list: &[String]) {
    let items: Vec<String> = list.iter().map(|s| format!("  \"{s}\"")).collect();
    let json = format!("[\n{}\n]\n", items.join(",\n"));
    let f = state_file();
    if let Some(dir) = f.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(f, json);
}

/// 探测本机无线调试端口（真机/沙箱内 param 命令可直接执行）
fn local_hdc_port() -> Option<u16> {
    let out = std::process::Command::new("param")
        .args(["get", "persist.hdc.port"])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    s.split(|c: char| !c.is_ascii_digit()).find(|p| !p.is_empty())?.parse().ok()
}

fn default_target() -> Option<String> {
    let saved = load_targets();
    if !saved.is_empty() {
        return Some(saved[0].clone());
    }
    local_hdc_port().map(|p| format!("127.0.0.1:{p}"))
}

fn split_target(key: &str) -> Result<(String, u16), String> {
    let (h, p) = key
        .rsplit_once(':')
        .ok_or_else(|| format!("target must be host:port, got '{key}'"))?;
    Ok((h.to_string(), p.parse().map_err(|_| "invalid port")?))
}

fn connect(key: &str) -> Result<HdcSession, String> {
    let (host, port) = split_target(key)?;
    HdcSession::connect(&host, port)
}

// ---------- CLI ----------

fn run(argv: &[String]) -> Result<i32, String> {
    // 全局选项解析：-t <key>、-l <level>（忽略）；-v 仅作为首参数表示版本
    let mut key: Option<String> = None;
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < argv.len() {
        let a = &argv[i];
        if a == "-t" {
            key = argv.get(i + 1).cloned();
            if key.is_none() {
                return Err("-t requires <host:port>".into());
            }
            i += 2;
        } else if a == "-l" {
            i += 2; // 日志级别，忽略
        } else if (a == "-v" || a == "--version") && i == 0 && argv.len() == 1 {
            println!("{VERSION_OUT}");
            return Ok(0);
        } else {
            rest.push(a.clone());
            i += 1;
        }
    }
    let Some(cmd) = rest.first().cloned() else {
        eprintln!("{USAGE}");
        return Ok(2);
    };
    let args: Vec<String> = rest[1..].to_vec();

    match cmd.as_str() {
        "help" => {
            println!("{USAGE}");
            Ok(0)
        }
        // 无 server 概念，恒成功（与官方 CLI 对齐）
        "kill" | "start" | "checkserver" => Ok(0),
        "tconn" => cmd_tconn(&args),
        "list" => cmd_list(&args),
        "shell" => {
            let target = resolve_target(&key)?;
            let mut s = connect(&target)?;
            let out = s.shell(&args.join(" "))?;
            std::io::stdout().write_all(&out).map_err(|e| e.to_string())?;
            Ok(0)
        }
        "file" => {
            if args.first().map(String::as_str) != Some("send") || args.len() < 3 {
                eprintln!("{USAGE}");
                return Ok(2);
            }
            let target = resolve_target(&key)?;
            let mut s = connect(&target)?;
            let summary = s.file_send(&args[1], &args[2])?;
            println!("{summary}");
            Ok(0)
        }
        "install" => {
            let hap = args.first().ok_or("missing <local.hap>")?.clone();
            let launch = if args.get(1).map(String::as_str) == Some("--launch") {
                Some((
                    args.get(2).cloned().ok_or("missing bundle")?,
                    args.get(3).cloned().unwrap_or_else(|| "EntryAbility".into()),
                ))
            } else {
                None
            };
            let remote = format!("/data/local/tmp/{}", file_name(&hap));
            let target = resolve_target(&key)?;
            let mut s = connect(&target)?;
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
        "root" => {
            let target = resolve_target(&key)?;
            let mut s = connect(&target)?;
            let resp = s.request_root_restart_raw()?;
            println!("{}", String::from_utf8_lossy(&resp).trim());
            eprintln!("[root] restart requested; reconnect in a few seconds");
            Ok(0)
        }
        // 未知子命令按 shell 命令转发（官方 hdc 对 shell 的宽松行为）
        _ => {
            let target = resolve_target(&key)?;
            let mut s = connect(&target)?;
            let out = s.shell(&rest.join(" "))?;
            std::io::stdout().write_all(&out).map_err(|e| e.to_string())?;
            Ok(0)
        }
    }
}

fn resolve_target(key: &Option<String>) -> Result<String, String> {
    if let Some(k) = key {
        return Ok(k.clone());
    }
    default_target().ok_or_else(|| "no target; run `hdc-direct tconn <host:port>` first".into())
}

fn cmd_tconn(args: &[String]) -> Result<i32, String> {
    let target = args.iter().find(|a| !a.starts_with('-')).cloned().ok_or("tconn requires <host:port>")?;
    let mut list = load_targets();
    if args.iter().any(|a| a == "-remove") {
        list.retain(|x| x != &target);
        save_targets(&list);
        println!("Disconnected {target}");
        return Ok(0);
    }
    let mut s = connect(&target).map_err(|e| format!("Connect {target} failed: {e}"))?;
    s.request_close();
    if !list.contains(&target) {
        list.push(target.clone());
    }
    save_targets(&list);
    println!("Connect OK");
    Ok(0)
}

fn cmd_list(args: &[String]) -> Result<i32, String> {
    if args.first().map(String::as_str) != Some("targets") {
        eprintln!("[error] only `list targets` supported");
        return Ok(1);
    }
    let verbose = args.iter().any(|a| a == "-v");
    let mut list = load_targets();
    let target = default_target();
    if let Some(t) = &target {
        if !list.contains(t) {
            list.push(t.clone());
        }
    }
    for k in &list {
        if verbose {
            println!("{k}\tConnected\thdc-direct");
        } else {
            println!("{k}");
        }
    }
    Ok(0)
}

fn file_name(p: &str) -> String {
    std::path::Path::new(p)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "upload.bin".into())
}
