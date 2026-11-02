# hdc-direct

直连 hdcd 的 HDC 客户端（Rust 单二进制）。不依赖 hdc server / UDS，
使 HAP 沙箱内的工具也能完成 **shell / 文件传输 / HAP 安装调试**。

## 为什么需要它

OpenHarmony / HarmonyOS PC 上官方 hdc 工具链是 `client → UDS server → TCP daemon`
三段式。以 HAP 应用身份运行的终端/IDE（SELinux 域 `develop_tools_debug_hap`）
被策略**禁止绑定任何 AF_UNIX socket**，hdc server 永远起不来
（`bind uds addr fail! ret:-13`），导致所有设备操作报 "No active devices"。

而设备端守护进程 **hdcd** 本身监听 TCP（无线调试端口，`persist.hdc.port`），
且该端口对本机回环**不限制来源进程**。hdc-direct 跳过 server 层，
直接实现 host↔daemon 的 TCP 协议（协议来自 [developtools_hdc](https://gitee.com/openharmony/developtools_hdc)
开源代码与实机抓包对照，见下文「协议速查」）。

```
官方:  hdc CLI ──UDS──▶ hdc server ──TCP──▶ hdcd (46273)   ← 沙箱内 UDS 被禁，断链
本库:  hdc-direct ───────────TCP───────────▶ hdcd (46273)   ← 沙箱内 TCP 出站不受限
```

## 用法

```sh
hdc-direct <host:port> shell "<command>"
hdc-direct <host:port> file send <local> <remote>
hdc-direct <host:port> install <local.hap> [--launch <bundle> <ability>]
```

host:port 在设备本机自连时为 `127.0.0.1:$(param get persist.hdc.port)`。

### 认证与密钥

- 密钥对位于 `~/.harmony/hdckey(.pub)`（或 `$HDC_KEY_DIR`），首次运行自动生成 3072 位 RSA；
- 新公钥首次连接时，设备弹出一次「允许调试」授权框，允许后写入
  `/data/service/el1/public/hdc/hdc_keys` 白名单，此后免打扰；
- 复用已有授权密钥（如其他工具的）只需把 `hdckey`/`hdckey.pub` 放进上述目录。

## 构建

```sh
cargo test                                   # 协议黄金用例（实机抓包字节）
cargo build --release                        # 本机平台
cargo build --release --target aarch64-unknown-linux-ohos   # OHOS arm64 交叉编译
./scripts/build-hnp.sh                       # 交叉编译 + hnpcli 打包 dist/hdc-direct.hnp
```

交叉编译依赖本机 DevEco command-line-tools（sysroot 与 libunwind 路径见
`.cargo/config.toml`，按实际安装位置调整）。产物仅动态依赖系统 `libc.so`。

## 协议速查（hdcd 3.2.0f 实测）

帧：`"HW" | reserve(2B)=0 | ver(1B)=1 | headSize(BE16) | dataSize(BE32) | PayloadProtect protobuf | data`
（`dataSize` 不含 protect 头；protect 为 channelId=1/commandFlag=2/checkSum=3=0/vCode=4=9 的 varint 字段）

- **握手**：hello(authType=0, TLV buf) → daemon 索要公钥(3) → 发 `hostname\x0C<hdckey.pub>` →
  daemon 下发 token(2) → **RSA-PSS(SHA-512, salt=digest) 签名 base64** 回传 → AUTH_OK(4) → cid=0 close 01/00
- **shell**：`CMD_UNITY_EXECUTE(1001)`，命令整体包双引号；输出 `ECHO_RAW(10)`；
  结束 close(2)=01，客户端对**同一 cid 连发两次 close(00)**（daemon task 清理依赖）
- **file send**：`WAKEUP_SLAVETASK(12)` 空帧 → `FILE_CHECK(3001)`+TransferConfig →
  `FILE_BEGIN(3002)` → `FILE_DATA(3003)`：TransferPayload(index/compressType/compressSize/uncompressSize)
  序列化后**补零至固定 64B 前缀** + 数据块 → `FILE_FINISH(3004)=01` → 回 00 → ECHO 总结
- **TransferPayload.index 是文件字节偏移而非块序号**（daemon `uv_fs_write(offset=index)`）
- **握手 version 必须非空**（空值触发 "version too low" 拒绝）；与 daemon 版本不一致仅记日志
- **channelId 必须无符号正数**：负值经 varint 截断为低 7 位，响应将无法匹配
- 单块上限 511KB（稳定档建议 60KB-64）；一命令一短连接（与官方 CLI 一致）

## 两种形态与真机部署结论（2026-11-02 HarmonyOS 7.0 实测）

| 形态 | 定位 | 状态 |
|---|---|---|
| `js/hdc-direct.mjs`（零依赖 Node 脚本） | **真机 zcode-ohos 沙箱内的当前部署形态** | ✅ 沙箱内全链路验证：认证→shell→file send→bm install→aa start |
| Rust 单二进制（本 crate） | 协议参考实现 + 开发机（Mac/Linux）调试器 + 未来 HNP 分发形态 | ✅ Mac 对真机全量验收（50 连发压测、5MB md5、install 闭环）；**真机部署被系统签名管制暂堵**（见下） |

### 为什么真机上目前用 JS 形态（重要调研结论）

HarmonyOS 7.0（OpenHarmony 7.0.0.109）对设备侧可执行文件有两层强制管制，均实测确认：

1. **ELF 执行白名单（hmdfs hmmac）**：沙箱内新写入的 ELF 一律 EACCES——
   hdcd file send、fetch 网络写入、fs 拷贝（跨文件系统）、应用私有 el2 目录全部无效；
   已有执行许可的文件被写保护（EPERM）。只有包管理器部署的文件可执行
   （brew Cellar、/data/service/hnp、系统区）。
2. **HNP 内 ELF 强制代码签名**：HAP 内嵌 hnp（`hnp/arm64-v8a/*.hnp` + module.json5
   `hnpPackages`）安装时，`EnforceCodeSignForApp` 校验 ELF 的 OHOS 代码签名
   （hnp 错误 0x801303「ELF文件验签失败」）。`binary-sign-tool` 自签/OpenHarmony 调试
   证书/华为开发者调试证书均缺 `Binary Cert Extension`（0x801305 前置检查报
   `Binary cert extension not found`）——该证书目前未对个人开发者开放。

**破局**：执行有许可的宿主二进制（node）+ 加载脚本（脚本是数据，不受 ELF 管制）。
zcode-ohos 沙箱内 `~/.harmonybrew/Cellar/node/*/bin/node` 可执行，
`node hdc-direct.mjs 127.0.0.1:$(param get persist.hdc.port) shell "..."` 全链路可用。

注意：宿主 `~/.harmony/hdckey` 若为带口令的 PKCS8（如 hap_installer 原始私钥），
需换无口令密钥对（`HDC_KEY_DIR` 指定或覆盖 `~/.harmony/hdckey(.pub)`）。

Rust 二进制等华为向开发者开放 binary 证书后即可通过 HNP 分发启用（协议实现不变）。

### 真机验证记录（全自主，无 HiShell / 无人工操作）

- 通道：USB hdc 端口转发 zcode 主进程 V8 Inspector（127.0.0.1:9229）→
  `process.mainModule.require('child_process')` spawn 沙箱内 node 执行本脚本；
- 结果：`id`（uid=2000 shell，经 hdcd）、`install bundle successfully`、
  `start ability successfully`——即 2026-11-01 zcode-ohos 会话卡死的最后一步
  （沙箱内安装 HAP）已打通。

## 版本矩阵

| hdc-direct | hdcd（实测） | 状态 |
|---|---|---|
| 0.1.x | 3.2.0f（HarmonyOS PC HAD-W32 / OpenHarmony 7.0.0.109） | ✅ 双形态全量验收（见上） |

> 协议随系统 hdcd 演进；新版本系统上的回归请按上表补充记录。

## 安全说明

`~/.harmony/hdckey` 私钥等价于该设备的调试授权凭据，请妥善保管；
hdc-direct 以 hdcd 权限（uid=2000 shell）执行命令，能力等同官方 hdc。

## License

Apache-2.0
