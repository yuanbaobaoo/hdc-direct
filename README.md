# hdc-direct

直连 hdcd 的 HDC 客户端（TypeScript / 零运行时依赖）。不依赖 hdc server / UDS，
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

## 安装与引入

发布资产由 GitHub Release 提供（`v*` tag 触发 CI 构建并上传）：

| 资产 | 说明 |
|---|---|
| `hdc-direct-<version>.tar.gz` | 运行时产物（`dist/src` + package.json + README/LICENSE），解包即可用 |
| `hdc-direct-<version>.tar.gz.sha256` | 校验和 |
| `hdc-direct-<version>.json` | 版本元信息（协议验证版本、入口、运行时要求） |

零运行时依赖，仅需 Node ≥ 18：

```sh
tar -xzf hdc-direct-<version>.tar.gz
node hdc-direct-<version>/dist/src/cli.js -v
```

作为库引用（例如 zcode-ohos 构建期拉取资产后挂到依赖目录）：

```ts
import { HdcSession } from 'hdc-direct';

const s = await HdcSession.connect('127.0.0.1', 46273);
console.log(await s.shellStr('id'));
s.close();
```

## 用法

CLI 命令面与官方 hdc 对齐，可作为 `hdc` 的替代供 devecocli 等工具调用：

```sh
hdc-direct [-t <host:port>] shell "<command>"
hdc-direct [-t <host:port>] file send <local> <remote>
hdc-direct [-t <host:port>] install <local.hap> [--launch <bundle> <ability>]
hdc-direct [-t <host:port>] root            # hdcd 以 root 重启（需 debuggable 设备）
hdc-direct tconn <host:port> [-remove]
hdc-direct list targets [-v]
hdc-direct -v | kill | start | checkserver  # no-op 兼容
hdc-direct [-t <key>] <other command>       # 未知命令按 shell 转发
```

target 记在 `~/.harmony/hdc-direct-targets.json`；无 `-t` 时取第一个已存 target，
为空则自动探测本机端口（`param get persist.hdc.port`，仅设备/沙箱内可用）。
设备本机自连地址为 `127.0.0.1:$(param get persist.hdc.port)`。

### 认证与密钥

- 密钥对在 `~/.harmony/hdckey(.pub)`（或 `$HDC_KEY_DIR`），首次运行自动生成 3072 位 RSA；
- 新公钥首次连接时设备弹一次「允许调试」授权框，允许后写入
  `/data/service/el1/public/hdc/hdc_keys` 白名单，此后免打扰；
- 私钥必须是**无口令 PKCS8 PEM**：带口令的私钥（如 hap_installer 原始私钥）会让
  OpenSSL 抛 `07880109 interrupted or cancelled`，需替换为无口令密钥对；
- 复用已有授权密钥只需把 `hdckey`/`hdckey.pub` 放进该目录。

## 开发

```sh
npm install
npm run typecheck
npm test            # 协议黄金用例（真机抓包字节）
npm run build       # tsc → dist/
npm run pack:release
```

## 协议速查（hdcd 3.2.0f 实测）

帧：`"HW" | reserve(2B)=0 | ver(1B)=1 | headSize(BE16) | dataSize(BE32) | PayloadProtect protobuf | data`
（`dataSize` 不含 protect 头；protect 为 channelId=1 / commandFlag=2 / checkSum=3=0 / vCode=4=9 的 varint 字段）

- **握手**：hello(authType=0, TLV buf) → daemon 索要公钥(3) → 发 `hostname\x0C<hdckey.pub>` →
  daemon 下发 token(2) → **RSA-PSS(SHA-512, salt=digest) 签名 base64** 回传 → AUTH_OK(4) → cid=0 close 01/00
- **shell**：`CMD_UNITY_EXECUTE(1001)`，命令整体包双引号；输出 `ECHO_RAW(10)`；
  结束 close(2)=01，客户端对**同一 cid 连发两次 close(00)**（daemon task 清理依赖第二次）
- **file send**：`WAKEUP_SLAVETASK(12)` 空帧 → `FILE_CHECK(3001)`+TransferConfig →
  `FILE_BEGIN(3002)` → `FILE_DATA(3003)`：TransferPayload(index/compressType/compressSize/uncompressSize)
  序列化后**补零至固定 64B 前缀** + 数据块 → `FILE_FINISH(3004)=01` → 回 00 → ECHO 总结
- **TransferPayload.index 是文件字节偏移而非块序号**（daemon `uv_fs_write(offset=index)`）
- **握手 version 必须非空**（空值触发 "version too low" 拒绝）；与 daemon 版本不一致仅记日志
- **channelId 必须无符号正数**：负值经 varint 截断为低 7 位，响应将无法匹配
- 单块上限 511KB（稳定档 60KB-64）；一命令一短连接（与官方 CLI 一致）

## 版本矩阵

| hdc-direct | hdcd（实测） | 状态 |
|---|---|---|
| 0.1.x / 0.2.x | 3.2.0f（HarmonyOS PC HAD-W32 / OpenHarmony 7.0.0.109） | ✅ 全量验收：30 连发压测、5MB md5 双端一致、install+launch 闭环、zcode-ohos 沙箱内端到端 |

> 协议随系统 hdcd 演进；新版本系统上的回归请按上表补充记录。

## 部署到鸿蒙真机（重要结论）

HarmonyOS 7.0（OpenHarmony 7.0.0.109）对设备侧可执行文件有两层强制管制，均已实测确认：

1. **ELF 执行白名单（hmdfs hmmac）**：沙箱内新写入的 ELF 一律 `EACCES`——
   hdcd file send、网络下载写入、跨文件系统拷贝、应用私有 el2 目录全部无效；
   已有执行许可的文件被写保护（`EPERM`）。只有包管理器部署的文件可执行。
2. **HNP 内 ELF 强制代码签名**：HAP 内嵌 hnp（`hnp/<abi>/*.hnp` + `module.json5`
   的 `hnpPackages`）安装时校验 ELF 的 OHOS 代码签名（hnp 错误 `0x801303`）；
   `binary-sign-tool` 自签、OpenHarmony 调试证书、华为开发者调试证书均缺
   `Binary Cert Extension`，该证书尚未对个人开发者开放——这也是 zcode-ohos
   现有 `electron.hnp` 被暂时禁用的 9568407 的根因。

**因此本项目以 Node 脚本形态部署**：执行沙箱内有许可的宿主 `node` + 本库脚本
（脚本是数据，不受 ELF 管制）。zcode-ohos 内的验证链路（2026-11-02，全程无
HiShell、无人工操作）为：

```
zcode 主进程(develop_tools_debug_hap) → spawn 沙箱内 node
  → node hdc-direct/dist/src/cli.js 127.0.0.1:$(param get persist.hdc.port) ...
  → hdcd TCP → shell / file send / bm install / aa start
```

结果：`install bundle successfully.` + `start ability successfully.`。

## 安全说明

`~/.harmony/hdckey` 私钥等价于该设备的调试授权凭据，请妥善保管；
hdc-direct 以 hdcd 权限（uid=2000 shell）执行命令，能力等同官方 hdc。

## License

Apache-2.0
