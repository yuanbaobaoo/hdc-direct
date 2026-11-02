# hdc-direct

直连 hdcd 的 HDC 客户端。跳过 hdc server，用 TCP 直连设备的 hdcd，
在 HAP 沙箱里也能执行 shell、传输文件、安装调试 HAP。

TypeScript 编写，零运行时依赖，只需 Node ≥ 18。

```sh
hdc-direct tconn 127.0.0.1:46273
hdc-direct shell "id"
hdc-direct install app.hap --launch com.example.app EntryAbility
```

## 为什么需要它

官方 hdc 是 `client → UDS server → TCP daemon` 三段式。hdc server 启动时要绑定
UDS，而 HAP 应用（SELinux 域 `develop_tools_debug_hap`）被禁止绑定任何
AF_UNIX socket，server 因此永远起不来：

```
bind uds addr fail! ret:-13
```

结果是所有设备操作都报 `No active devices`，构建和签名能做，安装调试做不了。

设备端的 hdcd 本身监听 TCP 无线调试端口（`persist.hdc.port`），且不限制来源进程。
hdc-direct 跳过 server 层，直接实现 host ↔ daemon 协议：

```
官方:  hdc CLI ──UDS──▶ hdc server ──TCP──▶ hdcd
本库:  hdc-direct ───────────TCP──────────▶ hdcd
```

### 适用场景

- 在鸿蒙 PC 上以 HAP 形式发布的 IDE / 终端里调用设备（zcode-ohos 即此场景）
- 无法启动 hdc server、但能访问本机回环 TCP 的环境
- 需要把 devecocli 等依赖 `hdc` 的工具接到一条可用通道上

### 不适用

- 需要 USB 直连、端口转发、多设备广播发现等 hdc server 侧能力
- 设备未开启无线调试，或 `hdcd` 端口不可达

## 怎么使用

### 安装

从 GitHub Release 下载对应版本，解包即用：

```sh
tar -xzf hdc-direct-<version>.tar.gz
node hdc-direct-<version>/dist/src/cli.js -v
```

也可以作为库引入：

```ts
import { HdcSession } from 'hdc-direct';

const session = await HdcSession.connect('127.0.0.1', 46273);
console.log(await session.shellStr('id'));
session.close();
```

### 命令

```sh
hdc-direct [-t <host:port>] shell "<command>"
hdc-direct [-t <host:port>] file send <local> <remote>
hdc-direct [-t <host:port>] install <local.hap> [--launch <bundle> <ability>]
hdc-direct [-t <host:port>] root
hdc-direct tconn <host:port> [-remove]
hdc-direct list targets [-v]
hdc-direct -v | kill | start | checkserver
hdc-direct [-t <host:port>] <other command>     # 按 shell 转发
```

不传 `-t` 时使用 `~/.harmony/hdc-direct-targets.json` 里的第一个 target；
该文件为空时读取本机 `param get persist.hdc.port` 自动拼出 `127.0.0.1:<port>`。

设备本机自连：

```sh
hdc-direct tconn 127.0.0.1:$(param get persist.hdc.port)
hdc-direct shell "bm dump -n com.example.app | head -3"
hdc-direct install build/entry-default-signed.hap --launch com.example.app EntryAbility
```

### 密钥

首次运行会在 `~/.harmony/` 生成 3072 位密钥对（可用 `HDC_KEY_DIR` 改目录）。
新公钥首次连接时，设备弹一次「允许调试」，允许后被写入 hdcd 白名单，之后不再打扰。

私钥必须是无口令 PKCS8 PEM。带口令的私钥会报
`07880109 interrupted or cancelled`，换成无口令的即可。

```sh
# 复用已有授权密钥
cp <已授权>/hdckey <已授权>/hdckey.pub ~/.harmony/
```

## 怎么开发

```sh
npm install
npm run typecheck       # 类型检查
npm test                # 协议黄金用例（取自真机抓包字节）
npm run build           # tsc → dist/
npm run pack:release    # 生成 dist-release/ 发布资产
```

## License

Apache-2.0
