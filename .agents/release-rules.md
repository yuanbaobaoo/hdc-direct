# hdc-direct 发版规则（Release Rule）

> 面向后续 AI 会话与维护者的发版操作规范。参考 ZCode-ohos 的
> `.ai-context/release-rules.md`，结合本项目（Node 库 + CLI，零运行时依赖）的实际产物。
>
> 原则：**发版是 CI 的事，本地只负责门禁 + commit + tag**，不在本地构建发布产物。

## 触发机制（唯一通道）

push 匹配 `v*` 的 tag → [`.github/workflows/release.yml`](../.github/workflows/release.yml)
自动执行「类型检查 → 测试 → 打包 → 校验资产 → 发布 GitHub Release」。

- `workflow_dispatch` 手动触发只跑构建并上传 Actions Artifact，**不会**发 Release，
  仅用于流程验证。
- Release 由 CI 用 `permissions: contents: write` + softprops/action-gh-release 创建，
  本地凭证不参与发布。

## 版本与 tag

- 版本号以 `package.json` 的 `version` 为唯一事实来源（semver）。
- tag 格式固定为 `v<version>`，必须与 `package.json` **完全一致**；
  CI 会校验，不一致直接失败。例：`package.json` 为 `0.2.0` → tag `v0.2.0`。
- 语义化版本约定：
  | 变更类型 | 版本位 | 示例 |
  | --- | --- | --- |
  | 协议行为变更、CLI 不兼容改动 | minor（0.x 阶段） | 0.2.0 → 0.3.0 |
  | 修复、文档、依赖与构建调整 | patch | 0.2.0 → 0.2.1 |
  | 破坏性重构（0.x 之后） | major | 1.0.0 → 2.0.0 |
- tag 使用附注标签（`git tag -a`），message 一句话说明本版内容。
- **不要复用或改写已推送的 tag**；发坏了就递增版本发下一个。

## 发版流程（按序执行）

1. **门禁**（本地，必须全绿）：
   ```sh
   npm run typecheck
   npm test
   ```
2. **改版本**：更新 `package.json` 的 `version`；协议行为有变化时同时更新
   `scripts/package-release.mjs` 的 `PROTOCOL_NOTE`（写清实测的 hdcd 版本与系统版本）。
3. **提交并推送**：commit 到 main，`git push origin main`。
   commit message 用 `feat: …` / `fix: …` / `chore(release): …` 中文摘要风格，
   正文写改动点与验证程度。
4. **打 tag 并推送**：
   ```sh
   git tag -a v<version> -m "<一句话>"
   git push origin v<version>
   ```
5. **盯 CI**：<https://github.com/yuanbaobaoo/hdc-direct/actions>
6. **验收 Release**（三项都过才算发完）：
   - run `conclusion: success`；
   - Release 资产齐全：`hdc-direct-<version>.tar.gz`、
     `hdc-direct-<version>.tar.gz.sha256`、`hdc-direct-<version>.json`；
   - 校验和可验证：下载两个文件后 `sha256sum -c hdc-direct-<version>.tar.gz.sha256` 通过。

## 产物事实

- `hdc-direct-<version>.tar.gz` 内容：`dist/src/`（tsc 编译产物）+ `package.json` +
  `README.md` + `LICENSE`；入口 `dist/src/cli.js`，运行时零依赖，仅需 Node ≥ 18。
- `hdc-direct-<version>.json` 记录包名、版本、协议验证结论、入口与运行时要求，
  供下游（如 zcode-ohos）判断兼容性。
- Release body 由 CI 动态生成：上一个 `v*` tag 以来的提交列表 + 固定资产/使用说明，
  不写死、不手写。

## 边界与易混点

- **协议黄金用例是发布门槛**：`test/proto.golden.test.ts` 的字节基线来自真机抓包，
  任何编码器改动必须先通过它再谈发版。
- 发布资产不含真机 ELF 或 HNP 包：HarmonyOS 7.0 对 ELF 有 hmmac 执行白名单与
  HNP 代码签名管制（详见 README「部署到鸿蒙真机」），本项目以 Node 脚本形态分发。
- 下游按资产名约定拉取，**改名必须同步通知下游**并在 Release notes 中说明。
- 本仓库不发布 npm 包；`npm publish` 不在发版流程内。
