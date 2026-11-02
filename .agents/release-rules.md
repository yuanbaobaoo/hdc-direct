# hdc-direct 发版规则

适用对象：本仓库维护者与 AI 会话。目标：每次发版可复现、可校验、可回滚。

## 原则

- 发布产物只由 CI 构建；本地只跑门禁、提交、打 tag，不产出发布文件。
- 版本号、tag、Release 资产三者严格对应，任何一处不一致即为发版失败。
- 已发布的东西不改：tag 与 Release 资产只增不改。

## 触发

push `v*` tag → `.github/workflows/release.yml` 依次执行
`typecheck → test → 打包 → 资产校验 → 发布 Release`。

`workflow_dispatch` 只跑构建并上传 Actions Artifact，用于验证流水线，不产生 Release。

## 版本与 tag

- `package.json` 的 `version` 是唯一版本来源。
- tag 必须为 `v<version>`，与 `version` 逐字符一致；CI 校验，不一致直接失败。
- 递增规则：

  | 变更 | 位 | 示例 |
  | --- | --- | --- |
  | 修复、文档、构建调整 | patch | 0.2.0 → 0.2.1 |
  | 协议行为或 CLI 不兼容改动 | minor | 0.2.0 → 0.3.0 |
  | 1.0 之后的破坏性变更 | major | 1.0.0 → 2.0.0 |

- tag 用附注标签（`git tag -a`），message 一句话说明本版内容。
- 已推送的 tag 不改不删；发错就递增版本重发。

## 发版步骤

1. **门禁**：`npm run typecheck`、`npm test` 全绿。
2. **改版本**：更新 `package.json` 的 `version`；协议实测结论有变化时，同步
   `scripts/package-release.mjs` 的 `PROTOCOL_NOTE`。
3. **提交并推送**：commit 到默认分支并 push。
4. **打 tag 并推送**：`git tag -a v<version> -m "<一句话>"`、`git push origin v<version>`。
5. **验收**（三项都过才算发完）：
   - workflow 结论为 success；
   - Release 资产齐全：`hdc-direct-<version>.tar.gz`、`.tar.gz.sha256`、`.json`；
   - 下载后 `sha256sum -c hdc-direct-<version>.tar.gz.sha256` 通过，
     且包内存在 `dist/src/cli.js`。

## 发布内容

- `hdc-direct-<version>.tar.gz`：`dist/src/`（编译产物）+ `package.json` +
  `README.md` + `LICENSE`。入口 `dist/src/cli.js`，运行时零依赖，Node ≥ 18。
- `hdc-direct-<version>.json`：包名、版本、协议验证结论、入口、运行时要求，
  供下游判断兼容性。
- Release body：上一 tag 至本 tag 的提交列表 + 资产表 + 使用片段，由 CI 生成。

## 禁止

- 本地打包后手工上传 Release 资产。
- 修改或覆盖已发布的 tag 与 Release 资产。
- 跳过测试发版。
- tag 与版本号不一致时用强推修正。
