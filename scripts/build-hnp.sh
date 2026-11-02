#!/bin/sh
# 一键构建 OHOS arm64 二进制并打包 .hnp（需要 DevEco command-line-tools，
# sysroot/libunwind 路径在 .cargo/config.toml 中配置）
set -e
cd "$(dirname "$0")/.."
cargo build --release --target aarch64-unknown-linux-ohos
rm -rf dist/hnp-pkg dist/hdc-direct.hnp
mkdir -p dist/hnp-pkg/bin
cp target/aarch64-unknown-linux-ohos/release/hdc-direct dist/hnp-pkg/bin/
cp hnp/hnp.json dist/hnp-pkg/
HNPCLI="${HNPCLI:-$(dirname "$(command -v hdc || echo /Users/Shared/local/ohos/command-line-tools_26.0.0_Beta1/sdk/default/openharmony/toolchains/hnpcli)")/hnpcli}"
"$HNPCLI" pack -i "$(pwd)/dist/hnp-pkg" -o "$(pwd)/dist/"
echo "==> dist/hdc-direct.hnp"
