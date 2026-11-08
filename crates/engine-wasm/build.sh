#!/usr/bin/env sh
# Builds the WebAssembly engine (decision 036) and writes its JavaScript glue into the SDK:
#   crates/engine-wasm/build.sh <sdk>/src
# Needs the wasm32-unknown-unknown target and wasm-bindgen-cli 0.2.125 (the crate pins the
# same wasm-bindgen version). The SDK commits the output; rebuild after an engine change.
set -eu
out=${1:?usage: build.sh <sdk>/src}
cd "$(dirname "$0")/../.."
cargo build -p dynodoc-engine-wasm --target wasm32-unknown-unknown --profile wasm
target=${CARGO_TARGET_DIR:-target}
wasm-bindgen --target web --out-name engine-wasm --out-dir "$out" \
  "$target/wasm32-unknown-unknown/wasm/dynodoc_engine_wasm.wasm"
rm -f "$out/engine-wasm_bg.wasm.d.ts"
# Size pass (decision 040): binaryen's wasm-opt, from PATH or WASM_OPT (for example
# `node <dir>/node_modules/binaryen/bin/wasm-opt` from `npm install binaryen@132.0.0`, no
# administrator rights needed). The SDK test holds the module under 400 KiB gzip.
opt=${WASM_OPT:-wasm-opt}
$opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext   --enable-mutable-globals "$out/engine-wasm_bg.wasm" -o "$out/engine-wasm_bg.wasm"
ls -l "$out/engine-wasm_bg.wasm"
