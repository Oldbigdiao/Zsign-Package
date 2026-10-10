#!/usr/bin/env bash
set -euo pipefail
umask 077

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
openssl_prefix="${ZSIGN_OPENSSL_PREFIX:-/opt/homebrew/opt/openssl@3}"
work="$(mktemp -d "${TMPDIR:-/tmp}/zsign-lifecycle.XXXXXX")"
trap 'rm -rf "$work"' EXIT
sdk="$(xcrun --sdk macosx --show-sdk-path)"
sources=(archo.cpp bundle.cpp macho.cpp openssl.cpp openssl_tools.mm signing.cpp zsign.mm
    common/base64.cpp common/fs.cpp common/json.cpp common/log.cpp
    common/sha.cpp common/timer.cpp common/util.cpp)
source_paths=()
for source in "${sources[@]}"; do source_paths+=("$root/src/$source"); done

# 通过当前进程的实际文件映射验证释放，不依赖源码文本或内存增长阈值。
xcrun clang++ -isysroot "$sdk" -std=c++17 -fblocks -Wno-deprecated-declarations -Wno-macro-redefined \
    -I "$root/src" -I "$root/src/common" -I "$openssl_prefix/include" \
    "${source_paths[@]}" "$root/tests/macho-lifecycle.cpp" \
    -L "$openssl_prefix/lib" -lcrypto -lssl -framework Foundation -o "$work/test-lifecycle"
"$work/test-lifecycle" "$work"
