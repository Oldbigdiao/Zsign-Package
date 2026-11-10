#!/usr/bin/env bash

set -euo pipefail
umask 077

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
openssl_prefix="${ZSIGN_OPENSSL_PREFIX:-/opt/homebrew/opt/openssl@3}"
if [[ ! -f "$openssl_prefix/lib/libcrypto.dylib" ]]; then
    echo "Host OpenSSL 3 is required; set ZSIGN_OPENSSL_PREFIX to its prefix." >&2
    exit 1
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/zsign-policy.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/module" "$work/cache"
export CLANG_MODULE_CACHE_PATH="$work/cache"
export SWIFT_MODULECACHE_PATH="$work/cache"
macos_sdk="$(xcrun --sdk macosx --show-sdk-path)"

# 可选的真实签名材料仅按路径读取；密码内容不进入 argv、日志或仓库。
# ZSIGN_TEST_P12 / ZSIGN_TEST_PROFILE / ZSIGN_TEST_PASSWORD_FILE 必须一起提供。
if [[ -n "${ZSIGN_TEST_P12:-}${ZSIGN_TEST_PROFILE:-}${ZSIGN_TEST_PASSWORD_FILE:-}" ]]; then
    for variable in ZSIGN_TEST_P12 ZSIGN_TEST_PROFILE ZSIGN_TEST_PASSWORD_FILE; do
        if [[ -z "${!variable:-}" || ! -f "${!variable}" ]]; then
            echo "Missing signing input: $variable" >&2
            exit 1
        fi
    done
    "$openssl_prefix/bin/openssl" cms -verify -inform DER -in "$ZSIGN_TEST_PROFILE" \
        -noverify -out "$work/profile.plist"
fi

# 编译真实的签名实现，验证产物中的 CodeDirectory，而不是匹配源码文本。
sources=(archo.cpp bundle.cpp macho.cpp openssl.cpp openssl_tools.mm signing.cpp zsign.mm
    common/base64.cpp common/fs.cpp common/json.cpp common/log.cpp
    common/sha.cpp common/timer.cpp common/util.cpp)
source_paths=()
for source in "${sources[@]}"; do source_paths+=("$root/src/$source"); done
xcrun clang++ -isysroot "$macos_sdk" -std=c++17 -fblocks -dynamiclib -Wno-deprecated-declarations -Wno-macro-redefined \
    -I "$root/src" -I "$root/src/common" -I "$openssl_prefix/include" \
    "${source_paths[@]}" -L "$openssl_prefix/lib" -lcrypto -lssl \
    -framework Foundation -o "$work/libZsignNative.dylib"
cat > "$work/module/module.modulemap" <<EOF
module Zsign {
    header "$root/src/include/ZSign.h"
    export *
}
EOF

cat > "$work/main.swift" <<'SWIFT'
import Foundation
import Zsign

let root = URL(fileURLWithPath: CommandLine.arguments[1])
let fm = FileManager.default

func fixture(_ name: String) throws -> String {
    let app = root.appendingPathComponent("\(name).app")
    try fm.createDirectory(at: app, withIntermediateDirectories: true)
    try fm.copyItem(at: root.appendingPathComponent("Fixture"), to: app.appendingPathComponent("Fixture"))
    let info: [String: Any] = ["CFBundleIdentifier": "test.zsign.fixture", "CFBundleExecutable": "Fixture",
                              "CFBundleVersion": "1", "CFBundleName": "Fixture"]
    try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
        .write(to: app.appendingPathComponent("Info.plist"))
    return app.path
}

// 无效文件的原生结果为 nil，Swift 列表接口不能因此强制解包崩溃。
let invalidMachO = root.appendingPathComponent("invalid-mach-o.dylib")
try Data("owned injected plugin".utf8).write(to: invalidMachO)
precondition(Zsign.listDylibs(appExecutable: invalidMachO.path).isEmpty)
precondition(Zsign.listDylibs(appExecutable: root.appendingPathComponent("missing-mach-o").path).isEmpty)

var callbackCount = 0
let defaultResult = Zsign.sign(appPath: try fixture("default"), adhoc: true) { success, error in
    precondition(success && error == nil)
    callbackCount += 1
}
precondition(defaultResult && callbackCount == 1)

for allowDebug in [false, true] {
    let name = allowDebug ? "sha256-debug" : "sha256-release"
    let entitlements = root.appendingPathComponent("\(name).plist")
    try PropertyListSerialization.data(fromPropertyList: ["get-task-allow": allowDebug], format: .xml, options: 0)
        .write(to: entitlements)
    // 不提供回调也是合法的公开 API 用法。
    let appPath = try fixture(name)
    precondition(Zsign.sign(appPath: appPath, entitlementsPath: entitlements.path,
                            adhoc: true, signaturePolicy: .sha256Only))
}

let legacyResult = zsign(try fixture("legacy"), "", "", "", "", "", "", "", true, true) { success, error in
    precondition(success && error == nil)
}
precondition(legacyResult == 0)

func expectFailure(_ path: String, adhoc: Bool) {
    var calls = 0
    let result = Zsign.sign(appPath: path, adhoc: adhoc) { success, error in
        precondition(!success && error != nil)
        calls += 1
    }
    guard !result && calls == 1 else {
        fputs("Failure must return false and invoke completion exactly once; got \(calls) callbacks.\n", stderr)
        exit(1)
    }
}
expectFailure(root.appendingPathComponent("missing.app").path, adhoc: true)
expectFailure(try fixture("missing-identity"), adhoc: false)
let invalidBundle = root.appendingPathComponent("invalid.app")
try fm.createDirectory(at: invalidBundle, withIntermediateDirectories: true)
expectFailure(invalidBundle.path, adhoc: true)
precondition(!Zsign.sign(appPath: root.appendingPathComponent("missing.app").path, adhoc: true))

func bundleInfo(in folder: URL, executable: String, info: String = "Info.plist") throws {
    let path = folder.appendingPathComponent(info)
    try fm.createDirectory(at: path.deletingLastPathComponent(), withIntermediateDirectories: true)
    try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": "test.zsign.executable",
        "CFBundleExecutable": executable, "CFBundleVersion": "1"], format: .binary, options: 0).write(to: path)
}

let sentinel = root.appendingPathComponent("outside")
let fixtureBytes = try Data(contentsOf: root.appendingPathComponent("Fixture"))
func writeSentinel() throws {
    try fixtureBytes.write(to: sentinel, options: .atomic)
    try fm.setAttributes([.posixPermissions: 0o444], ofItemAtPath: sentinel.path)
}
func assertSentinel(_ label: String) throws {
    let mode = try fm.attributesOfItem(atPath: sentinel.path)[.posixPermissions] as? NSNumber
    guard try Data(contentsOf: sentinel) == fixtureBytes, mode?.intValue == 0o444 else {
        fputs("\(label) modified an external Mach-O or its mode.\n", stderr)
        exit(1)
    }
}

try writeSentinel()
let escapedApp = URL(fileURLWithPath: try fixture("escaped"))
try bundleInfo(in: escapedApp, executable: "../outside")
let escapedResult = Zsign.sign(appPath: escapedApp.path, adhoc: true)
try assertSentinel("Root traversal")
precondition(!escapedResult)

for (index, name) in ["", ".", "..", "/Fixture", "Contents/Fixture", "A\\B", "A:B", "Fixture\0ignored", "Directory"].enumerated() {
    let app = URL(fileURLWithPath: try fixture("invalid-leaf-\(index)"))
    try fm.createDirectory(at: app.appendingPathComponent("Contents"), withIntermediateDirectories: false)
    try fm.createDirectory(at: app.appendingPathComponent("Directory"), withIntermediateDirectories: false)
    for path in ["Contents/Fixture", "A\\B", "A:B"] {
        try fm.copyItem(at: root.appendingPathComponent("Fixture"), to: app.appendingPathComponent(path))
    }
    try bundleInfo(in: app, executable: name)
    expectFailure(app.path, adhoc: true)
}

for (index, bundleName, executable) in [(0, "PlugIns/Unsafe.appex", "../../../outside"),
    (1, "Frameworks/Unsafe.framework", "../../../outside"), (2, "Watch/Unsafe.app", "../../../outside"),
    (3, "PlugIns/Unsafe.xctest", "../../../outside"), (4, "PlugIns/Unsafe.appex", "Linked"),
    (5, "Frameworks/Unsafe.framework", "HardLinked")] {
    let app = URL(fileURLWithPath: try fixture("unsafe-nested-\(index)"))
    let nested = app.appendingPathComponent(bundleName)
    try bundleInfo(in: nested, executable: executable)
    if executable == "Linked" {
        try fm.createSymbolicLink(at: nested.appendingPathComponent(executable), withDestinationURL: sentinel)
    } else if executable == "HardLinked" {
        try fm.linkItem(at: sentinel, to: nested.appendingPathComponent(executable))
    }
    let result = Zsign.sign(appPath: app.path, adhoc: true)
    try assertSentinel("Nested traversal or link in \(bundleName)")
    precondition(!result)
}

let escapedResourcesApp = URL(fileURLWithPath: try fixture("escaped-resources"))
let escapedFramework = escapedResourcesApp.appendingPathComponent("Frameworks/Unsafe.framework")
try bundleInfo(in: escapedFramework, executable: "../../../outside", info: "Resources/Info.plist")
expectFailure(escapedResourcesApp.path, adhoc: true)
try assertSentinel("Framework Resources traversal")

let largePlistApp = URL(fileURLWithPath: try fixture("large-nested-plist"))
let largePlistExtension = largePlistApp.appendingPathComponent("PlugIns/Large.appex")
try fm.createDirectory(at: largePlistExtension, withIntermediateDirectories: true)
try fm.copyItem(at: root.appendingPathComponent("Fixture"), to: largePlistExtension.appendingPathComponent("Fixture"))
try PropertyListSerialization.data(fromPropertyList: [
    "CFBundleIdentifier": "test.zsign.large",
    "CFBundleExecutable": "Fixture",
    "Padding": Data(count: 1024 * 1024)
], format: .binary, options: 0).write(to: largePlistExtension.appendingPathComponent("Info.plist"))
precondition(!Zsign.validateBundleForSigning(in: largePlistApp))
expectFailure(largePlistApp.path, adhoc: true)

let readOnly = root.appendingPathComponent("read-only")
try fm.copyItem(at: root.appendingPathComponent("Fixture"), to: readOnly)
try fm.setAttributes([.posixPermissions: 0o444], ofItemAtPath: readOnly.path)
precondition(Zsign.listDylibs(appExecutable: readOnly.path).contains("/usr/lib/libSystem.B.dylib"))
let mode = try fm.attributesOfItem(atPath: readOnly.path)[.posixPermissions] as? NSNumber
precondition(mode?.intValue == 0o444)

let nestedApp = URL(fileURLWithPath: try fixture("valid-nested"))
let flatFramework = nestedApp.appendingPathComponent("Frameworks/Flat.framework")
let resourceFramework = nestedApp.appendingPathComponent("Frameworks/Resources.framework")
let appExtension = nestedApp.appendingPathComponent("PlugIns/Valid.appex")
for (bundle, executable, info) in [(flatFramework, "Flat", "Info.plist"),
    (resourceFramework, "ResourcesFramework", "Resources/Info.plist"), (appExtension, "Valid", "Info.plist")] {
    try bundleInfo(in: bundle, executable: executable, info: info)
    try fm.copyItem(at: root.appendingPathComponent("Fixture"), to: bundle.appendingPathComponent(executable))
}
precondition(Zsign.sign(appPath: nestedApp.path, adhoc: true))
for bundle in [flatFramework, resourceFramework, appExtension] {
    precondition(fm.fileExists(atPath: bundle.appendingPathComponent("_CodeSignature/CodeResources").path))
}
print("Zsign bundle executable paths: external sentinels preserved, read-only inspection and valid nested bundles passed")

if let p12Path = ProcessInfo.processInfo.environment["ZSIGN_TEST_P12"] {
    let environment = ProcessInfo.processInfo.environment
    let profilePath = environment["ZSIGN_TEST_PROFILE"]!
    let password = try String(contentsOfFile: environment["ZSIGN_TEST_PASSWORD_FILE"]!, encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    let profileData = try Data(contentsOf: root.appendingPathComponent("profile.plist"))
    let profile = try PropertyListSerialization.propertyList(from: profileData, format: nil) as! [String: Any]
    let entitlements = profile["Entitlements"] as! [String: Any]
    let appID = entitlements["application-identifier"] as! String
    let bundleID = appID.split(separator: ".", maxSplits: 1)[1].replacingOccurrences(of: "*", with: "zsignfixture")
    for removeProvision in [false, true] {
        let name = removeProvision ? "cms-remove" : "cms-keep"
        var calls = 0
        let result = Zsign.sign(appPath: try fixture(name), provisionPath: profilePath,
                               p12Path: p12Path, p12Password: password,
                               customIdentifier: bundleID, removeProvision: removeProvision,
                               signaturePolicy: .sha256Only) { success, error in
            precondition(success && error == nil)
            calls += 1
        }
        precondition(result && calls == 1)
    }
}
SWIFT

printf 'int main(void) { return 0; }\n' > "$work/fixture.c"
xcrun clang -target arm64-apple-ios15.0 -isysroot "$(xcrun --sdk iphoneos --show-sdk-path)" \
    "$work/fixture.c" -o "$work/Fixture"
xcrun swiftc -sdk "$macos_sdk" -module-cache-path "$work/cache" -I "$work/module" \
    "$root/Sources/zsign.swift" "$work/main.swift" -L "$work" -lZsignNative \
    -Xlinker -rpath -Xlinker "$work" -o "$work/test-policy"
(cd "$work" && "$work/test-policy" "$work")

python3 - "$work" "$openssl_prefix/bin/openssl" <<'PY'
import hashlib
import os
import pathlib
import plistlib
import struct
import subprocess
import sys

root = pathlib.Path(sys.argv[1])

def slots(name):
    data = (root / f"{name}.app" / "Fixture").read_bytes()
    assert struct.unpack_from("<I", data)[0] == 0xFEEDFACF
    ncmds = struct.unpack_from("<I", data, 16)[0]
    command = 32
    for _ in range(ncmds):
        kind, size = struct.unpack_from("<II", data, command)
        if kind == 0x1D:
            start, length = struct.unpack_from("<II", data, command + 8)
            signature = data[start:start + length]
            break
        command += size
    else:
        raise AssertionError("missing LC_CODE_SIGNATURE")
    magic, length, count = struct.unpack_from(">III", signature)
    assert magic == 0xFADE0CC0
    result = {}
    for i in range(count):
        slot, offset = struct.unpack_from(">II", signature, 12 + 8 * i)
        size = struct.unpack_from(">I", signature, offset + 4)[0]
        result[slot] = signature[offset:offset + size]
    return result

def directories(name, expected_exec_flags=1):
    result = []
    for slot, data in slots(name).items():
        if slot == 0 or 0x1000 <= slot <= 0x1005:
            assert struct.unpack_from(">I", data)[0] == 0xFADE0C02
            hash_type = data[37]
            exec_flags = struct.unpack_from(">Q", data, 80)[0]
            assert exec_flags == expected_exec_flags, f"{name}: main executable flags {exec_flags:#x}"
            result.append(hash_type)
    return result

for name in ("default", "legacy"):
    actual = directories(name)
    assert actual == [1, 2], f"{name}: expected compatible SHA1 + SHA256 directories; got {actual}"
assert directories("sha256-release") == [2]
assert directories("sha256-debug", 0x11) == [2]
print("Zsign native signatures: compatible default, legacy entry, SHA256-only, execution flags and failure callbacks passed")

def der_nodes(data):
    result = []
    offset = 0
    while offset < len(data):
        tag, length = data[offset:offset + 2]
        offset += 2
        if length & 0x80:
            width = length & 0x7F
            assert width > 0, "indefinite length is not DER"
            length = int.from_bytes(data[offset:offset + width], "big")
            offset += width
        content = data[offset:offset + length]
        assert len(content) == length
        offset += length
        result.append((tag, content, der_nodes(content) if tag & 0x20 else []))
    return result

def entitlement_value(node):
    tag, content, children = node
    if tag == 0x31:
        return {entitlement_value(pair[2][0]): entitlement_value(pair[2][1]) for pair in children}
    if tag == 0x30:
        return [entitlement_value(child) for child in children]
    if tag == 0x0C:
        return content.decode()
    if tag == 0x01:
        assert len(content) == 1
        return content != b"\0"
    if tag == 0x02:
        return int.from_bytes(content, "big", signed=True)
    raise AssertionError(f"Unsupported entitlement DER tag: {tag:#x}")

def attribute(nodes, oid):
    for tag, _, children in nodes:
        if tag == 0x30 and len(children) == 2 and children[0][:2] == (0x06, oid):
            return children[1][2]
        found = attribute(children, oid)
        if found is not None:
            return found
    return None

if (root / "profile.plist").exists():
    profile = plistlib.loads((root / "profile.plist").read_bytes())
    expected_exec_flags = 0x11 if profile["Entitlements"].get("get-task-allow") else 1
    for name in ("cms-keep", "cms-remove"):
        assert directories(name, expected_exec_flags) == [2]
        blobs = slots(name)
        directory = blobs[0]
        digest = hashlib.sha256(directory).digest()
        xml_entitlements = plistlib.loads(blobs[5][8:])
        assert struct.unpack_from(">I", blobs[7])[0] == 0xFADE7172
        assert entitlement_value(der_nodes(blobs[7][8:])[0]) == xml_entitlements, "DER/XML entitlements differ"
        assert xml_entitlements == profile["Entitlements"], "Profile entitlements were not preserved"
        hash_offset = struct.unpack_from(">I", directory, 16)[0]
        for special_slot in (5, 7):
            expected_hash = hashlib.sha256(blobs[special_slot]).digest()
            assert directory[hash_offset - special_slot * 32:hash_offset - (special_slot - 1) * 32] == expected_hash

        cms = blobs[0x10000][8:]
        nodes = der_nodes(cms)
        plist_attribute = attribute(nodes, bytes.fromhex("2a864886f763640901"))
        assert len(plist_attribute) == 1 and plist_attribute[0][0] == 0x04
        assert plistlib.loads(plist_attribute[0][1])["cdhashes"] == [digest[:20]], "CMS plist CDHash mismatch"
        digest_attribute = attribute(nodes, bytes.fromhex("2a864886f763640902"))
        assert len(digest_attribute) == 1 and digest_attribute[0][0] == 0x30
        algorithm, value = digest_attribute[0][2]
        assert algorithm[:2] == (0x06, bytes.fromhex("608648016503040201"))
        assert value[:2] == (0x04, digest), "CMS SHA256 CDHash mismatch"

        cms_path, directory_path = root / f"{name}.cms", root / f"{name}.cd"
        cms_path.write_bytes(cms)
        directory_path.write_bytes(directory)
        subprocess.run([sys.argv[2], "cms", "-verify", "-binary", "-inform", "DER", "-in", str(cms_path),
                        "-content", str(directory_path), "-noverify", "-out", os.devnull], check=True)
        app_path = root / f"{name}.app"
        subprocess.run(["codesign", "--verify", "--strict", "--verbose=2", str(app_path)], check=True)
        details = subprocess.run(["codesign", "-d", "--verbose=4", str(app_path)], capture_output=True, text=True, check=True)
        assert f"CDHash={digest[:20].hex()}" in details.stderr.splitlines(), "codesign CDHash mismatch"
        embedded = app_path / "embedded.mobileprovision"
        if name == "cms-keep":
            assert embedded.read_bytes() == pathlib.Path(os.environ["ZSIGN_TEST_PROFILE"]).read_bytes()
        else:
            assert not embedded.exists(), "removeProvision=true retained the profile"
    print("Zsign real identity: CMS signatures, both CDHash attributes, DER entitlements, codesign and removeProvision passed")
PY
