#!/usr/bin/env python3
"""Verify separate ABI APKs and their matching native/runtime payloads."""

import glob
import io
import struct
import sys
import zipfile

if len(sys.argv) != 2 or sys.argv[1] not in {"debug", "release"}:
    raise SystemExit("usage: python3 scripts/verify-abi-apks.py debug|release")
variant = sys.argv[1]

specs = [
    ("arm32", "armeabi-v7a", 1, 40),
    ("arm64", "arm64-v8a", 2, 183),
]
required_native = {"libfusion.so", "libmain.so", "libcrypto.so", "libssl.so"}

for flavor, abi, elf_class, machine in specs:
    matches = glob.glob(f"fusionApp/build/outputs/apk/{flavor}/{variant}/*.apk")
    if len(matches) != 1:
        raise SystemExit(f"Expected one {flavor}/{variant} APK, found {matches}")
    apk_path = matches[0]
    with zipfile.ZipFile(apk_path) as apk:
        names = set(apk.namelist())
        native_entries = sorted(n for n in names if n.startswith("lib/") and n.endswith(".so"))
        if not native_entries:
            raise SystemExit(f"No native libraries in {apk_path}")
        wrong_abi = [n for n in native_entries if not n.startswith(f"lib/{abi}/")]
        if wrong_abi:
            raise SystemExit(f"Wrong ABI libraries in {apk_path}: {wrong_abi}")
        for name in native_entries:
            data = apk.read(name)
            actual_machine = struct.unpack("<H", data[18:20])[0]
            if data[:4] != b"\x7fELF" or data[4] != elf_class or actual_machine != machine:
                raise SystemExit(
                    f"Wrong ELF ABI in {apk_path}: {name} (class={data[4]}, machine={actual_machine})"
                )
        packaged = {n.rsplit("/", 1)[-1] for n in native_entries}
        missing = required_native - packaged
        if missing:
            raise SystemExit(f"Missing native libraries in {apk_path}: {sorted(missing)}")

        runtime_assets = [
            f"assets/BepInEx-{flavor}.zip",
            f"assets/dotnet-{flavor}.zip",
            f"assets/il2cpp2mono-{flavor}.zip",
        ]
        absent = [n for n in runtime_assets if n not in names]
        if absent:
            raise SystemExit(f"Missing {flavor} assets in {apk_path}: {absent}")
        other = "arm64" if flavor == "arm32" else "arm32"
        opposite_assets = [
            f"assets/BepInEx-{other}.zip",
            f"assets/dotnet-{other}.zip",
            f"assets/il2cpp2mono-{other}.zip",
        ]
        leaked = [n for n in opposite_assets if n in names]
        if leaked:
            raise SystemExit(f"Unexpected other-ABI assets in {apk_path}: {leaked}")

        mono_zip = zipfile.ZipFile(io.BytesIO(apk.read(f"assets/il2cpp2mono-{flavor}.zip")))
        if mono_zip.testzip() is not None:
            raise SystemExit(f"Corrupt Il2Cpp2Mono asset in {apk_path}")
        for name in mono_zip.namelist():
            basename = name.rsplit("/", 1)[-1]
            if name.startswith("__MACOSX/") or basename.startswith("._") or basename == ".DS_Store":
                continue
            if not name.endswith(".so"):
                continue
            data = mono_zip.read(name)
            actual_machine = struct.unpack("<H", data[18:20])[0]
            if data[:4] != b"\x7fELF" or data[4] != elf_class or actual_machine != machine:
                raise SystemExit(
                    f"Wrong ELF ABI in {apk_path}: {name} (class={data[4]}, machine={actual_machine})"
                )
    print(f"OK: {flavor} {variant}: {apk_path} ({abi}; matching runtime assets)")
