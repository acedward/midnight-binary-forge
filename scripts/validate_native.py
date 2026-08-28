#!/usr/bin/env python3
"""Validate native binary identity/linkage without architecture fallback."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

from forge_io import ForgeError, expect, validate_regular_file


def run(command: list[str]) -> str:
    completed = subprocess.run(command, check=False, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    expect(completed.returncode == 0, f"probe failed ({completed.returncode}): {command[0]}: {completed.stderr.strip()}")
    return completed.stdout + completed.stderr


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--os", required=True, choices=["linux", "macos"])
    parser.add_argument("--arch", required=True, choices=["amd64", "arm64"])
    parser.add_argument("--runner-os", required=True, choices=["linux", "macos"])
    parser.add_argument("--runner-arch", required=True, choices=["amd64", "arm64"])
    parser.add_argument("--forbid-linkage-prefix", action="append", default=[])
    args = parser.parse_args()
    try:
        validate_regular_file(args.binary, "0755")
        expect(args.os == args.runner_os and args.arch == args.runner_arch, "native runner mismatch; fallback/emulation is forbidden")
        expect(shutil.which("file") is not None, "file utility unavailable")
        file_output = run(["file", "-b", str(args.binary)])
        if args.os == "linux":
            expect("ELF" in file_output, "expected ELF binary")
            expected = "x86-64" if args.arch == "amd64" else "aarch64"
            expect(expected.casefold() in file_output.casefold(), f"ELF architecture mismatch: {file_output.strip()}")
            expect(shutil.which("readelf") is not None, "readelf utility unavailable")
            header = run(["readelf", "-h", str(args.binary)])
            machine = "Advanced Micro Devices X86-64" if args.arch == "amd64" else "AArch64"
            expect(machine.casefold() in header.casefold(), f"readelf machine mismatch: expected {machine}")
            linkage = run(["readelf", "-d", str(args.binary)])
        else:
            expect("Mach-O" in file_output, "expected Mach-O binary")
            for tool in ("lipo", "otool", "vtool"):
                expect(shutil.which(tool) is not None, f"{tool} utility unavailable")
            archs = run(["lipo", "-archs", str(args.binary)])
            expected = "x86_64" if args.arch == "amd64" else "arm64"
            expect(archs.strip() == expected, f"Mach-O architecture mismatch: {archs.strip()}")
            linkage = run(["otool", "-L", str(args.binary)])
            run(["vtool", "-show-build", str(args.binary)])
        for prefix in args.forbid_linkage_prefix:
            expect(prefix not in linkage, f"forbidden developer-only linkage: {prefix}")
        print(f"OK native {args.os}/{args.arch} {args.binary.name}")
        return 0
    except (ForgeError, OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
