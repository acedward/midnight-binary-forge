#!/usr/bin/env python3
"""Prove a job is executing on the exact requested native runner class."""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import sys
from pathlib import Path

from forge_io import ForgeError, expect


RUNNER_TARGETS = {
    "ubuntu-24.04": ("linux", "amd64"),
    "ubuntu-24.04-arm": ("linux", "arm64"),
    "macos-15": ("macos", "arm64"),
    "macos-15-intel": ("macos", "amd64"),
}
MACHINE_ALIASES = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
}
SYSTEM_ALIASES = {"linux": "linux", "darwin": "macos"}


def actual_target() -> tuple[str, str]:
    system = SYSTEM_ALIASES.get(platform.system().casefold())
    machine = MACHINE_ALIASES.get(platform.machine().casefold())
    expect(system is not None, f"unsupported runner operating system: {platform.system()}")
    expect(machine is not None, f"unsupported runner architecture: {platform.machine()}")
    return system, machine


def verify_capability(label: str, expected_os: str, expected_arch: str, tools: list[str], min_free_gib: int, workspace: Path) -> None:
    expect(label in RUNNER_TARGETS, f"unapproved runner label: {label}")
    expect(RUNNER_TARGETS[label] == (expected_os, expected_arch), "runner label does not map to requested target")
    expect(actual_target() == (expected_os, expected_arch), "native runner mismatch; emulation/fallback is forbidden")
    expect(workspace.is_dir(), f"workspace does not exist: {workspace}")
    free_bytes = shutil.disk_usage(workspace).free
    expect(free_bytes >= min_free_gib * 1024**3, f"runner has less than {min_free_gib} GiB free")
    missing = sorted(tool for tool in tools if shutil.which(tool) is None)
    expect(not missing, f"required native runner tools missing: {','.join(missing)}")
    github_arch = os.environ.get("RUNNER_ARCH")
    if github_arch:
        expected_github_arch = "X64" if expected_arch == "amd64" else "ARM64"
        expect(github_arch == expected_github_arch, "RUNNER_ARCH disagrees with requested native target")
    github_os = os.environ.get("RUNNER_OS")
    if github_os:
        expected_github_os = "Linux" if expected_os == "linux" else "macOS"
        expect(github_os == expected_github_os, "RUNNER_OS disagrees with requested native target")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner-label", required=True, choices=sorted(RUNNER_TARGETS))
    parser.add_argument("--expected-os", required=True, choices=["linux", "macos"])
    parser.add_argument("--expected-arch", required=True, choices=["amd64", "arm64"])
    parser.add_argument("--require-tool", action="append", default=[])
    parser.add_argument("--min-free-gib", type=int, default=2)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        expect(1 <= args.min_free_gib <= 1000, "invalid minimum free-space requirement")
        verify_capability(args.runner_label, args.expected_os, args.expected_arch, args.require_tool, args.min_free_gib, args.workspace)
        print(f"OK native runner {args.runner_label} {args.expected_os}/{args.expected_arch}")
        return 0
    except (ForgeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
