#!/usr/bin/env python3
"""Capture the actual pre-Developer-ID signature state of one Mach-O file."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from forge_io import ForgeError, canonical_bytes, create_file_atomic, expect, sha256_file


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, check=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        digest, size = sha256_file(args.binary, 512 * 2**20)
        display = run(["codesign", "--display", "--verbose=4", str(args.binary)])
        combined = display.stdout + display.stderr
        if display.returncode != 0:
            expect("not signed" in combined.casefold(), f"unexpected codesign display failure: {combined.strip()}")
            kind = "none"
            strict = False
            cdhash = None
            authorities: list[str] = []
            team_id = None
            hardened = False
        else:
            authorities = re.findall(r"^Authority=(.+)$", combined, flags=re.MULTILINE)
            team_match = re.search(r"^TeamIdentifier=(.+)$", combined, flags=re.MULTILINE)
            team_id = None if team_match is None or team_match.group(1) in {"not set", ""} else team_match.group(1)
            cdhash_match = re.search(r"^CDHash=([0-9A-Fa-f]+)$", combined, flags=re.MULTILINE)
            expect(cdhash_match is not None, "signed Mach-O has no CDHash")
            cdhash = cdhash_match.group(1).lower()
            adhoc = bool(re.search(r"^Signature=adhoc$", combined, flags=re.MULTILINE))
            kind = "linker-adhoc" if adhoc and not authorities and team_id is None else "developer-id"
            verify = run(["codesign", "--verify", "--strict", "--verbose=4", str(args.binary)])
            strict = verify.returncode == 0
            hardened = "runtime" in combined.casefold() and "flags=" in combined.casefold()
        expect(kind in {"none", "linker-adhoc"}, "initial development build unexpectedly carries Developer ID authority")
        record = {
            "schemaVersion": "phase4-macos-signature-v1",
            "distributionSigningState": "UNSIGNED_DEVELOPMENT_ONLY",
            "binary": {"name": args.binary.name, "size": size, "sha256": digest},
            "codeSignatureKind": kind,
            "cdHash": cdhash,
            "authorities": authorities,
            "teamId": team_id,
            "hardenedRuntime": hardened,
            "strictVerification": strict,
            "codesignDisplayExit": display.returncode,
            "codesignDisplay": combined,
        }
        create_file_atomic(args.output, canonical_bytes(record) + b"\n")
        print(json.dumps(record, sort_keys=True, separators=(",", ":")))
        return 0
    except (ForgeError, OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
