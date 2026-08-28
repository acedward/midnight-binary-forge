#!/usr/bin/env python3
"""Fetch one immutable HTTPS object by exact size and SHA-256, create-only."""

from __future__ import annotations

import argparse
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from forge_io import ForgeError, expect, parse_sha256, safe_basename


class HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != "https" or parsed.username or parsed.password:
            raise ForgeError(f"redirect target is not credential-free HTTPS: {newurl!r}")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--size", required=True, type=int)
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()
    temporary: Path | None = None
    try:
        expected_digest = parse_sha256(args.sha256)
        expect(args.size > 0, "size must be positive")
        parsed = urllib.parse.urlsplit(args.url)
        expect(parsed.scheme == "https", "source URL must use HTTPS")
        expect(parsed.hostname is not None and not parsed.username and not parsed.password, "source URL must not embed credentials")
        safe_basename(args.output.name, "output basename")
        expect(args.output.parent.is_dir(), "output parent must exist")
        expect(not args.output.exists(), "refusing to replace existing output")
        temporary = args.output.parent / f".{args.output.name}.part-{os.getpid()}"
        opener = urllib.request.build_opener(HttpsOnlyRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        request = urllib.request.Request(args.url, headers={"User-Agent": "midnight-binary-forge/fetch_verified-v1", "Accept-Encoding": "identity"})
        import hashlib

        hasher = hashlib.sha256()
        total = 0
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(temporary, flags, 0o600)
        with os.fdopen(fd, "wb") as output, opener.open(request, timeout=args.timeout) as response:
            expect(response.geturl().startswith("https://"), "final source URL is not HTTPS")
            while True:
                chunk = response.read(min(1024 * 1024, args.size - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                expect(total <= args.size, "download exceeds expected size")
                output.write(chunk)
                hasher.update(chunk)
            output.flush()
            os.fsync(output.fileno())
        expect(total == args.size, f"size mismatch: expected {args.size}, got {total}")
        actual_digest = hasher.hexdigest()
        expect(actual_digest == expected_digest, f"SHA-256 mismatch: expected {expected_digest}, got {actual_digest}")
        os.chmod(temporary, 0o644)
        os.link(temporary, args.output)
        os.unlink(temporary)
        temporary = None
        print(f"OK {args.output.name} {total} {actual_digest}")
        return 0
    except (ForgeError, OSError, urllib.error.URLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
