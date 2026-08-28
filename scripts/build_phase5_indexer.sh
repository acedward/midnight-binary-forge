#!/usr/bin/env bash
set -euo pipefail

: "${PHASE5_OS:?PHASE5_OS is required}"
: "${PHASE5_ARCH:?PHASE5_ARCH is required}"
: "${PHASE5_ATTEMPT:?PHASE5_ATTEMPT is required}"
: "${PHASE5_RUNNER_LABEL:?PHASE5_RUNNER_LABEL is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

case "${PHASE5_OS}/${PHASE5_ARCH}/${PHASE5_ATTEMPT}/${PHASE5_RUNNER_LABEL}" in
  linux/amd64/1/ubuntu-24.04|linux/amd64/2/ubuntu-24.04|\
  linux/arm64/1/ubuntu-24.04-arm|linux/arm64/2/ubuntu-24.04-arm|\
  macos/amd64/1/macos-15-intel|macos/amd64/2/macos-15-intel|\
  macos/arm64/1/macos-15|macos/arm64/2/macos-15) ;;
  *) echo "unapproved native target/build mapping" >&2; exit 2 ;;
esac

readonly SOURCE_COMMIT=56561b2f5cf5c6839f678257fc69bed1a8b9ba2c
readonly SOURCE_TREE=ebc2936215c8791e8bc9e5590b07991bd01878f2
readonly TAG_OBJECT=f0e8019c0d3c8480f14914bdd721357cfb29c073
readonly TAG=v4.4.0-rc.3
readonly CARGO_LOCK_SHA256=7c348e5aeae2caec386ca8e0e2ac06cf103d4b6ea8097d9c18eaef89c9ac23d1
readonly TOOLCHAIN_SHA256=821ff14e4c4a1cbe1e8915f35aff0a3fbbdf8d293ad48ab8f31e3b0440c581f9
readonly LICENSE_SHA256=c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4
readonly VERSION=4.4.0-rc.3
readonly TARGET_ID="${PHASE5_OS}-${PHASE5_ARCH}"
readonly ARCHIVE="indexer-standalone-${TARGET_ID}-v${VERSION}.zip"
readonly INNER="${ARCHIVE%.zip}"
readonly WORK="${RUNNER_TEMP}/phase5-indexer-${TARGET_ID}-build${PHASE5_ATTEMPT}"
readonly SOURCE="${WORK}/source"
readonly STAGE="${GITHUB_WORKSPACE}/stage/${TARGET_ID}-build${PHASE5_ATTEMPT}"
readonly LOG="${WORK}/build.log"

rm -rf "$WORK"
mkdir -p "$WORK" "$STAGE/payload" "$STAGE/evidence-input" "$WORK/package/$INNER"

python3 scripts/check_runner_capability.py \
  --runner-label "$PHASE5_RUNNER_LABEL" \
  --expected-os "$PHASE5_OS" \
  --expected-arch "$PHASE5_ARCH" \
  --require-tool git \
  --require-tool rustc \
  --require-tool cargo \
  --min-free-gib 12

curl -fsSL --retry 3 https://static.rust-lang.org/dist/channel-rust-1.95.0.toml -o "$WORK/channel-rust-1.95.0.toml"
test "$(python3 - "$WORK/channel-rust-1.95.0.toml" <<'PY'
import hashlib, pathlib, sys
print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)" = "$TOOLCHAIN_SHA256"
rustc -Vv | tee "$WORK/rustc-Vv.txt"
test "$(rustc --version | awk '{print $2}')" = 1.95.0
cargo --version | tee "$WORK/cargo-version.txt"

git init "$SOURCE"
git -C "$SOURCE" remote add origin https://github.com/midnightntwrk/midnight-indexer.git
git -C "$SOURCE" fetch --depth 1 origin "refs/tags/${TAG}:refs/tags/${TAG}"
test "$(git -C "$SOURCE" rev-parse "${TAG}")" = "$TAG_OBJECT"
test "$(git -C "$SOURCE" rev-parse "${TAG}^{commit}")" = "$SOURCE_COMMIT"
git -C "$SOURCE" checkout --detach "$SOURCE_COMMIT"
test "$(git -C "$SOURCE" rev-parse HEAD)" = "$SOURCE_COMMIT"
test "$(git -C "$SOURCE" rev-parse HEAD^{tree})" = "$SOURCE_TREE"
test "$(python3 - "$SOURCE/Cargo.lock" <<'PY'
import hashlib, pathlib, sys
print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)" = "$CARGO_LOCK_SHA256"
test "$(python3 - "$SOURCE/LICENSE" <<'PY'
import hashlib, pathlib, sys
print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)" = "$LICENSE_SHA256"

export SOURCE_DATE_EPOCH=1787533457
export MIDNIGHT_INDEXER_GIT_SHA=56561b2f
export MIDNIGHT_INDEXER_BUILD_DATE=2026-08-24
export CARGO_INCREMENTAL=0
export LC_ALL=C
export TZ=UTC
if [[ "$PHASE5_OS" == linux ]]; then
  export RUSTFLAGS="--remap-path-prefix=${SOURCE}=/usr/src/midnight-indexer -C strip=symbols -C link-arg=-Wl,--build-id=sha1"
else
  # Apply path/strip policy to dependencies, including proc-macro dylibs. The
  # final-only no_uuid flag is added below: applying it to proc macros makes
  # Apple-Silicon dyld reject them before the product can be linked.
  export RUSTFLAGS="--remap-path-prefix=${SOURCE}=/usr/src/midnight-indexer -C strip=symbols"
fi

(
  cd "$SOURCE"
  cargo build --locked --release -p indexer-standalone --features standalone
) 2>&1 | tee "$LOG"

if [[ "$PHASE5_OS" == macos ]]; then
  # Apple's linker otherwise creates a random LC_UUID. cargo rustc's trailing
  # arguments affect the selected product target only, leaving host proc-macro
  # dylibs valid. Suppressing this optional load command is not a signing step.
  (
    cd "$SOURCE"
    cargo rustc --locked --release -p indexer-standalone --features standalone -- -C link-arg=-Wl,-no_uuid
  ) 2>&1 | tee -a "$LOG"
fi

readonly BINARY="${SOURCE}/target/release/indexer-standalone"
test -f "$BINARY"
chmod 0755 "$BINARY"
test "$($BINARY --version)" = "indexer-standalone 4.4.0-rc.3 (56561b2f 2026-08-24)"
python3 scripts/validate_native.py \
  --binary "$BINARY" --os "$PHASE5_OS" --arch "$PHASE5_ARCH" \
  --runner-os "$PHASE5_OS" --runner-arch "$PHASE5_ARCH" \
  --forbid-linkage-prefix /nix/store \
  --forbid-linkage-prefix /opt/homebrew \
  --forbid-linkage-prefix /usr/local

python3 - "$BINARY" "$PHASE5_OS" "$PHASE5_ARCH" "$PHASE5_RUNNER_LABEL" "$WORK/native-evidence.json" <<'PY'
import json, os, pathlib, platform, subprocess, sys
binary, os_name, arch, runner_label, output = sys.argv[1:]
def capture(*command):
    result = subprocess.run(command, check=True, text=True, capture_output=True)
    return (result.stdout + result.stderr).strip()
value = {
    "schemaVersion": "phase5-indexer-native-evidence-v1",
    "target": {"os": os_name, "arch": arch, "native": True, "runner": runner_label},
    "host": {"platform": platform.platform(), "machine": platform.machine(), "runnerImage": os.environ.get("ImageOS"), "runnerImageVersion": os.environ.get("ImageVersion")},
    "version": capture(binary, "--version"),
    "file": capture("file", "-b", binary),
}
if os_name == "linux":
    value["elfHeader"] = capture("readelf", "-h", binary)
    value["elfProgramHeaders"] = capture("readelf", "-l", binary)
    value["elfDynamic"] = capture("readelf", "-d", binary)
    value["glibcSymbolVersions"] = sorted(set(capture("readelf", "--version-info", binary).splitlines()))
    value["linkage"] = capture("ldd", binary)
else:
    value["architectures"] = capture("lipo", "-archs", binary)
    value["linkage"] = capture("otool", "-L", binary)
    value["loadCommands"] = capture("otool", "-l", binary)
    value["buildVersion"] = capture("vtool", "-show-build", binary)
    value["swVers"] = capture("sw_vers")
    value["xcode"] = capture("xcodebuild", "-version")
pathlib.Path(output).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
PY

python3 - "$BINARY" "$PHASE5_OS" "$WORK/signing-evidence.json" <<'PY'
import json, pathlib, re, subprocess, sys
binary, os_name, output = sys.argv[1:]
value = {"schemaVersion": "phase5-indexer-signing-evidence-v1", "distributionSigningState": "NOT_APPLICABLE" if os_name == "linux" else "UNSIGNED_DEVELOPMENT_ONLY"}
if os_name == "linux":
    value.update({"applicability": "not-applicable", "codeSignatureKind": None})
else:
    display = subprocess.run(["codesign", "--display", "--verbose=4", binary], text=True, capture_output=True)
    strict = subprocess.run(["codesign", "--verify", "--strict", "--verbose=4", binary], text=True, capture_output=True)
    text = display.stdout + display.stderr
    authorities = re.findall(r"^Authority=(.+)$", text, re.M)
    team = re.search(r"^TeamIdentifier=(.+)$", text, re.M)
    cdhash = re.search(r"^CDHash=([0-9a-fA-F]+)$", text, re.M)
    flags = re.search(r"^CodeDirectory .*?flags=([^\n]+)", text, re.M)
    if display.returncode != 0:
        kind = "none"
    elif authorities or (team and team.group(1) not in ("not set", "")):
        raise SystemExit("unexpected Developer ID/authority in initial no-Developer-ID build")
    else:
        kind = "linker-adhoc"
    value.update({
        "applicability": "macos", "codeSignatureKind": kind,
        "cdHash": cdhash.group(1) if cdhash else None,
        "authorities": authorities, "teamId": None if not team or team.group(1) == "not set" else team.group(1),
        "hardenedRuntime": bool(flags and "runtime" in flags.group(1)),
        "strictVerification": strict.returncode == 0,
        "displayExitCode": display.returncode, "strictExitCode": strict.returncode,
        "display": text.strip(), "strictOutput": (strict.stdout + strict.stderr).strip(),
        "ciSigningAction": "inspection-only; no ad-hoc or Developer ID signing command was invoked",
        "warning": "DEVELOPMENT ONLY — NOT FOR PRODUCTION USE. No Developer ID; Gatekeeper may require explicit override."
    })
pathlib.Path(output).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
PY

if [[ "$PHASE5_ATTEMPT" == 1 ]]; then
  (
    cd "$SOURCE"
    cargo test --locked -p indexer-common --features standalone concurrent_write_transactions_never_hit_busy_errors -- --nocapture
  ) 2>&1 | tee "$WORK/concurrent-wallet-regression.log"

  readonly RUNTIME="$WORK/runtime"
  mkdir -p "$RUNTIME"
  cp "$SOURCE/indexer-standalone/config.yaml" "$RUNTIME/config.yaml"
  python3 - "$RUNTIME/indexer-secret" "$RUNTIME/blockfrost-id" <<'PY'
import pathlib, secrets, sys
pathlib.Path(sys.argv[1]).write_text(secrets.token_hex(32) + "\n")
pathlib.Path(sys.argv[2]).write_text("phase5-public-test-placeholder\n")
PY
  chmod 0600 "$RUNTIME/indexer-secret" "$RUNTIME/blockfrost-id"
  readonly PORT="$(python3 - <<'PY'
import random, socket
for _ in range(1000):
    port = random.randrange(10000, 60000)
    with socket.socket() as sock:
        try: sock.bind(("127.0.0.1", port))
        except OSError: continue
        print(port); break
else: raise SystemExit("no free random port")
PY
)"
  readonly CLOSED_PORT="$(python3 - <<'PY'
import random, socket
for _ in range(1000):
    port = random.randrange(10000, 60000)
    with socket.socket() as sock:
        try: sock.bind(("127.0.0.1", port))
        except OSError: continue
        print(port); break
else: raise SystemExit("no free random port")
PY
)"
  export CONFIG_FILE="$RUNTIME/config.yaml"
  export APP__INFRA__SECRET_FILE="$RUNTIME/indexer-secret"
  export APP__INFRA__SPO_NODE__BLOCKFROST_ID_FILE="$RUNTIME/blockfrost-id"
  export APP__INFRA__STORAGE__CNN_URL="$RUNTIME/indexer.sqlite"
  export APP__INFRA__STORAGE__MAX_CONNECTIONS=8
  export APP__INFRA__LEDGER_DB__CNN_URL="$RUNTIME/ledger-db.sqlite"
  export APP__INFRA__API__ADDRESS=127.0.0.1
  export APP__INFRA__API__PORT="$PORT"
  export APP__INFRA__NODE__URL="ws://127.0.0.1:${CLOSED_PORT}"
  export APP__INFRA__NODE__RECONNECT_MAX_DELAY=100ms
  export APP__INFRA__NODE__RECONNECT_MAX_ATTEMPTS=600
  export APP__INFRA__SPO_NODE__URL="ws://127.0.0.1:${CLOSED_PORT}"
  export APP__INFRA__SPO_NODE__RECONNECT_MAX_DELAY=100ms
  export APP__INFRA__SPO_NODE__RECONNECT_MAX_ATTEMPTS=600

  start_indexer() {
    "$BINARY" >"$RUNTIME/indexer.log" 2>&1 &
    INDEXER_PID=$!
    for _ in $(seq 1 120); do
      if ! kill -0 "$INDEXER_PID" 2>/dev/null; then
        cat "$RUNTIME/indexer.log" >&2
        return 1
      fi
      if curl -fsS -H 'content-type: application/json' --data '{"query":"{ __typename }"}' "http://127.0.0.1:${PORT}/api/v4/graphql" | grep -F '"data"' >/dev/null; then
        return 0
      fi
      sleep 0.5
    done
    return 1
  }
  stop_indexer() {
    kill -TERM "$INDEXER_PID"
    set +e
    wait "$INDEXER_PID"
    INDEXER_EXIT=$?
    set -e
    case "$INDEXER_EXIT" in 0|1|143) ;; *) echo "unexpected shutdown status $INDEXER_EXIT" >&2; return 1 ;; esac
  }
  start_indexer
  python3 - "$PORT" <<'PY'
import concurrent.futures, json, sys, urllib.request
port = int(sys.argv[1])
body = json.dumps({"query": "{ __typename }"}).encode()
def probe(_):
    request = urllib.request.Request(f"http://127.0.0.1:{port}/api/v4/graphql", data=body, headers={"content-type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        value = json.load(response)
    if not value.get("data", {}).get("__typename"): raise RuntimeError(value)
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    list(pool.map(probe, range(64)))
PY
  test "$(sqlite3 "$RUNTIME/indexer.sqlite" 'PRAGMA journal_mode;')" = wal
  kill -0 "$INDEXER_PID"
  stop_indexer
  readonly FIRST_EXIT="$INDEXER_EXIT"
  start_indexer
  kill -0 "$INDEXER_PID"
  stop_indexer
  readonly SECOND_EXIT="$INDEXER_EXIT"
  if grep -Ei 'pool timed out while waiting|database is locked|SQLITE_BUSY' "$RUNTIME/indexer.log" >/dev/null; then
    echo "fatal SQLite/pool regression found" >&2
    exit 2
  fi
  python3 - "$WORK/runtime-evidence.json" "$PORT" "$FIRST_EXIT" "$SECOND_EXIT" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
  "schemaVersion": "phase5-indexer-runtime-evidence-v1",
  "graphql": {"path": "/api/v4/graphql", "portPolicy": "random-free-above-10000", "concurrentRequests": 64, "maxWorkers": 8},
  "sqlite": {"journalMode": "wal", "maxConnections": 8, "fatalBusyOrPoolErrors": 0},
  "regression": "indexer_common::infra::pool::sqlite::tests::concurrent_write_transactions_never_hit_busy_errors passed",
  "process": {"aliveAfterConcurrency": True, "firstShutdownExit": int(sys.argv[3]), "restartReady": True, "secondShutdownExit": int(sys.argv[4])}
}, sort_keys=True, indent=2) + "\n")
PY
else
  python3 - "$WORK/runtime-evidence.json" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({"schemaVersion":"phase5-indexer-runtime-evidence-v1","reproducibilityBuildOnly":True,"runtimeGatesExecutedByIndependentBuild":1}, sort_keys=True, indent=2) + "\n")
PY
fi

cp "$BINARY" "$WORK/package/$INNER/$INNER"
chmod 0755 "$WORK/package/$INNER/$INNER"
readonly BIN_SHA="$(python3 - "$WORK/package/$INNER/$INNER" <<'PY'
import hashlib, pathlib, sys
print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
readonly BIN_SIZE="$(python3 - "$WORK/package/$INNER/$INNER" <<'PY'
import pathlib, sys
print(pathlib.Path(sys.argv[1]).stat().st_size)
PY
)"
cat >"$WORK/members.json" <<EOF
{"schemaVersion":"member-manifest-v1","members":[{"path":"${INNER}","type":"file","mode":"0755","size":${BIN_SIZE},"sha256":"${BIN_SHA}"}]}
EOF
python3 scripts/package_deterministic.py \
  --input-dir "$WORK/package/$INNER" \
  --members "$WORK/members.json" \
  --output "$STAGE/payload/$ARCHIVE"

cat >"$WORK/archive-policy.json" <<EOF
{"schemaVersion":"archive-policy-v1","container":"zip","maxCompressedBytes":536870912,"maxExpandedBytes":1073741824,"maxMembers":1,"maxExpansionRatio":20,"expectedMembers":[{"path":"${INNER}","type":"file","mode":"0755","size":${BIN_SIZE},"sha256":"${BIN_SHA}"}]}
EOF
python3 scripts/validate_archive.py \
  --archive "$STAGE/payload/$ARCHIVE" \
  --policy "$WORK/archive-policy.json" \
  --scratch-parent "$WORK"

(
  cd "$SOURCE"
  cargo metadata --locked --format-version 1 > "$WORK/cargo-metadata.json"
)
cp "$SOURCE/Cargo.lock" "$WORK/Cargo.lock"
python3 scripts/phase5_indexer_evidence.py \
  --metadata "$WORK/cargo-metadata.json" \
  --binary "$WORK/package/$INNER/$INNER" \
  --archive "$STAGE/payload/$ARCHIVE" \
  --build-log "$LOG" \
  --native-evidence "$WORK/native-evidence.json" \
  --runtime-evidence "$WORK/runtime-evidence.json" \
  --signing-evidence "$WORK/signing-evidence.json" \
  --license "$SOURCE/LICENSE" \
  --output "$STAGE/evidence" \
  --os "$PHASE5_OS" --arch "$PHASE5_ARCH" --attempt "$PHASE5_ATTEMPT"

python3 - "$STAGE" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
assert len(list((root / "payload").iterdir())) == 1
assert (root / "result.json").is_file()
assert not any(path.name in {"target", "source", ".cargo"} for path in root.rglob("*"))
PY

echo "Phase-5 native build complete: ${PHASE5_OS}/${PHASE5_ARCH} build ${PHASE5_ATTEMPT}"
