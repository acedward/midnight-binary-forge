#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'usage: probe_phase4_toolkit.sh <binary> <evidence-directory>' >&2
  exit 2
fi

binary=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
evidence=$2
mkdir -p "$evidence"
work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/phase4-toolkit-probe.XXXXXX")
trap 'find "$work" -depth -delete' EXIT

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

export LC_ALL=C
export TZ=UTC
cd "$work"
"$binary" version >"$evidence/version.stdout" 2>"$evidence/version.stderr"
test ! -s "$evidence/version.stderr"
grep -Fq '2.0.0' "$evidence/version.stdout"
grep -Fq '7.0.3' "$evidence/version.stdout"
grep -Fq '0.31.0-6587676a9bb2' "$evidence/version.stdout"
"$binary" --help >"$evidence/help.stdout" 2>"$evidence/help.stderr"
test ! -s "$evidence/help.stderr"

"$binary" show-address \
  --network undeployed \
  --seed 0000000000000000000000000000000000000000000000000000000000000001 \
  --unshielded >"$evidence/show-address.stdout" 2>"$evidence/show-address.stderr"
test ! -s "$evidence/show-address.stderr"
printf 'mn_addr_undeployed1h3ssm5ru2t6eqy4g3she78zlxn96e36ms6pq996aduvmateh9p9sk96u7s\n' >"$work/expected-address"
cmp "$work/expected-address" "$evidence/show-address.stdout"
test "$(wc -c <"$evidence/show-address.stdout" | tr -d ' ')" = 78
test "$(sha256_file "$evidence/show-address.stdout")" = 6387f62fb1d77d0b2ece8e2931265485cdb585a4d85fd32515229c64404206c8

set +e
"$binary" show-address --network undeployed --unshielded >"$evidence/missing-seed.stdout" 2>"$evidence/missing-seed.stderr"
status=$?
set -e
test "$status" = 2
test ! -s "$evidence/missing-seed.stdout"
test "$(sha256_file "$evidence/missing-seed.stderr")" = 9f064fa173e49cfb3a74b161334e35d0ef787e200699b788c6921419ff01ca28
printf 'missingSeedExit=%s\n' "$status" >"$evidence/probe-summary.txt"
for probe_file in "$evidence"/*; do
  printf '%s  %s\n' "$(sha256_file "$probe_file")" "$(basename "$probe_file")" >>"$evidence/probe-summary.txt"
done
