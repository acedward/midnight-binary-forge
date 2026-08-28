#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: phase4_sbom.sh <binary> <output-prefix> <linux|macos> <amd64|arm64>" >&2
  exit 2
fi

binary=$1
output_prefix=$2
os_name=$3
arch=$4
case "${os_name}/${arch}" in
  linux/amd64)
    asset=syft_1.51.1_linux_amd64.tar.gz
    size=29203595
    digest=8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3
    ;;
  linux/arm64)
    asset=syft_1.51.1_linux_arm64.tar.gz
    size=26668605
    digest=a7fd2b784e6664acd44719270574f6cd8c6864fc2b1700bf9099bd1cccda7d7f
    ;;
  macos/arm64)
    asset=syft_1.51.1_darwin_arm64.tar.gz
    size=27907057
    digest=ac063af3b9874769deb7ea1e6d76841e68f9e3bb50cd654226fc977de65532c1
    ;;
  *)
    echo "unsupported native Syft tuple: ${os_name}/${arch}" >&2
    exit 2
    ;;
esac

scratch="${RUNNER_TEMP:?}/phase4-syft-${os_name}-${arch}"
test ! -e "$scratch"
mkdir -p "$scratch/download" "$scratch/tool"
python3 scripts/fetch_verified.py \
  --url "https://github.com/anchore/syft/releases/download/v1.51.1/${asset}" \
  --output "$scratch/download/$asset" \
  --size "$size" \
  --sha256 "$digest"
members=$(tar -tzf "$scratch/download/$asset")
printf '%s\n' "$members" | grep -Fxq syft
if printf '%s\n' "$members" | grep -Eq '(^/|(^|/)\.\.(/|$)|\\)'; then
  echo 'unsafe Syft archive member' >&2
  exit 2
fi
tar -xzf "$scratch/download/$asset" --no-same-owner --no-same-permissions -C "$scratch/tool" syft
chmod 0755 "$scratch/tool/syft"
"$scratch/tool/syft" version
mkdir -p "$(dirname "$output_prefix")"
"$scratch/tool/syft" scan "file:$binary" \
  -o "spdx-json=${output_prefix}.spdx.json" \
  -o "cyclonedx-json=${output_prefix}.cyclonedx.json"
python3 -m json.tool "${output_prefix}.spdx.json" >/dev/null
python3 -m json.tool "${output_prefix}.cyclonedx.json" >/dev/null
