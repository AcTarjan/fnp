#!/usr/bin/env bash
# build_image.sh - Build fnp_node_perf_demo, package into Docker image, load to server 231
#
# Usage:
#   ./build_image.sh [SERVER...]
#   IMAGE_TAG=fnp-perf:mytag ./build_image.sh
#
# Default server: 10.38.1.231
# Default IMAGE_TAG: fnp-perf:YYYYMMDD-HHMMSS

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FNP_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FNP_BUILD="${FNP_BUILD_DIR:-${FNP_DIR}/build-server1-dpdk2203}"
IMAGE_TAG="${IMAGE_TAG:-fnp-perf:$(date +%Y%m%d-%H%M%S)}"
CONTEXT_DIR="${SCRIPT_DIR}/_build_context"

if (($#)); then
    SERVERS=("$@")
else
    SERVERS=("10.38.1.231")
fi

echo "=== [1/4] build fnp_node_perf_demo ==="
(cd "${FNP_BUILD}" && make fnp_node_perf_demo -j"$(nproc)")

echo "=== [2/4] prepare Docker build context ==="
rm -rf "${CONTEXT_DIR}"
mkdir -p "${CONTEXT_DIR}/bin" "${CONTEXT_DIR}/conf"

cp "${SCRIPT_DIR}/Dockerfile.fnp-perf"   "${CONTEXT_DIR}/Dockerfile"
cp "${FNP_BUILD}/fnp-daemon"             "${CONTEXT_DIR}/bin/fnp-daemon"
cp "${FNP_BUILD}/fnp_node_perf_demo"     "${CONTEXT_DIR}/bin/fnp_node_perf_demo"
cp "${SCRIPT_DIR}/run_perf.sh"           "${CONTEXT_DIR}/bin/run_perf.sh"
cp "${SCRIPT_DIR}/analyze_rtt.py"        "${CONTEXT_DIR}/bin/analyze_rtt.py"
cp -a "${SCRIPT_DIR}/conf/."             "${CONTEXT_DIR}/conf/"

{
    echo "built_at=$(date --iso-8601=seconds)"
    echo "image_tag=${IMAGE_TAG}"
    echo "fnp_build_dir=${FNP_BUILD}"
    echo "fnp_dpdk_dir=$(grep -E '^DPDK_DIR:' "${FNP_BUILD}/CMakeCache.txt" 2>/dev/null | cut -d= -f2- || echo unknown)"
    sha256sum "${CONTEXT_DIR}/bin/fnp-daemon" \
              "${CONTEXT_DIR}/bin/fnp_node_perf_demo"
} > "${CONTEXT_DIR}/conf/build-artifacts.txt"

echo "=== [3/4] docker build: ${IMAGE_TAG} ==="
docker build --pull=false -t "${IMAGE_TAG}" "${CONTEXT_DIR}"

echo "=== [4/4] load to servers ==="
IMAGE_TAR="/tmp/${IMAGE_TAG//[:\/]/-}.tar"
docker save "${IMAGE_TAG}" -o "${IMAGE_TAR}"

for server in "${SERVERS[@]}"; do
    echo "  -> ${server}"
    scp "${IMAGE_TAR}" "root@${server}:/tmp/$(basename "${IMAGE_TAR}")"
    ssh "root@${server}" \
        "docker load -i /tmp/$(basename "${IMAGE_TAR}") \
         && rm -f /tmp/$(basename "${IMAGE_TAR}") \
         && docker image inspect '${IMAGE_TAG}' \
                  --format 'loaded {{.RepoTags}} size={{.Size}}'"
done

rm -f "${IMAGE_TAR}"
echo ""
echo "image: ${IMAGE_TAG}"
echo "done"
