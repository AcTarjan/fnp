#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  ./build.sh [build|publish] [--tag TAG] [--mode MODE] [--daemon-dpdk-link MODE]

Actions:
  build                 Build fnp-daemon and static libfnp-api.a (default)
  publish               Build, package, and publish the archive to GitHub Release

Options:
  --tag TAG             Package / release tag. Default: latest
  --mode MODE           Build mode: release or debug. Default: release
  --daemon-dpdk-link    fnp-daemon DPDK link mode: static or dynamic. Default: static
  -h, --help            Show this help message

Notes:
  - GitHub repository defaults to: AcTarjan/fnp-dist
  - publish uploads the generated archive in ./build rather than source code
  - publish only keeps a fixed-name archive: fnp-linux-amd64.tar.gz
  - Advanced paths can still be overridden via env:
      BUILD_DIR, DPDK_DIR, FNP_BUILD_MODE, FNP_DAEMON_DPDK_LINK_MODE, GITHUB_REPO
EOF
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT="${SCRIPT_DIR}"

ACTION="build"
if [[ $# -gt 0 && "${1}" != --* && "${1}" != "-h" ]]; then
    ACTION="$1"
    shift
fi

case "${ACTION}" in
    build|publish)
        ;;
    *)
        echo "unknown action: ${ACTION}" >&2
        usage >&2
        exit 1
        ;;
esac

BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/build}"
DPDK_DIR="${DPDK_DIR:-/opt/dpdk}"
BUILD_MODE="${FNP_BUILD_MODE:-release}"
BUILD_TYPE="${CMAKE_BUILD_TYPE:-Release}"
DAEMON_DPDK_LINK_MODE="${FNP_DAEMON_DPDK_LINK_MODE:-static}"
GITHUB_REPO="${GITHUB_REPO:-AcTarjan/fnp-dist}"
OUTPUT_STATIC_LIB="${BUILD_DIR}/libfnp-api.a"
TAG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag)
            [[ $# -ge 2 ]] || { echo "missing value for --tag" >&2; exit 1; }
            TAG="$2"
            shift 2
            ;;
        --mode)
            [[ $# -ge 2 ]] || { echo "missing value for --mode" >&2; exit 1; }
            BUILD_MODE="$2"
            shift 2
            ;;
        --daemon-dpdk-link)
            [[ $# -ge 2 ]] || { echo "missing value for --daemon-dpdk-link" >&2; exit 1; }
            DAEMON_DPDK_LINK_MODE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

case "${BUILD_MODE}" in
    release)
        BUILD_TYPE="Release"
        ;;
    debug)
        BUILD_TYPE="Debug"
        ;;
    *)
        echo "invalid --mode value: ${BUILD_MODE}" >&2
        echo "expected: release or debug" >&2
        exit 1
        ;;
esac

case "${DAEMON_DPDK_LINK_MODE}" in
    static)
        FNP_DAEMON_STATIC_DPDK=ON
        ;;
    dynamic)
        FNP_DAEMON_STATIC_DPDK=OFF
        ;;
    *)
        echo "invalid --daemon-dpdk-link value: ${DAEMON_DPDK_LINK_MODE}" >&2
        echo "expected: static or dynamic" >&2
        exit 1
        ;;
esac

if [[ -z "${TAG}" ]]; then
    TAG="latest"
fi

PACKAGE_NAME="fnp-${TAG}-linux-amd64"
PACKAGE_ROOT_DIR="${BUILD_DIR}/${PACKAGE_NAME}"
LATEST_ARCHIVE_NAME="fnp-linux-amd64.tar.gz"
LATEST_ARCHIVE="${BUILD_DIR}/${LATEST_ARCHIVE_NAME}"

build_outputs() {
    cmake -S "${REPO_ROOT}" -B "${BUILD_DIR}" \
        -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
        -DDPDK_DIR="${DPDK_DIR}" \
        -DFNP_DAEMON_STATIC_DPDK="${FNP_DAEMON_STATIC_DPDK}"

    # Avoid Makefile ordering issues around the custom fnp-api static archive rule by
    # building only the required targets in a stable order.
    cmake --build "${BUILD_DIR}" --target fnp-api-obj -j1
    cmake --build "${BUILD_DIR}" --target fnp-api-static -j1
    cmake --build "${BUILD_DIR}" --target fnp-daemon -j"$(nproc)"

    rm -rf "${BUILD_DIR}/conf"
    cp -a "${REPO_ROOT}/k8s/conf" "${BUILD_DIR}/conf"

    echo "built fnp-daemon: ${BUILD_DIR}/fnp-daemon"
    echo "build mode: ${BUILD_MODE}"
    echo "fnp-daemon DPDK link mode: ${DAEMON_DPDK_LINK_MODE}"
    echo "built static library:"
    echo "  ${OUTPUT_STATIC_LIB}"
    echo "copied config directory:"
    echo "  ${BUILD_DIR}/conf"
}

create_package() {
    local include_dir="${PACKAGE_ROOT_DIR}/inc"
    local lib_dir="${PACKAGE_ROOT_DIR}/lib"
    local k8s_dir="${PACKAGE_ROOT_DIR}/k8s"

    rm -rf "${PACKAGE_ROOT_DIR}"
    install -d "${include_dir}" "${lib_dir}" "${k8s_dir}"

    cp -a "${REPO_ROOT}/inc/." "${include_dir}/"
    install -m 0644 "${OUTPUT_STATIC_LIB}" "${lib_dir}/libfnp-api.a"
    cp -a "${REPO_ROOT}/k8s/." "${k8s_dir}/"
    install -m 0755 "${BUILD_DIR}/fnp-daemon" "${k8s_dir}/fnp-daemon"

    rm -f "${LATEST_ARCHIVE}"
    install -d "${BUILD_DIR}"
    tar -C "${BUILD_DIR}" -czf "${LATEST_ARCHIVE}" "${PACKAGE_NAME}"

    echo "created package directory: ${PACKAGE_ROOT_DIR}"
    echo "created package archive: ${LATEST_ARCHIVE}"
}

publish_package() {
    command -v gh >/dev/null 2>&1 || { echo "gh CLI is required for publish" >&2; exit 1; }
    gh auth status >/dev/null 2>&1 || {
        echo "gh is not authenticated; run: gh auth login" >&2
        exit 1
    }

    if gh release view "${TAG}" --repo "${GITHUB_REPO}" >/dev/null 2>&1; then
        gh release upload "${TAG}" "${LATEST_ARCHIVE}" --repo "${GITHUB_REPO}" --clobber
        echo "uploaded asset to existing release: ${GITHUB_REPO} ${TAG}"
    else
        gh release create "${TAG}" "${LATEST_ARCHIVE}" \
            --repo "${GITHUB_REPO}" \
            --title "${TAG}" \
            --generate-notes
        echo "created release and uploaded asset: ${GITHUB_REPO} ${TAG}"
    fi

    echo "latest package URL:"
    echo "  https://github.com/${GITHUB_REPO}/releases/latest/download/${LATEST_ARCHIVE_NAME}"
}

build_outputs

if [[ "${ACTION}" == "publish" ]]; then
    create_package
    publish_package
fi
