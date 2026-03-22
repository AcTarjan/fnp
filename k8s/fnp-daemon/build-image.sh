#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/../.." && pwd)

docker build \
  -f "${REPO_ROOT}/k8s/fnp-daemon/Dockerfile" \
  -t fnp-daemon:v1 \
  "${REPO_ROOT}"
