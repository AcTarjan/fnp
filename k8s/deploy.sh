#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)
YAML_FILE="${SCRIPT_DIR}/fnp-daemon.yaml"
ACTION="${1:-deploy}"
IMAGE_NAME="${FNP_DAEMON_IMAGE:-fnp-daemon:v1}"
DOCKERFILE_PATH="${SCRIPT_DIR}/Dockerfile"
HOST_BUILD_SCRIPT="${REPO_ROOT}/build.sh"
HOST_DAEMON_BIN="${SCRIPT_DIR}/fnp-daemon"

usage() {
    cat <<'EOF'
Usage:
  k8s/deploy.sh deploy
  k8s/deploy.sh rebuild
  k8s/deploy.sh delete
  k8s/deploy.sh restart
  k8s/deploy.sh status
  k8s/deploy.sh logs [pod-name]
EOF
}

get_first_pod() {
    kubectl get pods -l app=fnp-daemon \
        -o jsonpath='{.items[0].metadata.name}'
}

ensure_host_artifacts() {
    if [[ -x "${HOST_DAEMON_BIN}" ]]; then
        return 0
    fi

    echo "host artifact missing: ${HOST_DAEMON_BIN}"
    echo "running ${HOST_BUILD_SCRIPT} to build fnp..."
    bash "${HOST_BUILD_SCRIPT}"
}

ensure_image() {
    if docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
        return 0
    fi

    echo "docker image not found: ${IMAGE_NAME}"
    ensure_host_artifacts
    docker build -f "${DOCKERFILE_PATH}" -t "${IMAGE_NAME}" "${REPO_ROOT}"
}

rebuild_image() {
    echo "rebuilding host artifacts..."
    bash "${HOST_BUILD_SCRIPT}"

    if docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
        echo "removing existing image: ${IMAGE_NAME}"
        docker image rm -f "${IMAGE_NAME}"
    fi

    docker build -f "${DOCKERFILE_PATH}" -t "${IMAGE_NAME}" "${REPO_ROOT}"
}

case "${ACTION}" in
    deploy|apply)
        ensure_image
        kubectl apply -f "${YAML_FILE}"
        ;;
    rebuild)
        rebuild_image
        ;;
    delete|remove|uninstall)
        kubectl delete -f "${YAML_FILE}"
        ;;
    restart)
        ensure_image
        kubectl delete -f "${YAML_FILE}" --ignore-not-found
        kubectl apply -f "${YAML_FILE}"
        ;;
    status)
        kubectl get daemonset fnp-daemon
        kubectl get pods -l app=fnp-daemon -o wide
        ;;
    logs)
        POD_NAME="${2:-$(get_first_pod)}"
        if [[ -z "${POD_NAME}" ]]; then
            echo "no fnp-daemon pod found" >&2
            exit 1
        fi
        kubectl logs -f "${POD_NAME}"
        ;;
    *)
        usage >&2
        exit 1
        ;;
esac
