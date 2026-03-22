#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
YAML_FILE="${SCRIPT_DIR}/fnp-daemon.yaml"
ACTION="${1:-deploy}"

usage() {
    cat <<'EOF'
Usage:
  k8s/fnp-daemon/deploy.sh deploy
  k8s/fnp-daemon/deploy.sh delete
  k8s/fnp-daemon/deploy.sh restart
  k8s/fnp-daemon/deploy.sh status
  k8s/fnp-daemon/deploy.sh logs [pod-name]
EOF
}

get_first_pod() {
    kubectl get pods -l app=fnp-daemon \
        -o jsonpath='{.items[0].metadata.name}'
}

case "${ACTION}" in
    deploy|apply)
        kubectl apply -f "${YAML_FILE}"
        ;;
    delete|remove|uninstall)
        kubectl delete -f "${YAML_FILE}"
        ;;
    restart)
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
        kubectl exec -it "${POD_NAME}" -- tail -n 200 -f /root/fnp/fnp-daemon.log
        ;;
    *)
        usage >&2
        exit 1
        ;;
esac
