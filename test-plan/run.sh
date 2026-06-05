#!/usr/bin/env bash
# ===========================================================================
# Test Plan Execution Launcher
# ===========================================================================
# Usage:
#   ./run.sh                    # Full execution
#   ./run.sh --dry-run          # Print plan without executing
#   ./run.sh --configs mNCC     # Run only mNCC configuration
#   ./run.sh --help             # Show all options
# ===========================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"

echo "============================================================"
echo " Provisioning Test Plan - Setup & Execution"
echo " $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"

# --- Create virtual environment if it doesn't exist ---
if [ ! -d "${VENV_DIR}" ]; then
    echo "[*] Creating Python virtual environment..."
    if python3 -m venv "${VENV_DIR}" 2>/dev/null; then
        echo "[*] Virtual environment created."
    else
        echo "[*] venv creation failed, using system Python."
        VENV_DIR=""
    fi
fi

# --- Activate and install dependencies ---
if [ -n "${VENV_DIR}" ] && [ -f "${VENV_DIR}/bin/activate" ]; then
    source "${VENV_DIR}/bin/activate"
    echo "[*] Installing dependencies..."
    pip install --quiet --upgrade pip
    pip install --quiet -r "${SCRIPT_DIR}/requirements.txt"
else
    echo "[*] Using system Python, verifying dependencies..."
    pip3 install --quiet -r "${SCRIPT_DIR}/requirements.txt" 2>/dev/null || \
        echo "[WARN] Some dependencies may be missing. Run: pip3 install -r requirements.txt"
fi

# --- Verify cluster access ---
KUBECONFIG_PATH="${SCRIPT_DIR}/../upm-nemo-kubeconfig.yaml"
echo "[*] Verifying cluster access (kubeconfig: ${KUBECONFIG_PATH})..."
if ! kubectl --kubeconfig "${KUBECONFIG_PATH}" cluster-info --request-timeout=10s > /dev/null 2>&1; then
    echo "[ERROR] Cannot connect to Kubernetes cluster. Check kubeconfig."
    exit 1
fi

NODE_COUNT=$(kubectl --kubeconfig "${KUBECONFIG_PATH}" get nodes --no-headers 2>/dev/null | wc -l)
echo "[*] Cluster nodes detected: ${NODE_COUNT}"
if [ "${NODE_COUNT}" -lt 6 ]; then
    echo "[WARNING] Expected 6 nodes, found ${NODE_COUNT}."
fi

# --- Ensure required namespaces exist ---
kubectl --kubeconfig "${SCRIPT_DIR}/../upm-nemo-kubeconfig.yaml" create namespace workloads --dry-run=client -o yaml | \
  kubectl --kubeconfig "${SCRIPT_DIR}/../upm-nemo-kubeconfig.yaml" apply -f - 2>/dev/null || true
kubectl --kubeconfig "${SCRIPT_DIR}/../upm-nemo-kubeconfig.yaml" create namespace cicd-sim --dry-run=client -o yaml | \
  kubectl --kubeconfig "${SCRIPT_DIR}/../upm-nemo-kubeconfig.yaml" apply -f - 2>/dev/null || true

# --- Verify mNCC RabbitMQ connectivity ---
echo "[*] mNCC communication via RabbitMQ (configured in config.yaml)"
echo "[*] Kubeconfig: ${SCRIPT_DIR}/../upm-nemo-kubeconfig.yaml"

# --- Start port-forward to RabbitMQ ---
echo "[*] Starting port-forward to RabbitMQ (nemo-rabbitmq in nemo-sec)..."
kubectl --kubeconfig "${KUBECONFIG_PATH}" port-forward svc/nemo-rabbitmq -n nemo-sec 5672:5672 --address=127.0.0.1 &
PF_PID=$!
sleep 3
if ! nc -z 127.0.0.1 5672 2>/dev/null; then
    echo "[WARNING] RabbitMQ port-forward may not be ready. Waiting..."
    sleep 5
fi
echo "[*] RabbitMQ port-forward active (PID: ${PF_PID})"

# Cleanup function
cleanup() {
    echo "[*] Stopping port-forward (PID: ${PF_PID})..."
    kill "${PF_PID}" 2>/dev/null || true
}
trap cleanup EXIT

# --- Execute test plan ---
echo ""
echo "[*] Launching test plan..."
echo "------------------------------------------------------------"
python3 "${SCRIPT_DIR}/run_test_plan.py" "$@"

echo ""
echo "============================================================"
echo " Execution finished at $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
