#!/bin/bash
# Data Plane MACsec Overhead (E5) - Launcher
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KUBECONFIG="${SCRIPT_DIR}/../upm-nemo-kubeconfig.yaml"
export KUBECONFIG

echo "============================================================"
echo " Data Plane MACsec Overhead (E5) - Setup & Execution"
echo " $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"

# Ensure port-forward to RabbitMQ
echo "[*] Setting up RabbitMQ port-forward..."
kubectl port-forward svc/nemo-rabbitmq -n nemo-sec 5672:5672 &>/dev/null &
PF_PID=$!
cleanup() {
    echo "[*] Cleaning up..."
    kill $PF_PID 2>/dev/null || true
}
trap cleanup EXIT
sleep 3

# Setup Python environment
cd "$SCRIPT_DIR"
if command -v python3 &>/dev/null; then
    PYTHON=python3
else
    PYTHON=python
fi

if [ ! -d .venv ]; then
    echo "[*] Creating virtual environment..."
    $PYTHON -m venv .venv 2>/dev/null || true
fi

if [ -f .venv/bin/activate ]; then
    source .venv/bin/activate
    pip install -q -r requirements.txt 2>/dev/null || pip install pyyaml numpy pandas scipy matplotlib pika
else
    echo "[!] venv not available, using system Python"
    pip3 install --user -q pyyaml numpy pandas scipy matplotlib pika 2>/dev/null || true
fi

echo "[*] Running Data Plane MACsec evaluation..."
echo "[!] WARNING: This test is time-intensive (~hours depending on iperf3 duration)"
$PYTHON run_security_dataplane.py "$@"
echo "[✓] Done. Results in results/"
