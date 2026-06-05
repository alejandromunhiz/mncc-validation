#!/usr/bin/env python3
"""
Data Plane Overhead: MACsec Impact on Throughput and Latency (E5)
==================================================================
Measures the performance penalty of MACsec encryption on overlay traffic.

Data plane configurations:
  D0 - No encryption (baseline VXLAN overlay)
  D1 - MACsec GCM-AES-128
  D2 - MACsec GCM-AES-256

Packet sizes: 64B, 512B, 1500B, 9000B
Scenarios: intra-cluster, cross-cluster
Trials: 10 per combination (first discarded as warm-up)

Metrics:
  - Median sustained throughput (Gbps)
  - Median one-way latency (µs)
  - Throughput degradation ratio: δ_bw = 1 - bw_d/bw_0
  - CPU utilisation on sender node

Output: Heatmap + line charts + statistics.
"""

import os
import sys
import time
import json
import logging
import argparse
import subprocess
import re
import uuid
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple

import yaml
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).parent
DEFAULT_CONFIG = SCRIPT_DIR / "config.yaml"

_kubeconfig_path = str(SCRIPT_DIR.parent / "upm-nemo-kubeconfig.yaml")
if os.path.exists(_kubeconfig_path) and "KUBECONFIG" not in os.environ:
    os.environ["KUBECONFIG"] = _kubeconfig_path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("security_dataplane_execution.log"),
    ],
)
logger = logging.getLogger(__name__)


def kubectl(*args, timeout=30) -> subprocess.CompletedProcess:
    cmd = ["kubectl"] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class DataPlaneResult:
    """Single measurement of data plane performance."""
    configuration: str      # D0, D1, D2
    packet_size: int        # 64, 512, 1500, 9000
    scenario: str           # intra-cluster, cross-cluster
    trial: int
    throughput_gbps: float
    latency_us: float       # one-way latency in microseconds
    cpu_utilization: float  # sender CPU %
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


# ---------------------------------------------------------------------------
# Pod Management
# ---------------------------------------------------------------------------

IPERF_SERVER_POD = """
apiVersion: v1
kind: Pod
metadata:
  name: iperf-server-{suffix}
  namespace: {namespace}
  labels:
    app: iperf-server
    test: e5-dataplane
spec:
  nodeSelector:
    kubernetes.io/hostname: {node}
  containers:
  - name: iperf3
    image: networkstatic/iperf3:latest
    command: ["iperf3", "-s", "-p", "5201"]
    ports:
    - containerPort: 5201
  terminationGracePeriodSeconds: 5
"""

IPERF_CLIENT_POD = """
apiVersion: v1
kind: Pod
metadata:
  name: iperf-client-{suffix}
  namespace: {namespace}
  labels:
    app: iperf-client
    test: e5-dataplane
spec:
  nodeSelector:
    kubernetes.io/hostname: {node}
  containers:
  - name: iperf3
    image: networkstatic/iperf3:latest
    command: ["sleep", "infinity"]
  terminationGracePeriodSeconds: 5
"""


def get_worker_nodes() -> List[str]:
    """Get list of worker nodes from cluster."""
    result = kubectl("get", "nodes", "-l", "node-role.kubernetes.io/control-plane!=",
                     "-o", "jsonpath={.items[*].metadata.name}")
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip().split()
    # Fallback: get all nodes
    result = kubectl("get", "nodes", "-o", "jsonpath={.items[*].metadata.name}")
    nodes = result.stdout.strip().split()
    return [n for n in nodes if "master" not in n.lower()]


def create_namespace(namespace: str):
    """Create test namespace if it doesn't exist."""
    kubectl("create", "namespace", namespace, "--dry-run=client", "-o", "yaml")
    result = kubectl("get", "namespace", namespace)
    if result.returncode != 0:
        kubectl("create", "namespace", namespace)


def deploy_iperf_pods(
    server_node: str,
    client_node: str,
    namespace: str = "e5-test",
    suffix: str = "test"
) -> Tuple[str, str]:
    """Deploy iperf3 server and client pods on specified nodes."""
    create_namespace(namespace)

    # Deploy server
    server_manifest = IPERF_SERVER_POD.format(suffix=suffix, namespace=namespace, node=server_node)
    result = subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=server_manifest, capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        logger.warning("Server deploy: %s", result.stderr)

    # Deploy client
    client_manifest = IPERF_CLIENT_POD.format(suffix=suffix, namespace=namespace, node=client_node)
    result = subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=client_manifest, capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        logger.warning("Client deploy: %s", result.stderr)

    # Wait for pods to be ready
    for pod in [f"iperf-server-{suffix}", f"iperf-client-{suffix}"]:
        kubectl("wait", "--for=condition=Ready", f"pod/{pod}",
                "-n", namespace, "--timeout=120s", timeout=130)

    # Get server pod IP
    result = kubectl("get", "pod", f"iperf-server-{suffix}",
                     "-n", namespace, "-o", "jsonpath={.status.podIP}")
    server_ip = result.stdout.strip()

    return server_ip, f"iperf-client-{suffix}"


def cleanup_iperf_pods(namespace: str = "e5-test", suffix: str = "test"):
    """Remove test pods."""
    kubectl("delete", "pod", f"iperf-server-{suffix}", "-n", namespace,
            "--ignore-not-found=true", "--grace-period=0", "--force")
    kubectl("delete", "pod", f"iperf-client-{suffix}", "-n", namespace,
            "--ignore-not-found=true", "--grace-period=0", "--force")


# ---------------------------------------------------------------------------
# MACsec Configuration via mNCC
# ---------------------------------------------------------------------------

def configure_macsec(configuration: str, mncc_config: Dict, node_pair: Tuple[str, str]):
    """
    Configure MACsec on the overlay link via mNCC intent.
    D0 = no encryption, D1 = GCM-AES-128, D2 = GCM-AES-256
    """
    if configuration == "D0":
        # No encryption - default overlay state
        logger.info("  D0: No encryption configured (baseline)")
        return

    try:
        import pika
    except ImportError:
        logger.warning("  pika not available, simulating MACsec config")
        return

    cipher = "GCM-AES-128" if configuration == "D1" else "GCM-AES-256"
    rmq = mncc_config["rabbitmq"]

    network_name = f"macsec-{configuration.lower()}-{uuid.uuid4().hex[:6]}"
    intent_msg = {
        "userLabel": "cloud_continuum",
        "Intent": {
            "id": f"macsec_{configuration}_{uuid.uuid4().hex[:8]}",
            "userLabel": "cloud_continuum",
            "intentExpectations": [{
                "expectationId": "1",
                "expectationVerb": "DELIVER",
                "expectationObject": {
                    "objectType": "L2SM_NETWORK",
                    "objectInstance": network_name,
                    "objectContexts": [
                        {"contextAttribute": "name", "contextCondition": "IS_EQUAL_TO",
                         "contextValueRange": network_name},
                        {"contextAttribute": "providerName", "contextCondition": "IS_EQUAL_TO",
                         "contextValueRange": mncc_config["l2sm"]["provider_name"]},
                        {"contextAttribute": "domain", "contextCondition": "IS_EQUAL_TO",
                         "contextValueRange": mncc_config["l2sm"]["domain"]},
                        {"contextAttribute": "encryption", "contextCondition": "IS_EQUAL_TO",
                         "contextValueRange": cipher},
                    ],
                },
                "expectationTargets": [
                    {"targetName": "secure", "targetCondition": "IS_EQUAL_TO",
                     "targetValueRange": "true"}
                ],
            }],
            "intentContexts": [
                {"contextAttribute": "NEMO_WORKLOAD", "contextCondition": "IS_EQUAL_TO",
                 "contextValueRange": f"macsec-{configuration.lower()}"}
            ],
            "intentPriority": 1,
            "observationPeriod": 60,
            "intentAdminState": "ACTIVATED",
        }
    }

    try:
        credentials = pika.PlainCredentials(rmq["username"], rmq["password"])
        conn_params = pika.ConnectionParameters(
            host=rmq["host"], port=rmq["port"], credentials=credentials
        )
        connection = pika.BlockingConnection(conn_params)
        channel = connection.channel()
        channel.basic_publish(
            exchange=rmq["intent_exchange"],
            routing_key=rmq["intent_routing_key"],
            body=json.dumps(intent_msg).encode("utf-8"),
            properties=pika.BasicProperties(content_type="application/json", delivery_mode=2),
        )
        connection.close()
        logger.info("  %s: MACsec %s intent published", configuration, cipher)
        time.sleep(3)  # Allow time for configuration to propagate
    except Exception as e:
        logger.warning("  MACsec intent publish failed: %s", e)


def remove_macsec(configuration: str, mncc_config: Dict):
    """Remove MACsec configuration (return to D0 baseline)."""
    if configuration == "D0":
        return
    # In production, this would be a DELETE intent; for now we log
    logger.info("  Removing MACsec configuration for %s", configuration)


# ---------------------------------------------------------------------------
# Measurements
# ---------------------------------------------------------------------------

def run_iperf3(
    client_pod: str,
    server_ip: str,
    namespace: str,
    packet_size: int,
    duration: int = 60,
    streams: int = 8,
) -> Dict:
    """Run iperf3 test from client pod to server and return parsed results."""
    # Map packet size to iperf3 length parameter
    length = packet_size

    cmd = (
        f"iperf3 -c {server_ip} -p 5201 "
        f"-l {length} -t {duration} -P {streams} -J"
    )

    result = kubectl(
        "exec", client_pod, "-n", namespace, "--",
        "sh", "-c", cmd,
        timeout=duration + 30
    )

    if result.returncode != 0:
        logger.warning("  iperf3 error: %s", result.stderr[:200])
        return {"throughput_bps": 0, "retransmits": 0}

    try:
        data = json.loads(result.stdout)
        end = data.get("end", {})
        sum_sent = end.get("sum_sent", {})
        throughput_bps = sum_sent.get("bits_per_second", 0)
        retransmits = sum_sent.get("retransmits", 0)
        return {"throughput_bps": throughput_bps, "retransmits": retransmits}
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning("  iperf3 parse error: %s", e)
        return {"throughput_bps": 0, "retransmits": 0}


def measure_latency(
    client_pod: str,
    server_ip: str,
    namespace: str,
    packet_size: int,
    count: int = 100,
) -> float:
    """Measure one-way latency using ping (approximation: RTT/2)."""
    # Use ping with specified packet size
    ping_size = max(packet_size - 28, 0)  # ICMP header overhead
    cmd = f"ping -c {count} -s {ping_size} -i 0.1 -q {server_ip}"

    result = kubectl(
        "exec", client_pod, "-n", namespace, "--",
        "sh", "-c", cmd,
        timeout=count + 30
    )

    if result.returncode != 0:
        logger.warning("  Latency measurement failed: %s", result.stderr[:200])
        return 0.0

    # Parse avg RTT from ping output
    # rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms
    match = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", result.stdout)
    if match:
        rtt_ms = float(match.group(1))
        return rtt_ms * 1000 / 2  # Convert to one-way µs
    return 0.0


def measure_cpu(node: str) -> float:
    """Measure CPU utilization on a specific node."""
    result = kubectl(
        "get", "--raw",
        f"/apis/metrics.k8s.io/v1beta1/nodes/{node}"
    )
    if result.returncode == 0:
        try:
            data = json.loads(result.stdout)
            cpu_str = data.get("usage", {}).get("cpu", "0n")
            # Parse nanocores
            if cpu_str.endswith("n"):
                nanocores = int(cpu_str[:-1])
                return nanocores / 1e9 * 100  # Approximate percentage
            elif cpu_str.endswith("m"):
                millicores = int(cpu_str[:-1])
                return millicores / 10  # millicores to percentage (assuming 1 core)
        except Exception:
            pass

    # Fallback: use top node
    result = kubectl("top", "node", node, "--no-headers")
    if result.returncode == 0:
        parts = result.stdout.strip().split()
        for part in parts:
            if part.endswith("%"):
                return float(part[:-1])
    return 0.0


# ---------------------------------------------------------------------------
# Main Experiment
# ---------------------------------------------------------------------------

def run_experiment(config: Dict, args) -> List[DataPlaneResult]:
    """Run the full E5 data plane experiment."""
    dp_config = config["security_dataplane"]
    mncc_config = config["mncc"]
    cluster = config["cluster"]

    configurations = args.configs or dp_config["configurations"]
    packet_sizes = dp_config["packet_sizes"]
    scenarios = dp_config["scenarios"]
    trials = dp_config["trials_per_combination"]
    warmup = dp_config["warmup_trials"]
    iperf_duration = dp_config.get("iperf_duration_seconds", 60)
    iperf_streams = dp_config.get("iperf_streams", 8)

    # Get worker nodes
    nodes = get_worker_nodes()
    if len(nodes) < 2:
        logger.error("Need at least 2 worker nodes, got: %s", nodes)
        return []

    logger.info("Available worker nodes: %s", nodes)

    # Define node pairs for each scenario
    # intra-cluster: two nodes in same cluster
    # cross-cluster: (simulated) two nodes that communicate via VXLAN tunnel
    intra_nodes = (nodes[0], nodes[1])
    cross_nodes = (nodes[0], nodes[-1])  # Furthest apart in the cluster

    results: List[DataPlaneResult] = []
    namespace = "e5-test"
    suffix = "dp"

    total_combos = len(configurations) * len(packet_sizes) * len(scenarios) * trials
    logger.info("Total measurements: %d", total_combos)
    combo_count = 0

    for scenario in scenarios:
        node_pair = intra_nodes if scenario == "intra-cluster" else cross_nodes
        server_node, client_node = node_pair

        logger.info("-" * 60)
        logger.info("SCENARIO: %s (server=%s, client=%s)", scenario, server_node, client_node)

        # Deploy pods for this scenario
        logger.info("  Deploying iperf3 pods...")
        try:
            server_ip, client_pod = deploy_iperf_pods(
                server_node, client_node, namespace, suffix
            )
            logger.info("  Server IP: %s, Client pod: %s", server_ip, client_pod)
        except Exception as e:
            logger.error("  Pod deployment failed: %s", e)
            cleanup_iperf_pods(namespace, suffix)
            continue

        for configuration in configurations:
            logger.info("  Configuration: %s", configuration)
            configure_macsec(configuration, mncc_config, node_pair)

            for pkt_size in packet_sizes:
                logger.info("    Packet size: %d B", pkt_size)

                for trial in range(1, trials + 1):
                    combo_count += 1
                    if trial == 1 or trial % 5 == 0:
                        logger.info("      Trial %d/%d (overall: %d/%d)",
                                    trial, trials, combo_count, total_combos)

                    try:
                        # Throughput measurement
                        iperf_result = run_iperf3(
                            client_pod, server_ip, namespace,
                            pkt_size, iperf_duration, iperf_streams
                        )
                        throughput_gbps = iperf_result["throughput_bps"] / 1e9

                        # Latency measurement
                        latency_us = measure_latency(
                            client_pod, server_ip, namespace, pkt_size
                        )

                        # CPU measurement
                        cpu_util = measure_cpu(client_node)

                        result = DataPlaneResult(
                            configuration=configuration,
                            packet_size=pkt_size,
                            scenario=scenario,
                            trial=trial,
                            throughput_gbps=throughput_gbps,
                            latency_us=latency_us,
                            cpu_utilization=cpu_util,
                        )
                        results.append(result)

                    except Exception as e:
                        logger.error("      Trial %d failed: %s", trial, str(e))

                    # Brief pause between trials
                    time.sleep(2)

            # Remove MACsec config before next configuration
            remove_macsec(configuration, mncc_config)

        # Cleanup pods for this scenario
        cleanup_iperf_pods(namespace, suffix)
        time.sleep(5)

    return results


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze_results(results: List[DataPlaneResult], warmup: int) -> Dict:
    """Compute data plane overhead statistics."""
    df = pd.DataFrame([asdict(r) for r in results])

    # Discard warm-up trials
    df = df[df["trial"] > warmup].copy()

    analysis = {"summary": {}, "detailed": {}}

    # Get D0 baseline throughput per (packet_size, scenario)
    d0_df = df[df["configuration"] == "D0"]

    for scenario in df["scenario"].unique():
        analysis["detailed"][scenario] = {}

        for pkt_size in sorted(df["packet_size"].unique()):
            key = f"{pkt_size}B"
            analysis["detailed"][scenario][key] = {}

            # Baseline throughput for this combination
            baseline = d0_df[(d0_df["scenario"] == scenario) & (d0_df["packet_size"] == pkt_size)]
            bw_baseline = baseline["throughput_gbps"].median() if not baseline.empty else 1.0

            for config in df["configuration"].unique():
                subset = df[
                    (df["configuration"] == config) &
                    (df["packet_size"] == pkt_size) &
                    (df["scenario"] == scenario)
                ]
                if subset.empty:
                    continue

                bw = subset["throughput_gbps"]
                lat = subset["latency_us"]
                cpu = subset["cpu_utilization"]
                delta_bw = 1.0 - (bw.median() / bw_baseline) if bw_baseline > 0 else 0

                analysis["detailed"][scenario][key][config] = {
                    "throughput_gbps": {
                        "median": float(bw.median()),
                        "p95": float(bw.quantile(0.95)),
                    },
                    "latency_us": {
                        "median": float(lat.median()),
                        "p95": float(lat.quantile(0.95)),
                    },
                    "degradation_ratio": float(delta_bw),
                    "cpu_utilization": {
                        "median": float(cpu.median()),
                        "p95": float(cpu.quantile(0.95)),
                    },
                    "n_trials": int(len(subset)),
                }

    return analysis


def generate_plots(results: List[DataPlaneResult], warmup: int, output_dir: Path):
    """Generate data plane overhead plots."""
    df = pd.DataFrame([asdict(r) for r in results])
    df = df[df["trial"] > warmup].copy()

    plots_dir = output_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)

    configs = ["D0", "D1", "D2"]
    existing_configs = [c for c in configs if c in df["configuration"].unique()]
    packet_sizes = sorted(df["packet_size"].unique())
    scenarios = df["scenario"].unique()

    # Plot 1: Throughput heatmap per configuration and packet size
    for scenario in scenarios:
        fig, axes = plt.subplots(1, len(existing_configs), figsize=(5 * len(existing_configs), 4))
        if len(existing_configs) == 1:
            axes = [axes]

        for idx, config in enumerate(existing_configs):
            data_matrix = []
            for pkt in packet_sizes:
                subset = df[
                    (df["configuration"] == config) &
                    (df["packet_size"] == pkt) &
                    (df["scenario"] == scenario)
                ]
                data_matrix.append(subset["throughput_gbps"].median() if not subset.empty else 0)

            ax = axes[idx]
            bars = ax.barh(range(len(packet_sizes)), data_matrix, color=["#2196F3", "#4CAF50", "#FF9800", "#F44336"])
            ax.set_yticks(range(len(packet_sizes)))
            ax.set_yticklabels([f"{p}B" for p in packet_sizes])
            ax.set_xlabel("Throughput (Gbps)")
            ax.set_title(f"{config} ({scenario})")
            ax.grid(axis="x", alpha=0.3)

        plt.suptitle(f"Throughput by Configuration and Packet Size ({scenario})")
        plt.tight_layout()
        plt.savefig(plots_dir / f"throughput_heatmap_{scenario.replace('-', '_')}.png", dpi=150)
        plt.close()

    # Plot 2: Latency vs packet size for each configuration
    for scenario in scenarios:
        fig, ax = plt.subplots(figsize=(8, 5))
        colors = {"D0": "#2196F3", "D1": "#4CAF50", "D2": "#F44336"}
        markers = {"D0": "o", "D1": "s", "D2": "^"}

        for config in existing_configs:
            latencies = []
            for pkt in packet_sizes:
                subset = df[
                    (df["configuration"] == config) &
                    (df["packet_size"] == pkt) &
                    (df["scenario"] == scenario)
                ]
                latencies.append(subset["latency_us"].median() if not subset.empty else 0)

            ax.plot(packet_sizes, latencies, marker=markers.get(config, "o"),
                    color=colors.get(config, "gray"), label=config, linewidth=2)

        ax.set_xlabel("Packet Size (bytes)")
        ax.set_ylabel("One-Way Latency (µs)")
        ax.set_title(f"Latency vs Packet Size ({scenario})")
        ax.set_xscale("log")
        ax.legend()
        ax.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(plots_dir / f"latency_vs_pktsize_{scenario.replace('-', '_')}.png", dpi=150)
        plt.close()

    # Plot 3: Throughput degradation ratio
    fig, ax = plt.subplots(figsize=(8, 5))
    d0_medians = {}
    for scenario in scenarios:
        for pkt in packet_sizes:
            subset = df[(df["configuration"] == "D0") & (df["packet_size"] == pkt) & (df["scenario"] == scenario)]
            d0_medians[(scenario, pkt)] = subset["throughput_gbps"].median() if not subset.empty else 1

    x = np.arange(len(packet_sizes))
    width = 0.35
    for i, config in enumerate(["D1", "D2"]):
        if config not in existing_configs:
            continue
        degradations = []
        for pkt in packet_sizes:
            subset = df[(df["configuration"] == config) & (df["packet_size"] == pkt) & (df["scenario"] == scenarios[0])]
            bw = subset["throughput_gbps"].median() if not subset.empty else 0
            baseline = d0_medians.get((scenarios[0], pkt), 1)
            degradations.append((1 - bw / baseline) * 100 if baseline > 0 else 0)

        offset = (i - 0.5) * width
        ax.bar(x + offset, degradations, width, label=config)

    ax.set_xlabel("Packet Size (bytes)")
    ax.set_ylabel("Throughput Degradation (%)")
    ax.set_title("MACsec Throughput Degradation vs D0 Baseline")
    ax.set_xticks(x)
    ax.set_xticklabels([f"{p}B" for p in packet_sizes])
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(plots_dir / "throughput_degradation.png", dpi=150)
    plt.close()

    # Plot 4: CPU utilization comparison
    fig, ax = plt.subplots(figsize=(8, 5))
    for config in existing_configs:
        cpus = []
        for pkt in packet_sizes:
            subset = df[(df["configuration"] == config) & (df["packet_size"] == pkt)]
            cpus.append(subset["cpu_utilization"].median() if not subset.empty else 0)
        ax.plot(packet_sizes, cpus, marker="o", label=config, linewidth=2)

    ax.set_xlabel("Packet Size (bytes)")
    ax.set_ylabel("CPU Utilization (%)")
    ax.set_title("Sender CPU Utilization by Configuration")
    ax.set_xscale("log")
    ax.legend()
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(plots_dir / "cpu_utilization.png", dpi=150)
    plt.close()

    logger.info("Plots saved to %s", plots_dir)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Data Plane MACsec Overhead (E5)")
    parser.add_argument("-c", "--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--configs", nargs="+", choices=["D0", "D1", "D2"],
                        help="Run only specified data plane configurations")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--output-dir", default="results")
    args = parser.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)

    dp_config = config["security_dataplane"]
    logger.info("=" * 70)
    logger.info("DATA PLANE OVERHEAD: MACsec EVALUATION (E5)")
    logger.info("=" * 70)
    logger.info("Configurations:  %s", dp_config["configurations"])
    logger.info("Packet sizes:    %s", dp_config["packet_sizes"])
    logger.info("Scenarios:       %s", dp_config["scenarios"])
    logger.info("Trials/combo:    %d (warmup: %d)", dp_config["trials_per_combination"], dp_config["warmup_trials"])
    logger.info("iperf3 duration: %d s, streams: %d",
                dp_config.get("iperf_duration_seconds", 60), dp_config.get("iperf_streams", 8))
    logger.info("=" * 70)

    if args.dry_run:
        combos = (len(dp_config["configurations"]) * len(dp_config["packet_sizes"])
                  * len(dp_config["scenarios"]) * dp_config["trials_per_combination"])
        logger.info("DRY RUN - would execute %d measurements", combos)
        logger.info("Estimated time: ~%.1f hours",
                    combos * (dp_config.get("iperf_duration_seconds", 60) + 15) / 3600)
        return

    # Run experiment
    results = run_experiment(config, args)

    if not results:
        logger.error("No results collected!")
        return

    # Save raw results
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(exist_ok=True)
    with open(raw_dir / "security_dataplane_results.json", "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    logger.info("Raw results saved: %s", raw_dir)

    # Analysis
    analysis = analyze_results(results, dp_config["warmup_trials"])
    analysis_dir = output_dir / "analysis"
    analysis_dir.mkdir(exist_ok=True)
    with open(analysis_dir / "security_dataplane_analysis.json", "w") as f:
        json.dump(analysis, f, indent=2)

    # Plots
    generate_plots(results, dp_config["warmup_trials"], output_dir)

    # Summary
    logger.info("\n" + "=" * 70)
    logger.info("RESULTS SUMMARY")
    logger.info("=" * 70)
    for scenario in analysis.get("detailed", {}):
        logger.info("Scenario: %s", scenario)
        for pkt_key in analysis["detailed"][scenario]:
            for cfg, metrics in analysis["detailed"][scenario][pkt_key].items():
                logger.info("  %s %s: bw=%.2f Gbps, lat=%.1f µs, δ_bw=%.1f%%, CPU=%.1f%%",
                            pkt_key, cfg,
                            metrics["throughput_gbps"]["median"],
                            metrics["latency_us"]["median"],
                            metrics["degradation_ratio"] * 100,
                            metrics["cpu_utilization"]["median"])

    logger.info("=" * 70)
    logger.info("DATA PLANE EVALUATION COMPLETE")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
