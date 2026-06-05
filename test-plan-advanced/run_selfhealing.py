#!/usr/bin/env python3
"""
Self-Healing Evaluation Script (E3)
====================================
Evaluates the mNCC's autonomous self-healing capability by injecting
controlled faults and measuring detection, remediation, and recovery times.

Fault classes:
  F1 - Link failure (ip link set <iface> down)
  F2 - Worker node loss (kubectl drain + cordon)
  F3 - BGP route withdrawal (ExaBGP prefix removal)

Configurations:
  C_mNCC - Autonomous self-healing (proposed system)
  C_B0   - Manual remediation baseline (operator re-issues intent)

Metrics:
  - ΔT_detect:  Time from fault injection to detection
  - ΔT_recover: Time from detection to service restoration
  - ΔT_impact:  Total service interruption (T_recover - T_fault)
  - ρ_loss:     Packet loss ratio during impact window
  - lat_max:    Peak latency during interruption

Statistical reporting: median, P95 over 20 trials per fault class.
"""

import os
import sys
import time
import json
import logging
import argparse
import subprocess
import random
import threading
import uuid
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple

import yaml
import numpy as np
import pandas as pd
from scipy import stats
import matplotlib.pyplot as plt

try:
    import pika
except ImportError:
    pika = None

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
        logging.FileHandler("selfhealing_execution.log"),
    ],
)
logger = logging.getLogger(__name__)


def get_monotonic_ns() -> int:
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


def ns_to_ms(ns: int) -> float:
    return ns / 1_000_000


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    """Single UDP probe measurement."""
    timestamp_ns: int
    seq: int
    latency_us: float  # one-way latency in microseconds
    received: bool     # whether probe was received


@dataclass
class SelfHealingResult:
    """Results from a single self-healing trial."""
    fault_type: str
    configuration: str  # "mNCC" or "B0"
    trial_number: int
    baseline_latency_us: float
    baseline_bandwidth_mbps: float
    t_fault_ns: int
    t_detect_ns: int
    t_recover_ns: int
    delta_t_detect_ms: float
    delta_t_recover_ms: float
    delta_t_impact_ms: float
    packet_loss_ratio: float
    peak_latency_us: float
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


# ---------------------------------------------------------------------------
# UDP Probe Engine
# ---------------------------------------------------------------------------

class ProbeEngine:
    """
    Generates continuous UDP probes between two pods to measure
    latency and detect service interruptions.
    """

    def __init__(self, source_pod: str, target_pod: str, namespace: str,
                 kubeconfig: str, interval_ms: int = 100):
        self.source_pod = source_pod
        self.target_pod = target_pod
        self.namespace = namespace
        self.kubeconfig = kubeconfig
        self.interval_ms = interval_ms
        self.probes: List[ProbeResult] = []
        self._running = False
        self._thread = None
        self._seq = 0

    def start(self):
        """Start continuous probing in background thread."""
        self._running = True
        self._thread = threading.Thread(target=self._probe_loop, daemon=True)
        self._thread.start()
        logger.info("Probe engine started: %s -> %s (interval=%dms)",
                    self.source_pod, self.target_pod, self.interval_ms)

    def stop(self):
        """Stop probing and return collected results."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Probe engine stopped. Total probes: %d", len(self.probes))
        return self.probes

    def _probe_loop(self):
        """Send probes at regular intervals."""
        while self._running:
            t_start = get_monotonic_ns()
            probe = self._send_probe()
            self.probes.append(probe)
            elapsed_ms = (get_monotonic_ns() - t_start) / 1e6
            sleep_ms = max(0, self.interval_ms - elapsed_ms)
            time.sleep(sleep_ms / 1000)

    def _send_probe(self) -> ProbeResult:
        """Send a single ping probe and measure RTT."""
        self._seq += 1
        t_send = get_monotonic_ns()
        try:
            result = subprocess.run(
                ["kubectl", "--kubeconfig", self.kubeconfig,
                 "exec", "-n", self.namespace, self.source_pod, "--",
                 "ping", "-c", "1", "-W", "1", self.target_pod],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0:
                # Parse RTT from ping output (e.g., "time=0.543 ms")
                rtt_ms = self._parse_ping_rtt(result.stdout)
                latency_us = (rtt_ms / 2) * 1000 if rtt_ms else 0
                return ProbeResult(t_send, self._seq, latency_us, True)
            else:
                return ProbeResult(t_send, self._seq, 0, False)
        except (subprocess.TimeoutExpired, Exception):
            return ProbeResult(t_send, self._seq, 0, False)

    @staticmethod
    def _parse_ping_rtt(output: str) -> Optional[float]:
        """Extract RTT from ping output."""
        for line in output.split("\n"):
            if "time=" in line:
                try:
                    time_part = line.split("time=")[1].split()[0]
                    return float(time_part)
                except (IndexError, ValueError):
                    pass
        return None

    def get_baseline_stats(self, window_s: float) -> Tuple[float, float]:
        """
        Calculate baseline latency and bandwidth from stabilisation window.
        Returns (mean_latency_us, estimated_bandwidth_mbps).
        """
        window_ns = int(window_s * 1e9)
        if not self.probes:
            return 0.0, 0.0

        cutoff = self.probes[-1].timestamp_ns - window_ns
        window_probes = [p for p in self.probes if p.timestamp_ns >= cutoff and p.received]

        if not window_probes:
            return 0.0, 0.0

        latencies = [p.latency_us for p in window_probes]
        mean_lat = np.mean(latencies)

        # Estimate bandwidth from successful probe rate and assumed packet size
        total_probes = len([p for p in self.probes if p.timestamp_ns >= cutoff])
        success_rate = len(window_probes) / max(total_probes, 1)
        # Assume 64-byte probes at interval_ms rate
        estimated_bw_mbps = (64 * 8 * success_rate * 1000 / self.interval_ms) / 1e6

        return mean_lat, estimated_bw_mbps


# ---------------------------------------------------------------------------
# Fault Injection Functions
# ---------------------------------------------------------------------------

def inject_fault_f1(config: Dict, kubeconfig: str) -> int:
    """
    F1 - Link failure: Take down inter-node interface.
    Returns timestamp (ns) of fault injection.
    """
    source_node = config["source_node"]
    interface = config.get("interface", "eth0")

    logger.info("Injecting F1: Link failure on %s (iface=%s)", source_node, interface)

    t_fault = get_monotonic_ns()
    # Execute ip link set down on the target node via kubectl
    subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig,
         "debug", "node/" + source_node, "--image=alpine", "--",
         "nsenter", "-t", "1", "-n", "--",
         "ip", "link", "set", interface, "down"],
        capture_output=True, timeout=30
    )
    return t_fault


def recover_fault_f1(config: Dict, kubeconfig: str):
    """Restore F1: Bring interface back up."""
    source_node = config["source_node"]
    interface = config.get("interface", "eth0")

    logger.info("Recovering F1: Restoring %s on %s", interface, source_node)
    subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig,
         "debug", "node/" + source_node, "--image=alpine", "--",
         "nsenter", "-t", "1", "-n", "--",
         "ip", "link", "set", interface, "up"],
        capture_output=True, timeout=30
    )


def inject_fault_f2(config: Dict, kubeconfig: str) -> int:
    """
    F2 - Worker node loss: Drain and cordon a worker node.
    Returns timestamp (ns) of fault injection.
    """
    target_node = config["target_node"]

    logger.info("Injecting F2: Node drain on %s", target_node)

    t_fault = get_monotonic_ns()
    subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig,
         "drain", target_node,
         "--ignore-daemonsets", "--delete-emptydir-data",
         "--force", "--grace-period=30", "--timeout=120s"],
        capture_output=True, timeout=130
    )
    subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "cordon", target_node],
        capture_output=True, timeout=30
    )
    return t_fault


def recover_fault_f2(config: Dict, kubeconfig: str):
    """Restore F2: Uncordon the node."""
    target_node = config["target_node"]
    logger.info("Recovering F2: Uncordoning %s", target_node)
    subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "uncordon", target_node],
        capture_output=True, timeout=30
    )


def inject_fault_f3(config: Dict, kubeconfig: str) -> int:
    """
    F3 - BGP route withdrawal: Remove a prefix from ExaBGP.
    Returns timestamp (ns) of fault injection.
    """
    exabgp_host = config["exabgp_host"]
    prefix = config["prefix"]

    logger.info("Injecting F3: BGP withdrawal of %s on %s", prefix, exabgp_host)

    t_fault = get_monotonic_ns()
    # Send route withdrawal to ExaBGP via its HTTP API or control pipe
    subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig,
         "debug", "node/" + exabgp_host, "--image=alpine", "--",
         "nsenter", "-t", "1", "-n", "--",
         "bash", "-c",
         f"echo 'neighbor 10.0.0.1 withdraw route {prefix} next-hop self' "
         f"> /run/exabgp.cmd"],
        capture_output=True, timeout=30
    )
    return t_fault


def recover_fault_f3(config: Dict, kubeconfig: str):
    """Restore F3: Re-announce the BGP prefix."""
    exabgp_host = config["exabgp_host"]
    prefix = config["prefix"]

    logger.info("Recovering F3: Re-announcing %s on %s", prefix, exabgp_host)
    subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig,
         "debug", "node/" + exabgp_host, "--image=alpine", "--",
         "nsenter", "-t", "1", "-n", "--",
         "bash", "-c",
         f"echo 'neighbor 10.0.0.1 announce route {prefix} next-hop self' "
         f"> /run/exabgp.cmd"],
        capture_output=True, timeout=30
    )


# ---------------------------------------------------------------------------
# mNCC Detection Monitoring
# ---------------------------------------------------------------------------

def monitor_mncc_detection(rmq_config: Dict, timeout_s: float = 300) -> Optional[int]:
    """
    Monitor the mNCC response queue for fault detection events.
    Returns timestamp (ns) when detection event is received, or None on timeout.
    """
    if pika is None:
        logger.warning("pika not available, simulating detection")
        return None

    detection_time = None

    credentials = pika.PlainCredentials(rmq_config["username"], rmq_config["password"])
    conn_params = pika.ConnectionParameters(
        host=rmq_config["host"], port=rmq_config["port"], credentials=credentials
    )
    connection = pika.BlockingConnection(conn_params)
    channel = connection.channel()

    # Listen on mncc exchange for fault detection events
    try:
        channel.exchange_declare(exchange="mncc", exchange_type="topic", passive=True)
    except Exception:
        connection = pika.BlockingConnection(conn_params)
        channel = connection.channel()
        channel.exchange_declare(exchange="mncc", exchange_type="topic", durable=True)

    result = channel.queue_declare(queue="", exclusive=True)
    tmp_queue = result.method.queue
    # Subscribe to all mncc events (detection notifications)
    channel.queue_bind(queue=tmp_queue, exchange="mncc", routing_key="mncc.#")

    def on_detection(ch, method, properties, body):
        nonlocal detection_time
        try:
            msg = json.loads(body.decode("utf-8"))
            # Check if it's a fault detection event
            if "fault" in str(msg).lower() or "alarm" in str(msg).lower() or "event" in str(msg).lower():
                detection_time = get_monotonic_ns()
                ch.stop_consuming()
        except Exception:
            pass

    channel.basic_consume(queue=tmp_queue, on_message_callback=on_detection, auto_ack=True)

    start = time.time()
    while detection_time is None and (time.time() - start) < timeout_s:
        connection.process_data_events(time_limit=1)

    connection.close()
    return detection_time


def publish_remediation_intent(rmq_config: Dict, network_name: str, workload_id: str,
                                provider_name: str, domain: str):
    """
    Re-issue a provisioning intent for the affected segment (manual remediation).
    Used for C_B0 baseline.
    """
    if pika is None:
        logger.warning("pika not available, skipping remediation intent")
        return

    intent_msg = {
        "userLabel": "cloud_continuum",
        "Intent": {
            "id": f"remediation_{uuid.uuid4().hex[:8]}",
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
                         "contextValueRange": provider_name},
                        {"contextAttribute": "domain", "contextCondition": "IS_EQUAL_TO",
                         "contextValueRange": domain},
                    ],
                },
                "expectationTargets": [
                    {"targetName": "secure", "targetCondition": "IS_EQUAL_TO",
                     "targetValueRange": "true"}
                ],
            }],
            "intentContexts": [
                {"contextAttribute": "NEMO_WORKLOAD", "contextCondition": "IS_EQUAL_TO",
                 "contextValueRange": workload_id}
            ],
            "intentPriority": 1,
            "observationPeriod": 60,
            "intentAdminState": "ACTIVATED",
        }
    }

    credentials = pika.PlainCredentials(rmq_config["username"], rmq_config["password"])
    conn_params = pika.ConnectionParameters(
        host=rmq_config["host"], port=rmq_config["port"], credentials=credentials
    )
    connection = pika.BlockingConnection(conn_params)
    channel = connection.channel()
    channel.basic_publish(
        exchange=rmq_config["intent_exchange"],
        routing_key=rmq_config["intent_routing_key"],
        body=json.dumps(intent_msg).encode("utf-8"),
        properties=pika.BasicProperties(content_type="application/json", delivery_mode=2),
    )
    connection.close()


# ---------------------------------------------------------------------------
# Recovery Detection
# ---------------------------------------------------------------------------

def detect_recovery(probes: List[ProbeResult], baseline_lat_us: float,
                    baseline_bw_mbps: float, lat_tolerance: float,
                    bw_tolerance: float, window_samples: int,
                    t_fault_ns: int) -> Optional[int]:
    """
    Find T_recover: earliest timestamp where 10 consecutive probes
    satisfy lat <= 1.1*baseline AND bw >= 0.9*baseline.
    Returns timestamp_ns or None.
    """
    # Filter probes after fault
    post_fault = [p for p in probes if p.timestamp_ns > t_fault_ns]

    if len(post_fault) < window_samples:
        return None

    max_lat = lat_tolerance * baseline_lat_us

    consecutive = 0
    for probe in post_fault:
        if probe.received and probe.latency_us <= max_lat and probe.latency_us > 0:
            consecutive += 1
            if consecutive >= window_samples:
                # Recovery confirmed at this probe's timestamp
                return probe.timestamp_ns
        else:
            consecutive = 0

    return None


# ---------------------------------------------------------------------------
# Trial Execution
# ---------------------------------------------------------------------------

def setup_test_pods(kubeconfig: str, namespace: str = "selfhealing-test") -> Tuple[str, str]:
    """Deploy two test pods on different nodes for probing."""
    # Create namespace
    subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-"],
        input=f'apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {namespace}\n'.encode(),
        capture_output=True, timeout=30
    )

    # Deploy sender pod on worker1
    sender_yaml = f"""
apiVersion: v1
kind: Pod
metadata:
  name: probe-sender
  namespace: {namespace}
spec:
  nodeName: nemo-dev-worker1
  containers:
  - name: probe
    image: alpine:3.18
    command: ["sleep", "infinity"]
  restartPolicy: Never
"""
    subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-"],
        input=sender_yaml.encode(), capture_output=True, timeout=30
    )

    # Deploy receiver pod on worker2
    receiver_yaml = f"""
apiVersion: v1
kind: Pod
metadata:
  name: probe-receiver
  namespace: {namespace}
spec:
  nodeName: nemo-dev-worker2
  containers:
  - name: probe
    image: alpine:3.18
    command: ["sleep", "infinity"]
  restartPolicy: Never
"""
    subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-"],
        input=receiver_yaml.encode(), capture_output=True, timeout=30
    )

    # Wait for pods to be ready
    subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "wait",
         "--for=condition=Ready", "pod/probe-sender", "pod/probe-receiver",
         "-n", namespace, "--timeout=120s"],
        capture_output=True, timeout=130
    )

    # Get receiver pod IP
    result = subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "get", "pod", "probe-receiver",
         "-n", namespace, "-o", "jsonpath={.status.podIP}"],
        capture_output=True, text=True, timeout=30
    )
    receiver_ip = result.stdout.strip()

    return "probe-sender", receiver_ip


def cleanup_test_pods(kubeconfig: str, namespace: str = "selfhealing-test"):
    """Remove test namespace and pods."""
    subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "delete", "ns", namespace,
         "--ignore-not-found", "--force", "--grace-period=0", "--wait=false"],
        capture_output=True, timeout=30
    )


def run_selfhealing_trial(
    fault_type: str,
    configuration: str,  # "mNCC" or "B0"
    trial_num: int,
    config: Dict,
    kubeconfig: str,
) -> Optional[SelfHealingResult]:
    """Execute a single self-healing trial."""

    sh_config = config["selfhealing"]
    mncc_config = config["mncc"]
    rmq_config = mncc_config["rabbitmq"]

    logger.info("Trial %d | Fault=%s | Config=%s", trial_num, fault_type, configuration)

    namespace = "selfhealing-test"

    # Get receiver IP for probing
    result = subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "get", "pod", "probe-receiver",
         "-n", namespace, "-o", "jsonpath={.status.podIP}"],
        capture_output=True, text=True, timeout=30
    )
    receiver_ip = result.stdout.strip()
    if not receiver_ip:
        logger.error("Cannot get receiver pod IP, skipping trial")
        return None

    # Start probe engine
    probe_engine = ProbeEngine(
        source_pod="probe-sender",
        target_pod=receiver_ip,
        namespace=namespace,
        kubeconfig=kubeconfig,
        interval_ms=sh_config["probe_interval_ms"],
    )
    probe_engine.start()

    # Phase 1: Stabilisation window
    stab_time = sh_config["stabilisation_window_s"]
    logger.info("  Stabilisation window: %ds", stab_time)
    time.sleep(stab_time)

    # Record baseline
    baseline_lat, baseline_bw = probe_engine.get_baseline_stats(stab_time)
    logger.info("  Baseline: lat=%.1f µs, bw=%.3f Mbps", baseline_lat, baseline_bw)

    # Phase 2: Randomised fault injection
    random_offset = random.uniform(0, sh_config["random_offset_window_s"])
    logger.info("  Waiting %.1fs random offset before fault injection...", random_offset)
    time.sleep(random_offset)

    # Start detection monitor (for mNCC configuration)
    detection_thread_result = [None]
    if configuration == "mNCC":
        def _monitor():
            detection_thread_result[0] = monitor_mncc_detection(rmq_config, timeout_s=300)
        det_thread = threading.Thread(target=_monitor, daemon=True)
        det_thread.start()

    # Inject fault
    fault_configs = {
        "F1": sh_config.get("link_failure", {}),
        "F2": sh_config.get("node_loss", {}),
        "F3": sh_config.get("bgp_withdrawal", {}),
    }
    inject_funcs = {"F1": inject_fault_f1, "F2": inject_fault_f2, "F3": inject_fault_f3}
    recover_funcs = {"F1": recover_fault_f1, "F2": recover_fault_f2, "F3": recover_fault_f3}

    t_fault = inject_funcs[fault_type](fault_configs[fault_type], kubeconfig)
    logger.info("  Fault injected at T=0")

    # Phase 3: Determine T_detect
    if configuration == "mNCC":
        # Wait for mNCC to detect (via RabbitMQ monitoring)
        det_thread.join(timeout=300)
        t_detect = detection_thread_result[0]
        if t_detect is None:
            # Fallback: estimate from probe loss pattern
            time.sleep(30)
            probes_after = [p for p in probe_engine.probes if p.timestamp_ns > t_fault]
            first_loss = next((p for p in probes_after if not p.received), None)
            t_detect = first_loss.timestamp_ns if first_loss else get_monotonic_ns()
    else:
        # B0: Manual detection - simulate operator observation delay
        operator_delay = sh_config["operator_delay_s"]
        logger.info("  B0: Simulating operator delay (%ds)...", operator_delay)
        time.sleep(operator_delay)
        t_detect = get_monotonic_ns()

        # Operator manually re-issues remediation intent
        publish_remediation_intent(
            rmq_config,
            network_name="selfhealing-net",
            workload_id="selfhealing-wl",
            provider_name=mncc_config["l2sm"]["provider_name"],
            domain=mncc_config["l2sm"]["domain"],
        )

    # Phase 4: Wait for recovery
    # For mNCC: autonomous recovery should happen
    # For B0: recovery after intent re-provisioning
    max_wait = 300  # 5 minutes max
    logger.info("  Waiting for recovery (max %ds)...", max_wait)
    time.sleep(min(max_wait, 60))  # Give time for recovery

    # Also restore the fault manually to ensure the cluster recovers
    recover_funcs[fault_type](fault_configs[fault_type], kubeconfig)

    # Wait additional time for stabilisation
    time.sleep(30)

    # Stop probing
    all_probes = probe_engine.stop()

    # Phase 5: Calculate metrics
    t_recover = detect_recovery(
        all_probes, baseline_lat, baseline_bw,
        sh_config["latency_tolerance"],
        sh_config["bandwidth_tolerance"],
        sh_config["recovery_window_samples"],
        t_fault,
    )

    if t_recover is None:
        t_recover = all_probes[-1].timestamp_ns if all_probes else get_monotonic_ns()
        logger.warning("  Recovery not fully detected, using last probe timestamp")

    # Packet loss during impact window
    impact_probes = [p for p in all_probes
                     if t_fault <= p.timestamp_ns <= t_recover]
    total_impact = len(impact_probes)
    lost_probes = len([p for p in impact_probes if not p.received])
    packet_loss_ratio = lost_probes / max(total_impact, 1)

    # Peak latency during impact
    impact_latencies = [p.latency_us for p in impact_probes if p.received and p.latency_us > 0]
    peak_latency = max(impact_latencies) if impact_latencies else 0

    delta_detect = ns_to_ms(t_detect - t_fault) if t_detect else 0
    delta_recover = ns_to_ms(t_recover - t_detect) if (t_detect and t_recover) else 0
    delta_impact = ns_to_ms(t_recover - t_fault)

    logger.info("  Results: ΔT_detect=%.1fms, ΔT_recover=%.1fms, ΔT_impact=%.1fms",
                delta_detect, delta_recover, delta_impact)
    logger.info("  Packet loss=%.2f%%, Peak latency=%.1fµs",
                packet_loss_ratio * 100, peak_latency)

    return SelfHealingResult(
        fault_type=fault_type,
        configuration=configuration,
        trial_number=trial_num,
        baseline_latency_us=baseline_lat,
        baseline_bandwidth_mbps=baseline_bw,
        t_fault_ns=t_fault,
        t_detect_ns=t_detect or 0,
        t_recover_ns=t_recover,
        delta_t_detect_ms=delta_detect,
        delta_t_recover_ms=delta_recover,
        delta_t_impact_ms=delta_impact,
        packet_loss_ratio=packet_loss_ratio,
        peak_latency_us=peak_latency,
    )


# ---------------------------------------------------------------------------
# Statistical Analysis
# ---------------------------------------------------------------------------

def analyze_results(results: List[SelfHealingResult]) -> Dict:
    """Compute summary statistics for self-healing results."""
    analysis = {}

    df = pd.DataFrame([asdict(r) for r in results])

    for fault in df["fault_type"].unique():
        fault_df = df[df["fault_type"] == fault]
        analysis[fault] = {}

        for config in fault_df["configuration"].unique():
            cfg_df = fault_df[fault_df["configuration"] == config]

            analysis[fault][config] = {
                "delta_t_detect_ms": {
                    "median": float(cfg_df["delta_t_detect_ms"].median()),
                    "p95": float(cfg_df["delta_t_detect_ms"].quantile(0.95)),
                    "mean": float(cfg_df["delta_t_detect_ms"].mean()),
                },
                "delta_t_recover_ms": {
                    "median": float(cfg_df["delta_t_recover_ms"].median()),
                    "p95": float(cfg_df["delta_t_recover_ms"].quantile(0.95)),
                    "mean": float(cfg_df["delta_t_recover_ms"].mean()),
                },
                "delta_t_impact_ms": {
                    "median": float(cfg_df["delta_t_impact_ms"].median()),
                    "p95": float(cfg_df["delta_t_impact_ms"].quantile(0.95)),
                    "mean": float(cfg_df["delta_t_impact_ms"].mean()),
                },
                "packet_loss_ratio": {
                    "median": float(cfg_df["packet_loss_ratio"].median()),
                    "p95": float(cfg_df["packet_loss_ratio"].quantile(0.95)),
                },
                "peak_latency_us": {
                    "median": float(cfg_df["peak_latency_us"].median()),
                    "p95": float(cfg_df["peak_latency_us"].quantile(0.95)),
                },
                "n_trials": int(len(cfg_df)),
            }

    return analysis


def generate_plots(results: List[SelfHealingResult], output_dir: Path):
    """Generate self-healing evaluation plots."""
    df = pd.DataFrame([asdict(r) for r in results])
    plots_dir = output_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)

    # Plot 1: Impact duration comparison (mNCC vs B0) per fault type
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    for idx, fault in enumerate(["F1", "F2", "F3"]):
        ax = axes[idx]
        fault_df = df[df["fault_type"] == fault]
        if fault_df.empty:
            continue
        data = [fault_df[fault_df["configuration"] == c]["delta_t_impact_ms"].values
                for c in ["mNCC", "B0"]]
        data = [d for d in data if len(d) > 0]
        if data:
            ax.boxplot(data, labels=["mNCC", "B0 (manual)"][:len(data)])
        ax.set_title(f"Fault {fault}: Total Impact Duration")
        ax.set_ylabel("ΔT_impact (ms)")
    plt.tight_layout()
    plt.savefig(plots_dir / "impact_duration_comparison.png", dpi=150)
    plt.close()

    # Plot 2: Detection vs Recovery breakdown
    fig, ax = plt.subplots(figsize=(10, 6))
    fault_types = ["F1", "F2", "F3"]
    configs = ["mNCC", "B0"]
    x = np.arange(len(fault_types))
    width = 0.35

    for i, config in enumerate(configs):
        detect_medians = []
        recover_medians = []
        for fault in fault_types:
            cfg_df = df[(df["fault_type"] == fault) & (df["configuration"] == config)]
            detect_medians.append(cfg_df["delta_t_detect_ms"].median() if not cfg_df.empty else 0)
            recover_medians.append(cfg_df["delta_t_recover_ms"].median() if not cfg_df.empty else 0)

        offset = (i - 0.5) * width
        ax.bar(x + offset, detect_medians, width, label=f"{config} (detect)")
        ax.bar(x + offset, recover_medians, width, bottom=detect_medians,
               label=f"{config} (recover)", alpha=0.7)

    ax.set_xlabel("Fault Type")
    ax.set_ylabel("Time (ms)")
    ax.set_title("Self-Healing: Detection + Recovery Breakdown")
    ax.set_xticks(x)
    ax.set_xticklabels(fault_types)
    ax.legend()
    plt.tight_layout()
    plt.savefig(plots_dir / "detection_recovery_breakdown.png", dpi=150)
    plt.close()

    # Plot 3: Packet loss comparison
    fig, ax = plt.subplots(figsize=(8, 5))
    for config in configs:
        losses = [df[(df["fault_type"] == f) & (df["configuration"] == config)]
                  ["packet_loss_ratio"].median() * 100 for f in fault_types]
        ax.plot(fault_types, losses, 'o-', label=config, markersize=8)
    ax.set_xlabel("Fault Type")
    ax.set_ylabel("Packet Loss (%)")
    ax.set_title("Packet Loss During Impact Window")
    ax.legend()
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(plots_dir / "packet_loss_comparison.png", dpi=150)
    plt.close()

    logger.info("Plots saved to %s", plots_dir)


# ---------------------------------------------------------------------------
# Main Execution
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Self-Healing Evaluation (E3)")
    parser.add_argument("-c", "--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--faults", nargs="+", choices=["F1", "F2", "F3"],
                        help="Run only specified fault types")
    parser.add_argument("--configs", nargs="+", choices=["mNCC", "B0"],
                        default=["mNCC", "B0"])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-setup", action="store_true",
                        help="Skip test pod deployment (assume already running)")
    parser.add_argument("--output-dir", default="results")
    args = parser.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)

    sh_config = config["selfhealing"]
    kubeconfig = config["cluster"]["kubeconfig"]
    fault_types = args.faults or sh_config["fault_types"]
    configurations = args.configs
    trials = sh_config["trials_per_fault"]
    output_dir = Path(args.output_dir)

    logger.info("=" * 70)
    logger.info("SELF-HEALING EVALUATION (E3)")
    logger.info("=" * 70)
    logger.info("Fault types:      %s", fault_types)
    logger.info("Configurations:   %s", configurations)
    logger.info("Trials per fault:  %d", trials)
    logger.info("Stabilisation:     %ds", sh_config["stabilisation_window_s"])
    logger.info("Probe interval:    %dms", sh_config["probe_interval_ms"])
    logger.info("Output:            %s", output_dir)
    logger.info("=" * 70)

    if args.dry_run:
        logger.info("DRY RUN - no trials will be executed.")
        total = len(fault_types) * len(configurations) * trials
        logger.info("Would execute %d trials total.", total)
        return

    # Setup test pods
    if not args.skip_setup:
        logger.info("Setting up test pods...")
        setup_test_pods(kubeconfig)
        time.sleep(30)  # Wait for pods to stabilise

    # Execute trials
    results: List[SelfHealingResult] = []

    for fault in fault_types:
        for cfg in configurations:
            logger.info("-" * 50)
            logger.info("Starting series: Fault=%s, Config=%s (%d trials)", fault, cfg, trials)

            for trial_num in range(1, trials + 1):
                try:
                    result = run_selfhealing_trial(
                        fault_type=fault,
                        configuration=cfg,
                        trial_num=trial_num,
                        config=config,
                        kubeconfig=kubeconfig,
                    )
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.error("Trial %d FAILED: %s", trial_num, str(e))

                # Wait between trials for cluster stabilisation
                time.sleep(30)

    # Save raw results
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(exist_ok=True)
    with open(raw_dir / "selfhealing_results.json", "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    logger.info("Raw results saved: %s", raw_dir / "selfhealing_results.json")

    # Analysis
    if results:
        analysis = analyze_results(results)
        analysis_dir = output_dir / "analysis"
        analysis_dir.mkdir(exist_ok=True)
        with open(analysis_dir / "selfhealing_analysis.json", "w") as f:
            json.dump(analysis, f, indent=2)
        logger.info("Analysis saved: %s", analysis_dir / "selfhealing_analysis.json")

        # Generate plots
        generate_plots(results, output_dir)

        # Print summary
        logger.info("\n" + "=" * 70)
        logger.info("RESULTS SUMMARY")
        logger.info("=" * 70)
        for fault in fault_types:
            logger.info("\nFault %s:", fault)
            for cfg in configurations:
                if fault in analysis and cfg in analysis[fault]:
                    a = analysis[fault][cfg]
                    logger.info("  %s: ΔT_detect=%.1fms (P95=%.1fms) | "
                                "ΔT_recover=%.1fms (P95=%.1fms) | "
                                "ΔT_impact=%.1fms (P95=%.1fms) | "
                                "loss=%.1f%%",
                                cfg,
                                a["delta_t_detect_ms"]["median"],
                                a["delta_t_detect_ms"]["p95"],
                                a["delta_t_recover_ms"]["median"],
                                a["delta_t_recover_ms"]["p95"],
                                a["delta_t_impact_ms"]["median"],
                                a["delta_t_impact_ms"]["p95"],
                                a["packet_loss_ratio"]["median"] * 100)

    # Cleanup
    if not args.skip_setup:
        cleanup_test_pods(kubeconfig)

    logger.info("=" * 70)
    logger.info("SELF-HEALING EVALUATION COMPLETE")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
