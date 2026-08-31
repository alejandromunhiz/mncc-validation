#!/usr/bin/env python3
"""
Self-Healing Evaluation Script (E3)
====================================
Evaluates self-healing under controlled faults using independent external
observability. The testbed does not expose correlatable internal mNCC
detection events, so detection latency is explicitly measured from the
external UDP probe observer.

Fault classes:
  F1 - L2SM link withdrawal (host interface failure)
  F2 - Worker node loss (kubectl drain + cordon)
  F3 - BGP route withdrawal (ExaBGP prefix removal, out of scope here)

Configurations:
  C_mNCC - Autonomous self-healing (proposed system)
  C_B0   - Manual remediation baseline (operator re-issues intent)

Metrics:
  - ΔT_detect_obs: Time from fault injection to external observation
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
import re
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
    """Single UDP request/reply measurement."""
    timestamp_ns: int
    seq: int
    latency_us: float  # RTT/2 unless PTP one-way timestamps are enabled
    received: bool
    payload_bytes: int


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
    detection_source: str
    valid: bool = True
    failure_reason: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


# ---------------------------------------------------------------------------
# UDP Probe Engine
# ---------------------------------------------------------------------------

class ProbeEngine:
    """
    Generates continuous UDP request/reply probes between two pods.
    The receiver is a persistent UDP server; each request includes a
    trial identifier and sequence number. Latency is RTT/2 unless the
    deployment provides synchronized one-way timestamps.
    """

    def __init__(self, source_pod: str, target_ip: str, trial_id: str,
                 namespace: str, kubeconfig: str, interval_ms: int = 100,
                 payload_bytes: int = 1200, port: int = 9999,
                 source_selector: Optional[str] = None):
        self.source_pod = source_pod
        self.source_selector = source_selector
        self.target_ip = target_ip
        self.trial_id = trial_id
        self.namespace = namespace
        self.kubeconfig = kubeconfig
        self.interval_ms = interval_ms
        self.payload_bytes = payload_bytes
        self.port = port
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
                    self.source_pod, self.target_ip, self.interval_ms)

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
        """Send one UDP probe through the persistent receiver."""
        self._seq += 1
        t_send = get_monotonic_ns()
        try:
            source_pod = self.source_pod
            if self.source_selector:
                result = subprocess.run(
                    ["kubectl", "--kubeconfig", self.kubeconfig, "get", "pods",
                     "-n", self.namespace, "-l", self.source_selector,
                     "--field-selector=status.phase=Running",
                     "-o", "jsonpath={.items[0].metadata.name}"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode != 0 or not result.stdout.strip():
                    return ProbeResult(t_send, self._seq, 0, False, self.payload_bytes)
                source_pod = result.stdout.strip()
            result = subprocess.run(
                ["kubectl", "--kubeconfig", self.kubeconfig,
                 "exec", "-n", self.namespace, source_pod, "--",
                 "python", "-c", (
                     "import socket,sys,time;"
                     "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
                     "s.settimeout(1.0);"
                     "payload=(sys.argv[1]+'|'+sys.argv[2]+'|'+str(time.monotonic_ns())+'|')"
                     ".encode()+b'x'*int(sys.argv[3]);"
                     "t=time.monotonic_ns();s.sendto(payload,(sys.argv[4],int(sys.argv[5])));"
                     "s.recvfrom(4096);print(time.monotonic_ns()-t)"
                 ),
                 self.trial_id, str(self._seq), str(self.payload_bytes),
                 self.target_ip, str(self.port)],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0:
                rtt_ns = int(result.stdout.strip())
                return ProbeResult(t_send, self._seq, rtt_ns / 2000, True,
                                   self.payload_bytes)
            logger.debug("UDP probe failed: %s", result.stderr.strip())
        except subprocess.TimeoutExpired:
            logger.debug("UDP probe timed out")
        except (OSError, ValueError) as exc:
            logger.warning("UDP probe failed operationally: %s", exc)
        return ProbeResult(t_send, self._seq, 0, False, self.payload_bytes)

    def get_baseline_stats(self, window_s: float) -> Tuple[float, float]:
        """
        Calculate baseline latency and measured received UDP throughput.
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

        first_ts = min(p.timestamp_ns for p in window_probes)
        last_ts = max(p.timestamp_ns for p in window_probes)
        duration_s = max((last_ts - first_ts) / 1e9, self.interval_ms / 1000)
        received_bytes = sum(p.payload_bytes for p in window_probes)
        measured_bw_mbps = received_bytes * 8 / duration_s / 1e6
        return mean_lat, measured_bw_mbps


# ---------------------------------------------------------------------------
# Fault Injection Functions
# ---------------------------------------------------------------------------

class TrialError(RuntimeError):
    """An operational or measurement failure invalidating one trial."""


def _run_checked(command: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise TrialError(
            f"Command failed (rc={result.returncode}): {' '.join(command)}; "
            f"{result.stderr.strip()}"
        )
    return result


def _node_ip_command(node: str, command: List[str], kubeconfig: str,
                     timeout: int = 30) -> subprocess.CompletedProcess:
    return _run_checked(
        ["kubectl", "--kubeconfig", kubeconfig, "debug", f"node/{node}",
         "--image=alpine:3.20", "--", "chroot", "/host"] + command,
        timeout=timeout,
    )


def _flannel_pod_for_node(node: str, kubeconfig: str) -> str:
    pods = json.loads(_run_checked(
        ["kubectl", "--kubeconfig", kubeconfig, "get", "pods", "-n", "kube-flannel",
         "-o", "json"], timeout=30
    ).stdout)
    candidates = [
        item["metadata"]["name"] for item in pods.get("items", [])
        if item.get("spec", {}).get("nodeName") == node
        and item.get("status", {}).get("phase") == "Running"
    ]
    if not candidates:
        raise TrialError(f"No Running kube-flannel pod found on {node}")
    return candidates[0]


def _flannel_exec(node: str, command: List[str], kubeconfig: str,
                  timeout: int = 30) -> subprocess.CompletedProcess:
    pod = _flannel_pod_for_node(node, kubeconfig)
    return _run_checked(
        ["kubectl", "--kubeconfig", kubeconfig, "exec", "-n", "kube-flannel",
         pod, "--"] + command, timeout=timeout
    )


def _flannel_set_link_state(node: str, interface: str, state: str,
                            kubeconfig: str) -> None:
    """Change link state without keeping kubectl exec attached to the link."""
    if state not in {"up", "down"}:
        raise TrialError(f"Unsupported link state: {state}")
    _node_ip_command(
        node, ["ip", "link", "set", interface, state], kubeconfig, timeout=15
    )


def _host_link_state(node: str, interface: str, kubeconfig: str) -> str:
    """Read a host interface through the node debug channel."""
    return _node_ip_command(
        node, ["ip", "-o", "link", "show", "dev", interface],
        kubeconfig, timeout=20,
    ).stdout


def _node_internal_ip(node: str, kubeconfig: str) -> str:
    node_obj = json.loads(_run_checked(
        ["kubectl", "--kubeconfig", kubeconfig, "get", "node", node, "-o", "json"],
        timeout=30
    ).stdout)
    for address in node_obj.get("status", {}).get("addresses", []):
        if address.get("type") == "InternalIP":
            return address["address"]
    raise TrialError(f"Node {node} has no InternalIP")


def _node_pod_cidr(node: str, kubeconfig: str) -> str:
    node_obj = json.loads(_run_checked(
        ["kubectl", "--kubeconfig", kubeconfig, "get", "node", node, "-o", "json"],
        timeout=30
    ).stdout)
    pod_cidr = node_obj.get("spec", {}).get("podCIDR")
    if not pod_cidr:
        raise TrialError(f"Node {node} has no podCIDR")
    return pod_cidr


def discover_link_interface(source_node: str, target_node: str,
                            kubeconfig: str,
                            destination_ip: Optional[str] = None) -> str:
    """Resolve the physical underlay interface used by the probe flow."""
    target_ip = destination_ip or _node_internal_ip(target_node, kubeconfig)
    route = _flannel_exec(
        source_node, ["ip", "route", "get", target_ip], kubeconfig
    ).stdout.strip()
    dev_match = re.search(r"\bdev\s+([^\s]+)", route)
    via_match = re.search(r"\bvia\s+([^\s]+)", route)
    if not dev_match:
        raise TrialError(
            f"Could not determine the route interface from {source_node} to {target_ip}: "
            f"{route!r}"
        )
    interface = dev_match.group(1)
    virtual_prefixes = ("lo", "cni", "flannel", "docker", "br-", "veth", "virbr")
    if interface.startswith(virtual_prefixes):
        link_details = _flannel_exec(
            source_node, ["ip", "-d", "link", "show", "dev", interface], kubeconfig
        ).stdout
        underlay_match = re.search(r"\bdev\s+([^\s]+)", link_details)
        if underlay_match and not underlay_match.group(1).startswith(virtual_prefixes):
            interface = underlay_match.group(1)
        elif via_match:
            next_hop = via_match.group(1)
            underlay_route = _flannel_exec(
                source_node, ["ip", "route", "get", next_hop], kubeconfig
            ).stdout.strip()
            underlay_match = re.search(r"\bdev\s+([^\s]+)", underlay_route)
            if not underlay_match:
                raise TrialError(
                    f"Could not resolve underlay interface for {target_ip} via {next_hop}: "
                    f"{underlay_route!r}"
                )
            interface = underlay_match.group(1)
        if interface.startswith(virtual_prefixes):
            raise TrialError(
                f"Route to {target_ip} resolved only to virtual interface {interface}"
            )
    links = _flannel_exec(source_node, ["ip", "-o", "link", "show"], kubeconfig).stdout
    if not re.search(rf"\b{re.escape(interface)}:", links):
        raise TrialError(f"Discovered interface {interface} is not present on {source_node}")
    logger.info("  F1 auto-discovered interface %s for probe route to %s (%s)",
                interface, target_node, target_ip)
    return interface


def _privileged_host_command(node: str, command: List[str], kubeconfig: str,
                             timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a host-network command with NET_ADMIN in a temporary pod."""
    pod = f"f1-host-{uuid.uuid4().hex[:10]}"
    manifest = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {pod}
  namespace: default
  labels:
    app: f1-link
spec:
  nodeName: {node}
  hostNetwork: true
  hostPID: true
  restartPolicy: Never
  containers:
  - name: host
    image: alpine:3.20
    command: ["sleep", "300"]
    securityContext:
      privileged: true
"""
    result = subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-"],
        input=manifest, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise TrialError(f"Could not create privileged F1 pod: {result.stderr.strip()}")
    try:
        _run_checked(
            ["kubectl", "--kubeconfig", kubeconfig, "wait",
             "--for=condition=Ready", f"pod/{pod}", "-n", "default",
             "--timeout=60s"], timeout=70,
        )
        return _run_checked(
            ["kubectl", "--kubeconfig", kubeconfig, "exec", "-n", "default",
             pod, "--"] + command, timeout=timeout,
        )
    finally:
        subprocess.run(
            ["kubectl", "--kubeconfig", kubeconfig, "delete", "pod", pod,
             "-n", "default", "--ignore-not-found", "--grace-period=0",
             "--force", "--wait=false"],
            capture_output=True, text=True, timeout=30,
        )


def _privileged_host_set_link_state(node: str, interface: str, state: str,
                                    kubeconfig: str) -> None:
    """Schedule a link change inside a host pod without waiting on its exec stream."""
    if state not in {"up", "down"}:
        raise TrialError(f"Unsupported link state: {state}")
    pod = f"f1-link-{uuid.uuid4().hex[:10]}"
    manifest = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {pod}
  namespace: default
  labels:
    app: f1-link
spec:
  nodeName: {node}
  hostNetwork: true
  hostPID: true
  restartPolicy: Never
  containers:
  - name: host
    image: alpine:3.20
    command: ["/bin/sh", "-c"]
    args: ["ip link set {interface} {state}; sleep 300"]
    securityContext:
      privileged: true
"""
    result = subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-"],
        input=manifest, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise TrialError(
            f"Could not schedule interface {interface} {state} on {node}: "
            f"{result.stderr.strip()}"
        )
    time.sleep(2)


def inject_fault_f1(config: Dict, kubeconfig: str) -> int:
    """
    F1 - L2SM link failure: disable the explicitly configured host interface.
    Returns timestamp (ns) of fault injection.
    """
    required = ("source_node", "interface")
    missing = [key for key in required if not config.get(key)]
    if missing:
        raise TrialError(
            f"F1 interface configuration is incomplete: {', '.join(missing)}. "
            "Set l2sm_failure.interface to the L2SM/underlay interface; "
            "never use flannel.1."
        )

    interface = config["interface"]
    if interface.startswith(("lo", "cni", "flannel", "docker", "br-", "veth", "virbr")):
        raise TrialError(
            f"Refusing to disable virtual/shared interface {interface!r}; "
            "configure the dedicated L2SM link interface."
        )
    _privileged_host_command(
        config["source_node"],
        ["ip", "-o", "link", "show", "dev", interface],
        kubeconfig,
        timeout=20,
    )
    logger.info(
        "Injecting F1: disabling L2SM interface %s on %s",
        interface, config["source_node"],
    )
    _privileged_host_set_link_state(
        config["source_node"], interface, "down", kubeconfig
    )
    config["_fault_injected"] = True
    t_fault = get_monotonic_ns()
    return t_fault


def recover_fault_f1(config: Dict, kubeconfig: str):
    """Restore F1 by re-enabling the configured L2SM host interface."""
    required = ("source_node", "interface")
    missing = [key for key in required if not config.get(key)]
    if missing:
        raise TrialError(f"F1 interface configuration is incomplete: {', '.join(missing)}")

    logger.info(
        "Recovering F1: enabling L2SM interface %s on %s",
        config["interface"], config["source_node"],
    )
    _privileged_host_set_link_state(
        config["source_node"], config["interface"], "up", kubeconfig
    )
    config["_fault_injected"] = False


def inject_fault_f2(config: Dict, kubeconfig: str) -> int:
    """
    F2 - Worker node loss: Drain and cordon a worker node.
    Returns timestamp (ns) of fault injection.
    """
    target_node = config["target_node"]

    logger.info("Injecting F2: Node drain on %s", target_node)
    # Drain can take tens of seconds; timestamp the beginning of the
    # disruptive operation so probes lost during eviction are measured.
    t_fault = get_monotonic_ns()

    # The sender is initially pinned to the target node so the baseline is
    # local to that node. Remove that pin immediately before draining it,
    # allowing the Deployment controller to recreate the sender elsewhere.
    namespace = config.get("_namespace")
    if namespace:
        _run_checked(
            ["kubectl", "--kubeconfig", kubeconfig, "patch",
             "deployment/probe-sender", "-n", namespace, "--type=merge",
             "-p", '{"spec":{"template":{"spec":{"nodeName":null}}}}'],
            timeout=30,
        )

    _run_checked(
        ["kubectl", "--kubeconfig", kubeconfig, "drain", target_node,
         "--ignore-daemonsets", "--delete-emptydir-data",
         "--force", "--grace-period=30", "--timeout=120s"], timeout=130
    )
    _run_checked(
        ["kubectl", "--kubeconfig", kubeconfig, "cordon", target_node], timeout=30
    )
    return t_fault


def recover_fault_f2(config: Dict, kubeconfig: str):
    """Restore F2: Uncordon the node."""
    target_node = config["target_node"]
    logger.info("Recovering F2: Uncordoning %s", target_node)
    _run_checked(["kubectl", "--kubeconfig", kubeconfig, "uncordon", target_node], timeout=30)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        result = _run_checked(
            ["kubectl", "--kubeconfig", kubeconfig, "get", "node", target_node,
             "-o", "jsonpath={.spec.unschedulable}"], timeout=15
        )
        if result.stdout.strip() != "true":
            return
        time.sleep(5)
    raise TrialError(f"F2 node {target_node} remained unschedulable after uncordon")


def inject_fault_f3(config: Dict, kubeconfig: str) -> int:
    """
    F3 - BGP route withdrawal: Remove a prefix from ExaBGP.
    Returns timestamp (ns) of fault injection.
    """
    exabgp_host = config["exabgp_host"]
    prefix = config["prefix"]

    logger.info("Injecting F3: BGP withdrawal of %s on %s", prefix, exabgp_host)

    command = config.get("withdraw_command")
    if not command:
        raise TrialError(
            "F3 requires bgp_withdrawal.withdraw_command for the real ExaBGP control interface"
        )
    _node_ip_command(exabgp_host, ["sh", "-c", command], kubeconfig)
    t_fault = get_monotonic_ns()
    return t_fault


def recover_fault_f3(config: Dict, kubeconfig: str):
    """Restore F3: Re-announce the BGP prefix."""
    exabgp_host = config["exabgp_host"]
    prefix = config["prefix"]

    logger.info("Recovering F3: Re-announcing %s on %s", prefix, exabgp_host)
    command = config.get("announce_command")
    if not command:
        raise TrialError(
            "F3 requires bgp_withdrawal.announce_command for the real ExaBGP control interface"
        )
    _node_ip_command(exabgp_host, ["sh", "-c", command], kubeconfig)


# ---------------------------------------------------------------------------
# mNCC Detection Monitoring
# ---------------------------------------------------------------------------

def monitor_mncc_detection(rmq_config: Dict, trial_id: str, fault_type: str,
                           fault_target: str, fault_gate: threading.Event,
                           timeout_s: float = 300) -> Optional[int]:
    """
    Monitor the mNCC response queue for fault detection events.
    Returns timestamp (ns) when detection event is received, or None on timeout.
    """
    if pika is None:
        raise TrialError("pika is required for mNCC detection monitoring")

    detection_time = None

    credentials = pika.PlainCredentials(rmq_config["username"], rmq_config["password"])
    conn_params = pika.ConnectionParameters(
        host=rmq_config["host"], port=rmq_config["port"], credentials=credentials
    )
    # Try a passive declare first (exchange already exists); if not, create it.
    # A failed passive declare closes the pika channel, so we open a fresh
    # connection for the active declare rather than reusing the broken one.
    connection = None
    try:
        connection = pika.BlockingConnection(conn_params)
        channel = connection.channel()
        channel.exchange_declare(exchange="mncc", exchange_type="topic", passive=True)
    except (pika.exceptions.AMQPError, OSError) as exc:
        raise TrialError(f"Cannot subscribe to mNCC monitoring exchange: {exc}") from exc

    result = channel.queue_declare(queue="", exclusive=True)
    tmp_queue = result.method.queue
    # Subscribe to all mncc events (detection notifications)
    channel.queue_bind(
        queue=tmp_queue,
        exchange="mncc",
        routing_key=rmq_config.get("monitoring_routing_key", "mncc.#"),
    )

    def on_detection(ch, method, properties, body):
        nonlocal detection_time
        try:
            msg = json.loads(body.decode("utf-8"))
            serialized = json.dumps(msg, sort_keys=True)
            event_trial_id = msg.get("trial_id") or msg.get("trialId")
            target_match = fault_target.lower() in serialized.lower()
            fault_match = fault_type.lower() in serialized.lower()
            if fault_gate.is_set() and (event_trial_id == trial_id
                                        or trial_id in serialized
                                        or (fault_match and target_match)):
                detection_time = get_monotonic_ns()
                ch.stop_consuming()
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            logger.debug("Ignoring malformed or non-detection mNCC event")

    channel.basic_consume(queue=tmp_queue, on_message_callback=on_detection, auto_ack=True)

    start = time.time()
    while detection_time is None and (time.time() - start) < timeout_s:
        connection.process_data_events(time_limit=1)

    connection.close()
    return detection_time


def monitor_external_probe_detection(probe_engine: ProbeEngine,
                                     fault_gate: threading.Event,
                                     fault_time_ns: List[Optional[int]],
                                     consecutive_failures: int,
                                     timeout_s: float = 300) -> Optional[int]:
    """Detect service impact from the independent UDP probe stream."""
    last_seen = 0
    failures = 0
    deadline = None
    while deadline is None or time.monotonic() < deadline:
        if not fault_gate.wait(timeout=0.5):
            continue
        if fault_time_ns[0] is None:
            continue
        if deadline is None:
            deadline = time.monotonic() + timeout_s
        probes = list(probe_engine.probes)
        for probe in probes[last_seen:]:
            last_seen += 1
            if probe.timestamp_ns < fault_time_ns[0]:
                continue
            if probe.received:
                failures = 0
            else:
                failures += 1
                if failures >= consecutive_failures:
                    return probe.timestamp_ns
        time.sleep(max(0.02, probe_engine.interval_ms / 1000))
    return None


def monitor_workload_relocation(kubeconfig: str, namespace: str,
                                selector: str, target_node: str,
                                fault_gate: threading.Event,
                                timeout_s: float = 300) -> Optional[int]:
    """Observe a managed workload leave the failed/drained node."""
    deadline = None
    while deadline is None or time.monotonic() < deadline:
        if not fault_gate.wait(timeout=0.5):
            continue
        if deadline is None:
            deadline = time.monotonic() + timeout_s
        result = subprocess.run(
            ["kubectl", "--kubeconfig", kubeconfig, "get", "pods",
             "-n", namespace, "-l", selector, "-o", "json"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            try:
                pods = json.loads(result.stdout).get("items", [])
            except json.JSONDecodeError:
                pods = []
            running_nodes = {
                item.get("spec", {}).get("nodeName")
                for item in pods
                if item.get("status", {}).get("phase") == "Running"
            }
            if running_nodes and any(node != target_node for node in running_nodes):
                return get_monotonic_ns()
        time.sleep(1)
    return None


def publish_remediation_intent(rmq_config: Dict, network_name: str, workload_id: str,
                                provider_name: str, domain: str):
    """
    Re-issue a provisioning intent for the affected segment (manual remediation).
    Used for C_B0 baseline.
    """
    if pika is None:
        raise TrialError("pika is required for B0 remediation")

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
    try:
        connection = pika.BlockingConnection(conn_params)
    except (pika.exceptions.AMQPError, OSError) as exc:
        raise TrialError(f"Cannot connect to RabbitMQ for B0 remediation: {exc}") from exc
    channel = connection.channel()
    channel.basic_publish(
        exchange=rmq_config["intent_exchange"],
        routing_key=rmq_config["intent_routing_key"],
        body=json.dumps(intent_msg).encode("utf-8"),
        properties=pika.BasicProperties(content_type="application/json", delivery_mode=2),
    )
    connection.close()


def publish_l2sm_intent_state(rmq_config: Dict, network_name: str,
                              workload_id: str, provider_name: str,
                              domain: str, admin_state: str) -> None:
    """Set the lifecycle state of a dedicated L2SM test network."""
    if pika is None:
        raise TrialError("pika is required for L2SM fault injection")
    if admin_state not in {"ACTIVATED", "DEACTIVATED"}:
        raise TrialError(f"Unsupported L2SM intent state: {admin_state}")

    intent_msg = {
        "userLabel": "cloud_continuum",
        "Intent": {
            "id": f"selfhealing_{admin_state.lower()}_{uuid.uuid4().hex[:8]}",
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
            "intentAdminState": admin_state,
        }
    }

    credentials = pika.PlainCredentials(rmq_config["username"], rmq_config["password"])
    conn_params = pika.ConnectionParameters(
        host=rmq_config["host"], port=rmq_config["port"], credentials=credentials
    )
    try:
        connection = pika.BlockingConnection(conn_params)
        channel = connection.channel()
        channel.basic_publish(
            exchange=rmq_config["intent_exchange"],
            routing_key=rmq_config["intent_routing_key"],
            body=json.dumps(intent_msg).encode("utf-8"),
            properties=pika.BasicProperties(
                content_type="application/json", delivery_mode=2
            ),
        )
        connection.close()
    except (pika.exceptions.AMQPError, OSError) as exc:
        raise TrialError(
            f"Could not publish L2SM intent state {admin_state}: {exc}"
        ) from exc


def wait_for_l2sm_network(kubeconfig: str, namespace: str,
                          network_name: str, present: bool,
                          timeout_s: float) -> None:
    """Wait for the L2S-M L2Network resource to reach the requested state."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["kubectl", "--kubeconfig", kubeconfig, "get", "l2network",
             "-n", namespace, network_name, "-o", "name"],
            capture_output=True, text=True, timeout=20,
        )
        exists = result.returncode == 0
        if exists == present:
            return
        time.sleep(2)
    state = "present" if present else "absent"
    raise TrialError(
        f"L2S-M L2Network {network_name!r} did not become {state} in "
        f"namespace {namespace!r} within {timeout_s:.0f}s. Verify that the "
        "L2S-M operator and l2sm.l2sm.k8s.local CRDs are installed."
    )


def ensure_namespace(kubeconfig: str, namespace: str) -> None:
    """Create a test namespace before creating namespaced L2S-M resources."""
    result = subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "create", "namespace", namespace],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0 and "AlreadyExists" not in result.stderr:
        raise TrialError(f"Failed to create namespace {namespace!r}: {result.stderr.strip()}")


def build_l2sm_network_manifest(namespace: str, network_name: str) -> str:
    """Build the upstream L2S-M L2Network resource used by the F1 test."""
    return f"""apiVersion: l2sm.l2sm.k8s.local/v1
kind: L2Network
metadata:
  name: {network_name}
  namespace: {namespace}
spec:
  type: vnet
"""


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

    if len(post_fault) < window_samples or baseline_lat_us <= 0 or baseline_bw_mbps <= 0:
        return None

    max_lat = lat_tolerance * baseline_lat_us
    min_bw = bw_tolerance * baseline_bw_mbps
    for end in range(window_samples - 1, len(post_fault)):
        window = post_fault[end - window_samples + 1:end + 1]
        if not all(p.received and p.latency_us > 0 and p.latency_us <= max_lat for p in window):
            continue
        duration_s = max((window[-1].timestamp_ns - window[0].timestamp_ns) / 1e9, 0.1)
        bandwidth_mbps = sum(p.payload_bytes for p in window) * 8 / duration_s / 1e6
        if bandwidth_mbps >= min_bw:
            return window[-1].timestamp_ns

    return None


# ---------------------------------------------------------------------------
# Trial Execution
# ---------------------------------------------------------------------------

def setup_test_pods(kubeconfig: str, namespace: str = "selfhealing-test",
                    sender_node: str = "nemo-dev-worker1",
                    receiver_node: str = "nemo-dev-worker2",
                    managed_sender: bool = False,
                    l2sm_network: Optional[str] = None,
                    l2sm_namespace: str = "default") -> Tuple[str, str, Optional[str]]:
    """Deploy two test pods on different nodes for probing."""

    # --- Delete any pre-existing pods to avoid stale Running/Unknown states ---
    logger.info("  Cleaning up any pre-existing test pods in '%s'...", namespace)
    subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "delete", "pod",
         "probe-sender", "probe-receiver", "-n", namespace,
         "--ignore-not-found", "--force", "--grace-period=0"],
        capture_output=True, timeout=30
    )

    # Create namespace (idempotent)
    r = subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-"],
        input=f'apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {namespace}\n'.encode(),
        capture_output=True, timeout=30
    )
    if r.returncode != 0:
        raise TrialError(f"Failed to create namespace '{namespace}': {r.stderr.decode(errors='replace').strip()}")

    template_network_annotation = ""
    pod_network_annotation = ""
    if l2sm_network:
        template_network_annotation = (
            f"      annotations:\n"
            f"        k8s.v1.cni.cncf.io/networks: {l2sm_namespace}/{l2sm_network}\n"
        )
        pod_network_annotation = (
            f"  annotations:\n"
            f"    k8s.v1.cni.cncf.io/networks: {l2sm_namespace}/{l2sm_network}\n"
        )

    # Deploy sender and receiver with a persistent Python UDP echo server.
    # Python is used instead of ping so the probe stream is UDP and carries
    # an explicit trial identifier.
    if managed_sender:
        sender_yaml = f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: probe-sender
  namespace: {namespace}
  labels:
    app: probe-sender
spec:
  replicas: 1
  selector:
    matchLabels:
      app: probe-sender
  template:
    metadata:
      labels:
        app: probe-sender
{template_network_annotation.rstrip()}
    spec:
      nodeName: {sender_node}
      containers:
      - name: probe
        image: python:3.12-alpine
        command: ["sleep", "infinity"]
"""
    else:
        sender_yaml = f"""
apiVersion: v1
kind: Pod
metadata:
  name: probe-sender
  namespace: {namespace}
  labels:
    app: probe-sender
{pod_network_annotation.rstrip()}
spec:
  nodeName: {sender_node}
  containers:
  - name: probe
    image: python:3.12-alpine
    command: ["sleep", "infinity"]
  restartPolicy: Never
"""
    r = subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-"],
        input=sender_yaml.encode(), capture_output=True, text=False, timeout=30
    )
    if r.returncode != 0:
        raise TrialError(f"Failed to apply probe-sender: {r.stderr.decode(errors='replace').strip()}")

    # Deploy receiver pod on worker2
    receiver_yaml = f"""
apiVersion: v1
kind: Pod
metadata:
  name: probe-receiver
  namespace: {namespace}
{pod_network_annotation.rstrip()}
spec:
  nodeName: {receiver_node}
  containers:
  - name: probe
    image: python:3.12-alpine
    command: ["python", "-c"]
    args:
    - |
      import socket
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.bind(("0.0.0.0", 9999))
      while True:
          data, addr = s.recvfrom(65535)
          s.sendto(data, addr)
  restartPolicy: Never
"""
    r = subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-"],
        input=receiver_yaml.encode(), capture_output=True, timeout=30
    )
    if r.returncode != 0:
        raise TrialError(f"Failed to apply probe-receiver: {r.stderr.decode(errors='replace').strip()}")

    # Wait for pods to be Ready — use kubectl wait, but verify its exit code
    logger.info("  Waiting for probe pods to become Ready (timeout=180s)...")
    if managed_sender:
        wait_command = [
            "kubectl", "--kubeconfig", kubeconfig, "wait",
            "--for=condition=Available", "deployment/probe-sender",
            "-n", namespace, "--timeout=180s",
        ]
    else:
        wait_command = [
            "kubectl", "--kubeconfig", kubeconfig, "wait",
            "--for=condition=Ready", "pod/probe-sender",
            "-n", namespace, "--timeout=180s",
        ]
    r = subprocess.run(wait_command, capture_output=True, timeout=190)
    if r.returncode == 0:
        r = subprocess.run(
            ["kubectl", "--kubeconfig", kubeconfig, "wait",
             "--for=condition=Ready", "pod/probe-receiver",
             "-n", namespace, "--timeout=180s"],
            capture_output=True, timeout=190,
        )
    if r.returncode != 0:
        # Dump pod status to help diagnose why they didn't become Ready
        status = subprocess.run(
            ["kubectl", "--kubeconfig", kubeconfig, "get", "pods", "-n", namespace, "-o", "wide"],
            capture_output=True, text=True, timeout=15
        )
        describe = subprocess.run(
            ["kubectl", "--kubeconfig", kubeconfig, "describe", "pods",
             "probe-sender", "probe-receiver", "-n", namespace],
            capture_output=True, text=True, timeout=15
        )
        logger.error("Pods not Ready after 180s.\nPod status:\n%s\nDescribe:\n%s",
                     status.stdout, describe.stdout[-3000:])  # last 3k chars of describe
        raise TrialError("Probe pods did not reach Ready state — see logs above for details")

    # Retrieve the L2SM secondary IP when this is an L2SM trial.
    receiver_ip = ""
    for attempt in range(10):
        r = subprocess.run(
            ["kubectl", "--kubeconfig", kubeconfig, "get", "pod", "probe-receiver",
             "-n", namespace, "-o", "jsonpath={.status.podIP}"],
            capture_output=True, text=True, timeout=15
        )
        receiver_ip = r.stdout.strip()
        if l2sm_network:
            status = subprocess.run(
                ["kubectl", "--kubeconfig", kubeconfig, "get", "pod",
                 "probe-receiver", "-n", namespace,
                 "-o", "jsonpath={.metadata.annotations.k8s\\.v1\\.cni\\.cncf\\.io/network-status}"],
                capture_output=True, text=True, timeout=15,
            )
            try:
                network_status = json.loads(status.stdout)
            except json.JSONDecodeError:
                network_status = []
            for attachment in network_status:
                if str(attachment.get("name", "")).endswith(l2sm_network):
                    ips = attachment.get("ips") or []
                    if ips:
                        receiver_ip = ips[0]
                        break
        if receiver_ip:
            break
        logger.debug("  Waiting for receiver pod IP (attempt %d/10)...", attempt + 1)
        time.sleep(2)

    if not receiver_ip:
        raise TrialError("probe-receiver is Ready but has no usable network IP")

    logger.info("  Probe pods ready. Receiver IP: %s", receiver_ip)
    return "probe-sender", receiver_ip, "app=probe-sender" if managed_sender else None


def cleanup_test_pods(kubeconfig: str, namespace: str = "selfhealing-test"):
    """Request removal of the test namespace without waiting for finalization."""
    result = subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "delete", "ns", namespace,
         "--ignore-not-found", "--force", "--grace-period=0", "--wait=false"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        raise TrialError(f"Failed to clean namespace {namespace}: {result.stderr.strip()}")
    logger.info("Cleanup requested for namespace %s; not waiting for finalization", namespace)


def run_selfhealing_trial(
    fault_type: str,
    configuration: str,  # "mNCC" or "B0"
    trial_num: int,
    config: Dict,
    kubeconfig: str,
    receiver_ip: str,
    namespace: str,
    trial_id: str,
    source_selector: Optional[str] = None,
) -> Optional[SelfHealingResult]:
    """Execute a single self-healing trial."""

    sh_config = config["selfhealing"]
    mncc_config = config["mncc"]
    rmq_config = mncc_config["rabbitmq"]

    logger.info("Trial %d | Fault=%s | Config=%s", trial_num, fault_type, configuration)

    # Sanity-check that receiver pod is still running before starting the trial
    r = subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, "get", "pod", "probe-receiver",
         "-n", namespace, "-o", "jsonpath={.status.phase}"],
        capture_output=True, text=True, timeout=15
    )
    pod_phase = r.stdout.strip()
    if pod_phase != "Running":
        logger.error("probe-receiver is not Running (phase=%r), skipping trial", pod_phase)
        return None

    # Start probe engine
    probe_engine = ProbeEngine(
        source_pod="probe-sender",
        target_ip=receiver_ip,
        trial_id=trial_id,
        namespace=namespace,
        kubeconfig=kubeconfig,
        interval_ms=sh_config["probe_interval_ms"],
        payload_bytes=sh_config.get("probe_payload_bytes", 1200),
        port=sh_config.get("probe_port", 9999),
        source_selector=source_selector,
    )
    probe_engine.start()

    # Phase 1: Stabilisation window
    stab_time = sh_config["stabilisation_window_s"]
    logger.info("  Stabilisation window: %ds", stab_time)
    time.sleep(stab_time)

    # Record baseline
    baseline_lat, baseline_bw = probe_engine.get_baseline_stats(stab_time)
    logger.info("  Baseline: lat=%.1f µs, bw=%.3f Mbps", baseline_lat, baseline_bw)
    if baseline_lat <= 0 or baseline_bw <= 0:
        probe_engine.stop()
        raise TrialError("Baseline window produced no valid UDP latency/throughput samples")

    # Phase 2: Randomised fault injection
    random_offset = random.uniform(0, sh_config["random_offset_window_s"])
    logger.info("  Waiting %.1fs random offset before fault injection...", random_offset)
    time.sleep(random_offset)

    fault_configs = {
        "F1": sh_config.get("l2sm_failure", {}),
        "F2": sh_config.get("node_loss", {}),
        "F3": sh_config.get("bgp_withdrawal", {}),
    }
    if fault_type == "F2":
        fault_configs[fault_type]["_namespace"] = namespace
    if fault_type == "F1":
        fault_configs[fault_type]["_receiver_ip"] = receiver_ip
    inject_funcs = {"F1": inject_fault_f1, "F2": inject_fault_f2, "F3": inject_fault_f3}
    recover_funcs = {"F1": recover_fault_f1, "F2": recover_fault_f2, "F3": recover_fault_f3}

    # Start detection monitor before fault injection.
    detection_thread_result = [None]
    detection_thread_error: List[Optional[BaseException]] = [None]
    fault_time_ns: List[Optional[int]] = [None]
    fault_gate = threading.Event()
    if configuration == "mNCC":
        def _monitor():
            try:
                detection_source = sh_config.get("detection_sources", {}).get(
                    fault_type, sh_config.get("detection_source", "rabbitmq")
                )
                if detection_source == "external_probe":
                    detection_thread_result[0] = monitor_external_probe_detection(
                        probe_engine, fault_gate, fault_time_ns,
                        consecutive_failures=sh_config.get(
                            "external_probe_consecutive_failures", 3
                        ),
                        timeout_s=sh_config.get("detection_timeout_s", 300),
                    )
                elif detection_source == "kubernetes_workload_relocation":
                    detection_thread_result[0] = monitor_workload_relocation(
                        kubeconfig, namespace, source_selector,
                        fault_configs[fault_type]["target_node"], fault_gate,
                        timeout_s=sh_config.get("detection_timeout_s", 300),
                    )
                elif detection_source == "rabbitmq":
                    detection_thread_result[0] = monitor_mncc_detection(
                        rmq_config, trial_id=trial_id, fault_type=fault_type,
                        fault_target=str(fault_configs.get(fault_type, {})),
                        fault_gate=fault_gate,
                        timeout_s=sh_config.get("detection_timeout_s", 300)
                    )
                else:
                    raise TrialError(
                        f"Unsupported detection source {detection_source!r}; "
                        "use external_probe, kubernetes_workload_relocation, or rabbitmq"
                    )
            except (TrialError, OSError) as exc:
                detection_thread_error[0] = exc
        det_thread = threading.Thread(target=_monitor, daemon=True)
        det_thread.start()

    t_fault = inject_funcs[fault_type](fault_configs[fault_type], kubeconfig)
    fault_time_ns[0] = t_fault
    fault_gate.set()
    logger.info("  Fault injected at T=0")

    # Phase 3: Determine T_detect
    if configuration == "mNCC":
        # Wait for the configured external observer or legacy RabbitMQ monitor.
        detection_source = sh_config.get("detection_sources", {}).get(
            fault_type, sh_config.get("detection_source", "external_probe")
        )
        det_thread.join(timeout=sh_config.get("detection_timeout_s", 300))
        t_detect = detection_thread_result[0]
        if detection_thread_error[0] is not None:
            probe_engine.stop()
            recover_funcs[fault_type](fault_configs[fault_type], kubeconfig)
            raise TrialError(str(detection_thread_error[0]))
        if t_detect is None:
            post_fault_probes = [
                probe for probe in probe_engine.probes
                if probe.timestamp_ns >= t_fault
            ]
            lost_after_fault = sum(
                1 for probe in post_fault_probes if not probe.received
            )
            logger.error(
                "External observer evidence after T_fault: %d probes, %d lost",
                len(post_fault_probes), lost_after_fault,
            )
            probe_engine.stop()
            recover_funcs[fault_type](fault_configs[fault_type], kubeconfig)
            raise TrialError(
                f"External detection timeout for source {detection_source}; "
                "no qualifying observation was recorded"
            )
    else:
        # B0: Manual detection - simulate operator observation delay
        operator_delay = sh_config["operator_delay_s"]
        logger.info("  B0: Simulating operator delay (%ds)...", operator_delay)
        time.sleep(operator_delay)
        t_detect = get_monotonic_ns()

        # The L2S-M F1 path is intentionally independent of mNCC intents:
        # B0 restores the withdrawn L2Network directly after the operator delay.
        if fault_type == "F1":
            recover_funcs[fault_type](fault_configs[fault_type], kubeconfig)
        else:
            try:
                publish_remediation_intent(
                    rmq_config,
                    network_name="selfhealing-net",
                    workload_id="selfhealing-wl",
                    provider_name=mncc_config["l2sm"]["provider_name"],
                    domain=mncc_config["l2sm"]["domain"],
                )
            except TrialError:
                try:
                    recover_funcs[fault_type](fault_configs[fault_type], kubeconfig)
                except TrialError as restore_error:
                    raise TrialError(
                        f"Manual remediation failed and fault restoration also failed: "
                        f"{restore_error}"
                    ) from restore_error
                raise
            try:
                recover_funcs[fault_type](fault_configs[fault_type], kubeconfig)
            except TrialError as restore_error:
                raise TrialError(
                    f"Manual remediation intent was published, but fault restoration failed: "
                    f"{restore_error}"
                ) from restore_error

    # Phase 4: Wait for ten consecutive valid recovery samples.
    max_wait = sh_config.get("recovery_timeout_s", 300)
    deadline = time.monotonic() + max_wait
    t_recover = None
    while time.monotonic() < deadline:
        t_recover = detect_recovery(
            list(probe_engine.probes), baseline_lat, baseline_bw,
            sh_config["latency_tolerance"], sh_config["bandwidth_tolerance"],
            sh_config["recovery_window_samples"], t_detect,
        )
        if t_recover is not None:
            break
        time.sleep(max(0.05, sh_config["probe_interval_ms"] / 1000))

    all_probes = probe_engine.stop()
    if t_recover is None:
        t_recover = detect_recovery(
            all_probes, baseline_lat, baseline_bw,
            sh_config["latency_tolerance"], sh_config["bandwidth_tolerance"],
            sh_config["recovery_window_samples"], t_detect,
        )

    if t_recover is None:
        recover_funcs[fault_type](fault_configs[fault_type], kubeconfig)
        raise TrialError("Recovery timeout; ten consecutive valid probes were not observed")

    # Restore the injected fault only after the measured recovery interval.
    recover_funcs[fault_type](fault_configs[fault_type], kubeconfig)

    # Packet loss during impact window
    impact_probes = [p for p in all_probes
                     if t_fault <= p.timestamp_ns <= t_recover]
    total_impact = len(impact_probes)
    lost_probes = len([p for p in impact_probes if not p.received])
    packet_loss_ratio = lost_probes / max(total_impact, 1)

    # Peak latency during impact
    impact_latencies = [p.latency_us for p in impact_probes if p.received and p.latency_us > 0]
    peak_latency = max(impact_latencies) if impact_latencies else 0

    if not (t_fault <= t_detect <= t_recover):
        recover_funcs[fault_type](fault_configs[fault_type], kubeconfig)
        raise TrialError("Invalid timestamp ordering: expected T_fault <= T_detect <= T_recover")
    delta_detect = ns_to_ms(t_detect - t_fault)
    delta_recover = ns_to_ms(t_recover - t_detect)
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
        detection_source=(
            sh_config.get("detection_sources", {}).get(
                fault_type, sh_config.get("detection_source", "external_probe")
            )
            if configuration == "mNCC" else "manual_operator"
        ),
    )


# ---------------------------------------------------------------------------
# Statistical Analysis
# ---------------------------------------------------------------------------

def analyze_results(results: List[SelfHealingResult]) -> Dict:
    """Compute summary statistics for self-healing results."""
    analysis = {}

    valid_results = [r for r in results if r.valid]
    if not valid_results:
        return analysis
    df = pd.DataFrame([asdict(r) for r in valid_results])

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
    fig, axes = plt.subplots(1, 2, figsize=(10, 5))
    for idx, fault in enumerate(["F1", "F2"]):
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
    fault_types = ["F1", "F2"]
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
    parser.add_argument("--trials", type=int,
                        help="Override trials_per_fault for a controlled smoke test")
    parser.add_argument("--stabilisation", type=float,
                        help="Override stabilisation window for validation only")
    parser.add_argument("--random-offset", type=float,
                        help="Override random fault offset window for validation only")
    parser.add_argument("--detection-timeout", type=float,
                        help="Override external detection timeout for validation only")
    parser.add_argument("--recovery-timeout", type=float,
                        help="Override recovery timeout for validation only")
    args = parser.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)

    sh_config = config["selfhealing"]
    if args.stabilisation is not None:
        sh_config["stabilisation_window_s"] = args.stabilisation
    if args.random_offset is not None:
        sh_config["random_offset_window_s"] = args.random_offset
    if args.detection_timeout is not None:
        sh_config["detection_timeout_s"] = args.detection_timeout
    if args.recovery_timeout is not None:
        sh_config["recovery_timeout_s"] = args.recovery_timeout
    kubeconfig = config["cluster"]["kubeconfig"]
    fault_types = args.faults or sh_config["fault_types"]
    configurations = args.configs
    trials = args.trials if args.trials is not None else sh_config["trials_per_fault"]
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

    # Execute trials
    results: List[SelfHealingResult] = []
    invalid_trials: List[Dict] = []

    for fault in fault_types:
        for cfg in configurations:
            logger.info("-" * 50)
            logger.info("Starting series: Fault=%s, Config=%s (%d trials)", fault, cfg, trials)

            for trial_num in range(1, trials + 1):
                trial_id = f"{fault}-{cfg}-{trial_num}-{uuid.uuid4().hex[:8]}"
                namespace = "selfhealing-" + uuid.uuid4().hex[:12]
                receiver_ip = None
                source_selector = None
                l2sm_network = None
                l2sm_namespace = "default"
                fault_cfg = {}
                try:
                    fault_cfg = sh_config.get({
                        "F1": "l2sm_failure",
                        "F2": "node_loss",
                        "F3": "bgp_withdrawal",
                    }[fault], {})
                    if fault == "F1":
                        sender_node = fault_cfg["source_node"]
                        receiver_node = fault_cfg["target_node"]
                        managed_sender = False
                    elif fault == "F2":
                        sender_node = fault_cfg["target_node"]
                        receiver_node = config["cluster"]["node_names"][2]
                        managed_sender = True
                    else:
                        sender_node = config["cluster"]["node_names"][1]
                        receiver_node = config["cluster"]["node_names"][2]
                        managed_sender = False
                    if args.skip_setup:
                        namespace = "selfhealing-test"
                    else:
                        _, receiver_ip, source_selector = setup_test_pods(
                            kubeconfig, namespace, sender_node, receiver_node,
                            managed_sender=managed_sender,
                            l2sm_network=l2sm_network,
                            l2sm_namespace=l2sm_namespace,
                        )
                    if receiver_ip is None:
                        result = subprocess.run(
                            ["kubectl", "--kubeconfig", kubeconfig, "get", "pod",
                             "probe-receiver", "-n", namespace,
                             "-o", "jsonpath={.status.podIP}"],
                            capture_output=True, text=True, timeout=15,
                        )
                        if result.returncode != 0 or not result.stdout.strip():
                            raise TrialError("probe-receiver has no usable pod IP")
                        receiver_ip = result.stdout.strip()
                    result = run_selfhealing_trial(
                        fault_type=fault,
                        configuration=cfg,
                        trial_num=trial_num,
                        config=config,
                        kubeconfig=kubeconfig,
                        receiver_ip=receiver_ip,
                        namespace=namespace,
                        trial_id=trial_id,
                        source_selector=source_selector,
                    )
                    if result:
                        results.append(result)
                except TrialError as e:
                    logger.error("Trial %d FAILED: %s", trial_num, str(e))
                    invalid_trials.append({
                        "fault_type": fault, "configuration": cfg,
                        "trial_number": trial_num, "trial_id": trial_id,
                        "valid": False, "failure_reason": str(e),
                    })
                finally:
                    if not args.skip_setup:
                        try:
                            cleanup_test_pods(kubeconfig, namespace)
                        except TrialError as cleanup_error:
                            logger.error("Trial cleanup failed: %s", cleanup_error)
                    if fault == "F1" and fault_cfg.get("_fault_injected"):
                        try:
                            recover_fault_f1(fault_cfg, kubeconfig)
                        except TrialError as restore_error:
                            logger.error("F1 interface cleanup failed: %s", restore_error)
                    if fault == "F1":
                        subprocess.run(
                            ["kubectl", "--kubeconfig", kubeconfig, "delete", "pod",
                             "-n", "default", "-l", "app=f1-link",
                             "--ignore-not-found", "--wait=false"],
                            capture_output=True, text=True, timeout=30,
                        )
                    if l2sm_network:
                        try:
                            subprocess.run(
                                ["kubectl", "--kubeconfig", kubeconfig, "delete",
                                 "l2network", l2sm_network, "-n", l2sm_namespace,
                                 "--ignore-not-found", "--wait=false"],
                                capture_output=True, text=True, timeout=30,
                            )
                        except TrialError as l2sm_cleanup_error:
                            logger.error(
                                "L2SM cleanup request failed for %s: %s",
                                l2sm_network, l2sm_cleanup_error,
                            )

                # Wait between trials for cluster stabilisation
                time.sleep(30)

    # Save raw results
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(exist_ok=True)
    with open(raw_dir / "selfhealing_results.json", "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    with open(raw_dir / "invalid_trials.json", "w") as f:
        json.dump(invalid_trials, f, indent=2)
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

    logger.info("=" * 70)
    logger.info("SELF-HEALING EVALUATION COMPLETE")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
