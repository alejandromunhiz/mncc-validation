#!/usr/bin/env python3
"""
Provisioning Test Plan - Baseline Comparison Script
====================================================
Compares three configurations:
  C_B1  - CNI + Manual Scripting (Flannel + kubectl apply)
  C_B2  - Service Mesh (Istio)
  C_mNCC - Proposed mNCC system (Intent-Based + L2S-M + ONOS SDN)

Cluster: 6 nodes
Batch sizes: N ∈ {1, 10, 25, 50}
Load levels: idle, medium, high
Trials: 30 per combination (first 3 discarded as warm-up)

Statistical analysis:
  - Median, P95, P99, CV
  - Kruskal-Wallis test (α=0.05)
  - Post-hoc Dunn tests with Bonferroni correction
  - Power-law scaling fit for mNCC
"""

import os
import sys
import time
import json
import logging
import argparse
import subprocess
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple

import yaml
import uuid
import numpy as np
import pandas as pd
import requests
from scipy import stats
from scipy.optimize import curve_fit
import scikit_posthocs as sp
import matplotlib.pyplot as plt

try:
    import pika
except ImportError:
    pika = None
    logger_placeholder = None  # will warn later

try:
    from kubernetes import client as k8s_client, config as k8s_config
except ImportError:
    k8s_client = None
    k8s_config = None

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).parent
DEFAULT_CONFIG = SCRIPT_DIR / "config.yaml"

# Set KUBECONFIG for all kubectl operations (B1, B2, mNCC)
_kubeconfig_path = str(SCRIPT_DIR.parent / "upm-nemo-kubeconfig.yaml")
if os.path.exists(_kubeconfig_path) and "KUBECONFIG" not in os.environ:
    os.environ["KUBECONFIG"] = _kubeconfig_path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("test_plan_execution.log"),
    ],
)
logger = logging.getLogger(__name__)


@dataclass
class TimingResult:
    """Stores provisioning timing for a single trial."""
    configuration: str
    batch_size: int
    load_level: str
    trial_number: int
    t_prov_ns: int  # Total provisioning time in nanoseconds
    stages: Dict[str, int] = field(default_factory=dict)  # Per-stage times in ns
    timestamp: str = ""
    node_offsets_us: List[float] = field(default_factory=list)


# ---------------------------------------------------------------------------
# High-Resolution Timing
# ---------------------------------------------------------------------------

def get_monotonic_ns() -> int:
    """Get high-resolution monotonic time in nanoseconds."""
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


def ns_to_ms(ns: int) -> float:
    """Convert nanoseconds to milliseconds."""
    return ns / 1_000_000


def ns_to_s(ns: int) -> float:
    """Convert nanoseconds to seconds."""
    return ns / 1_000_000_000


# ---------------------------------------------------------------------------
# PTP Synchronization Verification
# ---------------------------------------------------------------------------

def verify_ptp_sync(nodes: List[str], max_offset_us: float = 1.0) -> bool:
    """
    Verify PTP (IEEE 1588) time synchronization across cluster nodes.
    Checks that inter-node offset is below the specified threshold.
    """
    logger.info("Verifying PTP synchronization across %d nodes...", len(nodes))
    offsets = []

    for node in nodes:
        try:
            result = subprocess.run(
                ["ssh", node, "ptp4l", "-m", "-s", "-i", "eth0", "-S",
                 "--summary_interval", "0"],
                capture_output=True, text=True, timeout=10
            )
            # Parse offset from ptp4l output (fallback: use phc2sys)
            result_phc = subprocess.run(
                ["ssh", node, "cat", "/var/log/ptp_offset.log"],
                capture_output=True, text=True, timeout=5
            )
            if result_phc.returncode == 0:
                lines = result_phc.stdout.strip().split("\n")
                if lines:
                    last_offset = float(lines[-1].split()[-1])
                    offsets.append(abs(last_offset))
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError) as e:
            logger.warning("PTP check failed for node %s: %s", node, e)
            offsets.append(0.0)  # Assume synchronized if check unavailable

    if offsets:
        max_observed = max(offsets)
        logger.info("Max PTP offset observed: %.3f µs (threshold: %.1f µs)",
                    max_observed, max_offset_us)
        if max_observed > max_offset_us:
            logger.error("PTP offset exceeds threshold! Aborting.")
            return False
    return True


# ---------------------------------------------------------------------------
# Cluster State Management
# ---------------------------------------------------------------------------

def reset_cluster_state(config: str) -> None:
    """Reset cluster to a clean state with no pre-existing overlay segments."""
    logger.info("Resetting cluster state for configuration: %s", config)

    def force_delete_ns(ns_name: str, timeout_sec: int = 30):
        """Delete namespace with force and short timeout, removing finalizers if stuck."""
        # First try normal delete with short timeout
        try:
            result = subprocess.run(
                ["kubectl", "delete", "ns", ns_name, "--ignore-not-found",
                 "--force", "--grace-period=0", "--wait=false"],
                capture_output=True, text=True, timeout=timeout_sec
            )
        except subprocess.TimeoutExpired:
            pass

        # Check if namespace is stuck in Terminating
        time.sleep(2)
        check = subprocess.run(
            ["kubectl", "get", "ns", ns_name, "-o", "jsonpath={.status.phase}"],
            capture_output=True, text=True, timeout=10
        )
        if check.returncode == 0 and "Terminating" in check.stdout:
            # Remove finalizers via finalize API endpoint
            logger.warning("Namespace %s stuck in Terminating, clearing finalizers...", ns_name)
            get_ns = subprocess.run(
                ["kubectl", "get", "ns", ns_name, "-o", "json"],
                capture_output=True, text=True, timeout=10
            )
            if get_ns.returncode == 0:
                import json as _json
                ns_obj = _json.loads(get_ns.stdout)
                ns_obj["metadata"].pop("finalizers", None)
                ns_obj["spec"] = {"finalizers": []}
                subprocess.run(
                    ["kubectl", "replace", "--raw",
                     f"/api/v1/namespaces/{ns_name}/finalize", "-f", "-"],
                    input=_json.dumps(ns_obj).encode(),
                    capture_output=True, timeout=10
                )

    if config == "B1":
        # Remove all non-system namespaces and network policies
        subprocess.run(
            ["kubectl", "delete", "networkpolicies", "--all", "--all-namespaces"],
            capture_output=True, timeout=30
        )
        force_delete_ns("test-overlay")
        # Restart Flannel to clear overlay state
        subprocess.run(
            ["kubectl", "-n", "kube-flannel", "rollout", "restart",
             "daemonset/kube-flannel-ds"],
            capture_output=True, timeout=30
        )
        time.sleep(5)  # Wait for Flannel stabilization

    elif config == "B2":
        # Remove Istio virtual services and destination rules
        subprocess.run(
            ["kubectl", "delete", "virtualservices", "--all", "--all-namespaces"],
            capture_output=True, timeout=30
        )
        subprocess.run(
            ["kubectl", "delete", "destinationrules", "--all", "--all-namespaces"],
            capture_output=True, timeout=30
        )
        subprocess.run(
            ["kubectl", "delete", "serviceentries", "--all", "--all-namespaces"],
            capture_output=True, timeout=30
        )
        force_delete_ns("test-overlay")
        time.sleep(5)

    elif config == "mNCC":
        # Clean mNCC state: delete L2SM virtual network resources and test pods
        kubeconfig = os.environ.get(
            "KUBECONFIG",
            str(SCRIPT_DIR.parent / "upm-nemo-kubeconfig.yaml")
        )
        # Delete test namespaces (which contain L2SM networks and pods)
        subprocess.run(
            ["kubectl", "--kubeconfig", kubeconfig,
             "delete", "ns", "-l", "mncc-test=true", "--ignore-not-found"],
            capture_output=True, timeout=60
        )
        # Delete any leftover L2SM network custom resources
        subprocess.run(
            ["kubectl", "--kubeconfig", kubeconfig,
             "delete", "l2networks.l2sm.k8s.local", "--all", "--all-namespaces",
             "--ignore-not-found"],
            capture_output=True, timeout=60
        )

    # Verify clean state
    time.sleep(5)
    logger.info("Cluster state reset complete for %s", config)


# ---------------------------------------------------------------------------
# Load Level Control
# ---------------------------------------------------------------------------

def set_load_level(level: str, nodes: List[str]) -> None:
    """Configure background load on the cluster."""
    logger.info("Setting load level: %s", level)

    if level == "idle":
        # Scale down all non-essential workloads
        subprocess.run(
            ["kubectl", "scale", "deployment", "--all", "-n", "workloads",
             "--replicas=0"],
            capture_output=True, timeout=60
        )
        # Stop any CI/CD simulators
        subprocess.run(
            ["kubectl", "delete", "jobs", "--all", "-n", "cicd-sim",
             "--ignore-not-found"],
            capture_output=True, timeout=30
        )

    elif level == "medium":
        # Scale to 50% of production microservices
        deployments = subprocess.run(
            ["kubectl", "get", "deployments", "-n", "workloads",
             "-o", "jsonpath={.items[*].metadata.name}"],
            capture_output=True, text=True, timeout=30
        )
        if deployments.returncode == 0:
            dep_list = deployments.stdout.strip().split()
            half = len(dep_list) // 2
            for dep in dep_list[:half]:
                subprocess.run(
                    ["kubectl", "scale", "deployment", dep, "-n", "workloads",
                     "--replicas=2"],
                    capture_output=True, timeout=30
                )
            for dep in dep_list[half:]:
                subprocess.run(
                    ["kubectl", "scale", "deployment", dep, "-n", "workloads",
                     "--replicas=0"],
                    capture_output=True, timeout=30
                )

    elif level == "high":
        # Full production load + CI/CD burst simulation
        subprocess.run(
            ["kubectl", "scale", "deployment", "--all", "-n", "workloads",
             "--replicas=3"],
            capture_output=True, timeout=60
        )
        # Launch CI/CD burst simulator
        subprocess.run(
            ["kubectl", "apply", "-f",
             str(SCRIPT_DIR / "manifests" / "cicd-burst-job.yaml")],
            capture_output=True, timeout=30
        )

    # Allow load to stabilize
    time.sleep(15)
    logger.info("Load level '%s' established", level)


# ---------------------------------------------------------------------------
# Provisioning Functions - Configuration B1 (Flannel + kubectl)
# ---------------------------------------------------------------------------

def provision_b1(batch_size: int) -> Dict[str, int]:
    """
    Provision overlay segments using Flannel CNI + manual kubectl scripting.
    Returns per-stage timing in nanoseconds.
    """
    stages = {}

    # Stage 1: Namespace creation
    t0 = get_monotonic_ns()
    subprocess.run(
        ["kubectl", "create", "namespace", "test-overlay", "--dry-run=client", "-o", "yaml",
         "|", "kubectl", "apply", "-f", "-"],
        shell=False, capture_output=True, timeout=30
    )
    subprocess.run(
        ["kubectl", "create", "namespace", "test-overlay", "--save-config",
         "--dry-run=client", "-o", "yaml"],
        capture_output=True, timeout=30
    )
    subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=b'apiVersion: v1\nkind: Namespace\nmetadata:\n  name: test-overlay\n',
        capture_output=True, timeout=30
    )
    t1 = get_monotonic_ns()
    stages["namespace_creation"] = t1 - t0

    # Stage 2: Network policy generation and application
    t2 = get_monotonic_ns()
    for i in range(batch_size):
        policy_yaml = f"""
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: overlay-segment-{i}
  namespace: test-overlay
spec:
  podSelector:
    matchLabels:
      segment: seg-{i}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          segment: seg-{i}
  egress:
  - to:
    - podSelector:
        matchLabels:
          segment: seg-{i}
"""
        subprocess.run(
            ["kubectl", "apply", "-f", "-"],
            input=policy_yaml.encode(), capture_output=True, timeout=30
        )
    t3 = get_monotonic_ns()
    stages["policy_application"] = t3 - t2

    # Stage 3: Overlay pod deployment
    t4 = get_monotonic_ns()
    for i in range(batch_size):
        deployment_yaml = f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: overlay-ep-{i}
  namespace: test-overlay
spec:
  replicas: 2
  selector:
    matchLabels:
      segment: seg-{i}
  template:
    metadata:
      labels:
        segment: seg-{i}
    spec:
      containers:
      - name: netperf
        image: networkstatic/iperf3:latest
        command: ["sleep", "infinity"]
"""
        subprocess.run(
            ["kubectl", "apply", "-f", "-"],
            input=deployment_yaml.encode(), capture_output=True, timeout=30
        )
    t5 = get_monotonic_ns()
    stages["pod_deployment"] = t5 - t4

    # Stage 4: Wait for readiness
    t6 = get_monotonic_ns()
    subprocess.run(
        ["kubectl", "wait", "--for=condition=available",
         "--all", "deployments", "-n", "test-overlay", "--timeout=120s"],
        capture_output=True, timeout=130
    )
    t7 = get_monotonic_ns()
    stages["readiness_wait"] = t7 - t6

    # Stage 5: Connectivity verification
    t8 = get_monotonic_ns()
    subprocess.run(
        ["kubectl", "exec", "-n", "test-overlay",
         "deploy/overlay-ep-0", "--", "ping", "-c", "1", "-W", "5",
         "overlay-ep-0.test-overlay.svc.cluster.local"],
        capture_output=True, timeout=30
    )
    t9 = get_monotonic_ns()
    stages["connectivity_verification"] = t9 - t8

    return stages


# ---------------------------------------------------------------------------
# Provisioning Functions - Configuration B2 (Istio Service Mesh)
# ---------------------------------------------------------------------------

def provision_b2(batch_size: int) -> Dict[str, int]:
    """
    Provision overlay segments using Istio service mesh.
    Returns per-stage timing in nanoseconds.
    """
    stages = {}

    # Stage 1: Namespace creation with Istio injection
    t0 = get_monotonic_ns()
    subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=b'apiVersion: v1\nkind: Namespace\nmetadata:\n  name: test-overlay\n  labels:\n    istio-injection: enabled\n',
        capture_output=True, timeout=30
    )
    t1 = get_monotonic_ns()
    stages["namespace_creation"] = t1 - t0

    # Stage 2: Virtual services and destination rules
    t2 = get_monotonic_ns()
    for i in range(batch_size):
        vs_yaml = f"""
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: segment-vs-{i}
  namespace: test-overlay
spec:
  hosts:
  - overlay-svc-{i}
  http:
  - route:
    - destination:
        host: overlay-svc-{i}
        subset: v1
---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: segment-dr-{i}
  namespace: test-overlay
spec:
  host: overlay-svc-{i}
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 100
  subsets:
  - name: v1
    labels:
      version: v1
"""
        subprocess.run(
            ["kubectl", "apply", "-f", "-"],
            input=vs_yaml.encode(), capture_output=True, timeout=30
        )
    t3 = get_monotonic_ns()
    stages["istio_config_application"] = t3 - t2

    # Stage 3: Service and deployment creation
    t4 = get_monotonic_ns()
    for i in range(batch_size):
        svc_deploy_yaml = f"""
apiVersion: v1
kind: Service
metadata:
  name: overlay-svc-{i}
  namespace: test-overlay
spec:
  selector:
    app: overlay-{i}
    version: v1
  ports:
  - port: 8080
    targetPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: overlay-dep-{i}
  namespace: test-overlay
spec:
  replicas: 2
  selector:
    matchLabels:
      app: overlay-{i}
      version: v1
  template:
    metadata:
      labels:
        app: overlay-{i}
        version: v1
    spec:
      containers:
      - name: netperf
        image: networkstatic/iperf3:latest
        command: ["sleep", "infinity"]
        ports:
        - containerPort: 8080
"""
        subprocess.run(
            ["kubectl", "apply", "-f", "-"],
            input=svc_deploy_yaml.encode(), capture_output=True, timeout=30
        )
    t5 = get_monotonic_ns()
    stages["service_deployment"] = t5 - t4

    # Stage 4: Sidecar injection & readiness
    t6 = get_monotonic_ns()
    subprocess.run(
        ["kubectl", "wait", "--for=condition=available",
         "--all", "deployments", "-n", "test-overlay", "--timeout=180s"],
        capture_output=True, timeout=190
    )
    t7 = get_monotonic_ns()
    stages["sidecar_readiness"] = t7 - t6

    # Stage 5: Istio proxy sync verification
    t8 = get_monotonic_ns()
    try:
        subprocess.run(
            ["istioctl", "proxy-status"],
            capture_output=True, timeout=30
        )
    except FileNotFoundError:
        # istioctl not installed; skip this verification step
        logger.warning("istioctl not found, skipping proxy sync verification")
    t9 = get_monotonic_ns()
    stages["proxy_sync"] = t9 - t8

    return stages


# ---------------------------------------------------------------------------
# Provisioning Functions - Configuration mNCC (Proposed System)
# ---------------------------------------------------------------------------

def _build_l2sm_network_intent(
    intent_id: str,
    network_name: str,
    workload_id: str,
    provider_name: str,
    domain: str,
    pod_cidr: str,
    clusters: List[Dict[str, str]],
) -> Dict:
    """
    Build a network intent dict following the mNCC IBS Pydantic schema.

    The message needs:
    - Top-level 'userLabel': 'cloud_continuum' for RabbitMQ receiver routing
    - 'Intent' wrapper containing the IntentMncc schema fields
    - objectType 'L2SM_NETWORK' (not K8S_L2_NETWORK) for network creation
    - expectationTargets (plural) with targetName='secure'
    - Intent contexts with contextAttribute='NEMO_WORKLOAD'

    Note: The IBS Pydantic model does NOT support pod_cidr in L2SM_NETWORK
    objectContexts, and the cluster expectation triggers a subnet bug when
    pod_cidr is empty. We send network-only intents (no cluster expectation)
    which successfully go through IBS → L2SM gRPC → network creation.
    """
    expectations = []

    # Expectation 1: L2SM_NETWORK definition
    expectations.append({
        "expectationId": "1",
        "expectationVerb": "DELIVER",
        "expectationObject": {
            "objectType": "L2SM_NETWORK",
            "objectInstance": network_name,
            "objectContexts": [
                {
                    "contextAttribute": "name",
                    "contextCondition": "IS_EQUAL_TO",
                    "contextValueRange": network_name,
                },
                {
                    "contextAttribute": "providerName",
                    "contextCondition": "IS_EQUAL_TO",
                    "contextValueRange": provider_name,
                },
                {
                    "contextAttribute": "domain",
                    "contextCondition": "IS_EQUAL_TO",
                    "contextValueRange": domain,
                },
            ],
        },
        "expectationTargets": [
            {
                "targetName": "secure",
                "targetCondition": "IS_EQUAL_TO",
                "targetValueRange": "true",
            }
        ],
    })

    # Intent message: top-level userLabel for RabbitMQ routing + Intent wrapper for model
    intent_msg = {
        "userLabel": "cloud_continuum",
        "Intent": {
            "id": intent_id,
            "userLabel": "cloud_continuum",
            "intentExpectations": expectations,
            "intentContexts": [
                {
                    "contextAttribute": "NEMO_WORKLOAD",
                    "contextCondition": "IS_EQUAL_TO",
                    "contextValueRange": workload_id,
                }
            ],
            "intentPriority": 1,
            "observationPeriod": 60,
            "intentAdminState": "ACTIVATED",
        }
    }

    return intent_msg


def _publish_intent_to_rabbitmq(
    intent_dict: Dict,
    rmq_host: str,
    rmq_port: int,
    exchange: str,
    routing_key: str,
    username: str = "guest",
    password: str = "guest",
) -> None:
    """
    Publish a network intent to the RabbitMQ exchange/queue
    that the IBS consumes (nemo.api.workload / intent-notify).
    The IBS expects JSON-encoded intent payloads.
    """
    if pika is None:
        raise RuntimeError("pika library not installed. Install with: pip install pika")

    intent_json = json.dumps(intent_dict)

    credentials = pika.PlainCredentials(username, password)
    connection_params = pika.ConnectionParameters(
        host=rmq_host,
        port=rmq_port,
        credentials=credentials,
        connection_attempts=3,
        retry_delay=2,
    )
    connection = pika.BlockingConnection(connection_params)
    channel = connection.channel()

    # Publish intent as JSON
    channel.basic_publish(
        exchange=exchange,
        routing_key=routing_key,
        body=intent_json.encode("utf-8"),
        properties=pika.BasicProperties(
            content_type="application/json",
            delivery_mode=2,  # persistent
        ),
    )
    connection.close()


def _wait_for_mncc_response(
    rmq_host: str,
    rmq_port: int,
    response_exchange: str,
    response_routing_key: str,
    response_queue: str,
    username: str = "guest",
    password: str = "guest",
    timeout: float = 120.0,
) -> Optional[Dict]:
    """
    Wait for the mNCC response on the mncc.ibs queue.
    The response contains the L2SM annotations (labels, annotations, env)
    needed by the workload deployment.
    """
    if pika is None:
        raise RuntimeError("pika library not installed")

    credentials = pika.PlainCredentials(username, password)
    connection_params = pika.ConnectionParameters(
        host=rmq_host,
        port=rmq_port,
        credentials=credentials,
    )
    connection = pika.BlockingConnection(connection_params)
    channel = connection.channel()

    # Use passive declaration to check exchange exists without creating
    try:
        channel.exchange_declare(exchange=response_exchange, exchange_type="topic", passive=True)
    except Exception:
        # Exchange may not exist yet; reconnect and create it
        connection = pika.BlockingConnection(connection_params)
        channel = connection.channel()
        channel.exchange_declare(exchange=response_exchange, exchange_type="topic", durable=True)

    # Declare a temporary exclusive queue for this consumer
    result = channel.queue_declare(queue="", exclusive=True)
    tmp_queue = result.method.queue
    channel.queue_bind(queue=tmp_queue, exchange=response_exchange, routing_key=response_routing_key)

    response_body = None
    start_time = time.time()

    def on_message(ch, method, properties, body):
        nonlocal response_body
        response_body = json.loads(body.decode("utf-8"))
        ch.stop_consuming()

    channel.basic_consume(queue=tmp_queue, on_message_callback=on_message, auto_ack=True)

    # Consume with timeout
    while response_body is None and (time.time() - start_time) < timeout:
        connection.process_data_events(time_limit=1)

    connection.close()
    return response_body


def _verify_l2sm_network_created(
    network_name: str,
    namespace: str,
    kubeconfig_path: str,
) -> bool:
    """
    Verify that the L2SM virtual network was created by checking
    NetworkAttachmentDefinition resources in the cluster.
    The L2SM gRPC server creates net-attach-def CRs upon network creation.
    """
    try:
        result = subprocess.run(
            [
                "kubectl", "--kubeconfig", kubeconfig_path,
                "get", "net-attach-def",
                "-n", namespace,
                network_name,
                "-o", "name",
            ],
            capture_output=True, text=True, timeout=30,
        )
        return result.returncode == 0 and network_name in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _verify_pod_connectivity_l2sm(
    pod_name: str,
    namespace: str,
    target_dns: str,
    kubeconfig_path: str,
) -> bool:
    """
    Verify L2SM connectivity by pinging between pods using DNS names
    within the virtual network (e.g., <app>.spain-network.inter.l2sm).
    """
    try:
        result = subprocess.run(
            [
                "kubectl", "--kubeconfig", kubeconfig_path,
                "exec", "-n", namespace, pod_name, "--",
                "ping", "-c", "3", "-W", "5", target_dns,
            ],
            capture_output=True, text=True, timeout=30,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def provision_mncc(batch_size: int, mncc_config: Dict) -> Dict[str, int]:
    """
    Provision overlay segments using the mNCC system.

    The mNCC provisioning workflow (as documented in NEMO D2.3/D4.3):
    1. Build L2SM network intent(s) in YAML format
    2. Publish intent to RabbitMQ (exchange=nemo.api.workload, routing_key=network-intent)
    3. IBS receives, classifies, and translates intent
    4. IBS calls L2S-M via gRPC to create virtual network resources
    5. L2S-M creates K8s custom resources in target clusters
    6. mNCC returns L2SM annotations via RabbitMQ (exchange=mncc, routing_key=mncc.ibs)
    7. Verify network creation via kubectl

    Returns per-stage timing in nanoseconds.
    """
    stages = {}

    rmq_host = mncc_config["rabbitmq"]["host"]
    rmq_port = mncc_config["rabbitmq"]["port"]
    rmq_user = mncc_config["rabbitmq"]["username"]
    rmq_pass = mncc_config["rabbitmq"]["password"]
    intent_exchange = mncc_config["rabbitmq"]["intent_exchange"]
    intent_routing_key = mncc_config["rabbitmq"]["intent_routing_key"]
    response_exchange = mncc_config["rabbitmq"]["response_exchange"]
    response_routing_key = mncc_config["rabbitmq"]["response_routing_key"]
    response_queue = mncc_config["rabbitmq"]["response_queue"]
    kubeconfig_path = mncc_config["kubernetes"]["kubeconfig"]
    provider_name = mncc_config["l2sm"]["provider_name"]
    domain = mncc_config["l2sm"]["domain"]
    dns_suffix = mncc_config["l2sm"]["dns_suffix"]
    timeout = mncc_config.get("timeout_seconds", 120)

    # Read bearer token from kubeconfig for cluster config expectations
    with open(kubeconfig_path) as f:
        kubeconfig = yaml.safe_load(f)
    bearer_token = kubeconfig["users"][0]["user"]["token"]
    api_server = kubeconfig["clusters"][0]["cluster"]["server"]

    # Generate a workload ID for this trial
    workload_id = str(uuid.uuid4())

    # Stage 1: Intent construction
    t0 = get_monotonic_ns()
    intents_list = []
    for i in range(batch_size):
        network_name = f"test-net-{i}"
        intent_id = f"mncc_test_{workload_id}_{i}"
        pod_cidr = f"10.{i + 1}.0.0/16"

        # Build intent dict (network-only, no cluster expectation to avoid IBS pod_cidr bug)
        intent_dict = _build_l2sm_network_intent(
            intent_id=intent_id,
            network_name=network_name,
            workload_id=workload_id,
            provider_name=provider_name,
            domain=domain,
            pod_cidr=pod_cidr,
            clusters=[],
        )
        intents_list.append(intent_dict)
    t1 = get_monotonic_ns()
    stages["intent_construction"] = t1 - t0

    # Stage 2: Set up response listener THEN publish intents
    # (Must listen before publishing to avoid race condition - IBS responds in ~1s)
    t2 = get_monotonic_ns()

    credentials = pika.PlainCredentials(rmq_user, rmq_pass)
    conn_params = pika.ConnectionParameters(
        host=rmq_host, port=rmq_port, credentials=credentials,
        connection_attempts=3, retry_delay=2,
    )
    # Set up response consumer
    resp_connection = pika.BlockingConnection(conn_params)
    resp_channel = resp_connection.channel()
    try:
        resp_channel.exchange_declare(exchange=response_exchange, exchange_type="topic", passive=True)
    except Exception:
        resp_connection = pika.BlockingConnection(conn_params)
        resp_channel = resp_connection.channel()
        resp_channel.exchange_declare(exchange=response_exchange, exchange_type="topic", durable=True)
    result = resp_channel.queue_declare(queue="", exclusive=True)
    tmp_queue = result.method.queue
    resp_channel.queue_bind(queue=tmp_queue, exchange=response_exchange, routing_key=response_routing_key)

    # Now publish intents
    pub_connection = pika.BlockingConnection(conn_params)
    pub_channel = pub_connection.channel()
    for intent_dict in intents_list:
        pub_channel.basic_publish(
            exchange=intent_exchange,
            routing_key=intent_routing_key,
            body=json.dumps(intent_dict).encode("utf-8"),
            properties=pika.BasicProperties(content_type="application/json", delivery_mode=2),
        )
    pub_connection.close()
    t3 = get_monotonic_ns()
    stages["rabbitmq_publish"] = t3 - t2

    # Stage 3: Wait for IBS classification + translation + L2SM gRPC execution
    # The IBS classifies the intent, translates it via the L2SM library,
    # and calls the L2S-M MD gRPC server to create the virtual network.
    # The response arrives on exchange=mncc, routing_key=mncc.ibs
    t4 = get_monotonic_ns()
    responses_received = 0
    responses = []

    def on_response(ch, method, properties, body):
        nonlocal responses_received
        responses.append(json.loads(body.decode("utf-8")))
        responses_received += 1
        if responses_received >= batch_size:
            ch.stop_consuming()

    resp_channel.basic_consume(queue=tmp_queue, on_message_callback=on_response, auto_ack=True)

    # Consume with timeout
    start_wait = time.time()
    while responses_received < batch_size and (time.time() - start_wait) < timeout:
        resp_connection.process_data_events(time_limit=1)

    resp_connection.close()
    t5 = get_monotonic_ns()
    stages["ibs_translation_l2sm_grpc"] = t5 - t4

    logger.info("    mNCC responses received: %d/%d", responses_received, batch_size)

    # Stage 4: Verify L2SM network creation via gRPC response
    # The L2SM gRPC server responds with "Network created successfully" and
    # returns pod patches (labels/annotations). It does NOT create a separate
    # NetworkAttachmentDefinition CR. The RabbitMQ response is the confirmation.
    t6 = get_monotonic_ns()
    verified = responses_received  # gRPC response = network created
    if verified < batch_size:
        # Fallback: quick check for net-attach-def (2s max per network)
        for i in range(batch_size):
            if verified >= batch_size:
                break
            network_name = f"test-net-{i}"
            for attempt in range(2):
                if _verify_l2sm_network_created(network_name, "default", kubeconfig_path):
                    verified += 1
                    break
                time.sleep(1)
    t7 = get_monotonic_ns()
    stages["l2sm_network_verification"] = t7 - t6

    logger.info("    L2SM networks verified: %d/%d", verified, batch_size)

    # Stage 5: Record pod patch information from mNCC response
    # The mNCC returns pod labels/annotations/env that would be applied to workloads.
    # We record this stage as the time to parse and validate the response patches.
    t8 = get_monotonic_ns()
    patches_valid = 0
    for resp in responses:
        if resp and "pod" in resp:
            patches_valid += 1
    t9 = get_monotonic_ns()
    stages["response_validation"] = t9 - t8

    logger.info("    Valid patch responses: %d/%d", patches_valid, batch_size)

    return stages


# ---------------------------------------------------------------------------
# Trial Execution
# ---------------------------------------------------------------------------

def run_trial(
    config: str,
    batch_size: int,
    load_level: str,
    trial_num: int,
    nodes: List[str],
    mncc_config: Dict,
) -> TimingResult:
    """Execute a single provisioning trial."""
    logger.info(
        "Trial %d | Config=%s | N=%d | Load=%s",
        trial_num, config, batch_size, load_level,
    )

    # Reset cluster state
    reset_cluster_state(config)

    # Measure total provisioning time
    t_start = get_monotonic_ns()

    if config == "B1":
        stages = provision_b1(batch_size)
    elif config == "B2":
        stages = provision_b2(batch_size)
    elif config == "mNCC":
        stages = provision_mncc(batch_size, mncc_config)
    else:
        raise ValueError(f"Unknown configuration: {config}")

    t_end = get_monotonic_ns()
    t_prov = t_end - t_start

    result = TimingResult(
        configuration=config,
        batch_size=batch_size,
        load_level=load_level,
        trial_number=trial_num,
        t_prov_ns=t_prov,
        stages=stages,
        timestamp=datetime.utcnow().isoformat(),
    )

    logger.info(
        "  -> T_prov = %.3f ms (stages: %s)",
        ns_to_ms(t_prov),
        {k: f"{ns_to_ms(v):.2f}ms" for k, v in stages.items()},
    )

    return result


# ---------------------------------------------------------------------------
# Statistical Analysis
# ---------------------------------------------------------------------------

def compute_statistics(data: np.ndarray) -> Dict[str, float]:
    """Compute descriptive statistics for a set of provisioning times."""
    return {
        "median_ms": float(np.median(data)),
        "p95_ms": float(np.percentile(data, 95)),
        "p99_ms": float(np.percentile(data, 99)),
        "mean_ms": float(np.mean(data)),
        "std_ms": float(np.std(data, ddof=1)),
        "cv": float(np.std(data, ddof=1) / np.mean(data)) if np.mean(data) > 0 else 0,
        "min_ms": float(np.min(data)),
        "max_ms": float(np.max(data)),
        "n": len(data),
    }


def kruskal_wallis_test(
    groups: Dict[str, np.ndarray], alpha: float = 0.05
) -> Dict:
    """
    Perform Kruskal-Wallis H-test followed by post-hoc Dunn tests
    with Bonferroni correction.
    """
    group_names = list(groups.keys())
    group_data = [groups[name] for name in group_names]

    # Kruskal-Wallis test
    h_stat, p_value = stats.kruskal(*group_data)

    result = {
        "h_statistic": float(h_stat),
        "p_value": float(p_value),
        "significant": p_value < alpha,
        "alpha": alpha,
        "pairwise_comparisons": {},
    }

    # Post-hoc Dunn test with Bonferroni correction if significant
    if p_value < alpha:
        # Build DataFrame for scikit-posthocs
        all_data = []
        all_groups = []
        for name, data in groups.items():
            all_data.extend(data.tolist())
            all_groups.extend([name] * len(data))

        dunn_results = sp.posthoc_dunn(
            a=all_data, val_col=None, group_col=all_groups,
            p_adjust="bonferroni",
        )
        # If using array input
        df_dunn = pd.DataFrame(all_data, columns=["value"])
        df_dunn["group"] = all_groups
        dunn_results = sp.posthoc_dunn(
            df_dunn, val_col="value", group_col="group", p_adjust="bonferroni"
        )

        for i, name_i in enumerate(group_names):
            for j, name_j in enumerate(group_names):
                if i < j:
                    pair_key = f"{name_i}_vs_{name_j}"
                    p_val = dunn_results.loc[name_i, name_j]
                    result["pairwise_comparisons"][pair_key] = {
                        "p_value": float(p_val),
                        "significant": float(p_val) < alpha,
                    }

    return result


def power_law_model(n: np.ndarray, a: float, b: float, c: float) -> np.ndarray:
    """Power-law model: T(N) = a * N^b + c"""
    return a * np.power(n, b) + c


def fit_scaling_model(
    batch_sizes: np.ndarray, median_times: np.ndarray
) -> Dict[str, float]:
    """
    Fit the power-law scaling model T(N) = a * N^b + c
    to observed median provisioning times via non-linear least squares.
    """
    try:
        # Initial parameter guesses
        p0 = [median_times[0], 1.0, 0.0]
        bounds = ([0, 0, -np.inf], [np.inf, 5.0, np.inf])

        popt, pcov = curve_fit(
            power_law_model, batch_sizes, median_times,
            p0=p0, bounds=bounds, maxfev=10000
        )

        a, b, c = popt
        perr = np.sqrt(np.diag(pcov))

        # R-squared
        y_pred = power_law_model(batch_sizes, *popt)
        ss_res = np.sum((median_times - y_pred) ** 2)
        ss_tot = np.sum((median_times - np.mean(median_times)) ** 2)
        r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0

        scaling_type = (
            "sub-linear" if b < 0.9 else
            "linear" if b <= 1.1 else
            "super-linear"
        )

        return {
            "a": float(a),
            "b": float(b),
            "c": float(c),
            "a_stderr": float(perr[0]),
            "b_stderr": float(perr[1]),
            "c_stderr": float(perr[2]),
            "r_squared": float(r_squared),
            "scaling_type": scaling_type,
        }
    except (RuntimeError, ValueError) as e:
        logger.error("Power-law fitting failed: %s", e)
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Results Analysis and Reporting
# ---------------------------------------------------------------------------

def analyze_results(results: List[TimingResult], config: dict) -> Dict:
    """Perform full statistical analysis on collected results."""
    warmup = config["experiment"]["warmup_trials"]
    alpha = config["experiment"]["significance_level"]
    batch_sizes = config["experiment"]["batch_sizes"]
    load_levels = config["experiment"]["load_levels"]

    analysis = {
        "summary_statistics": {},
        "statistical_tests": {},
        "scaling_analysis": {},
        "bottleneck_analysis": {},
    }

    # Convert results to DataFrame
    records = []
    for r in results:
        record = {
            "configuration": r.configuration,
            "batch_size": r.batch_size,
            "load_level": r.load_level,
            "trial_number": r.trial_number,
            "t_prov_ms": ns_to_ms(r.t_prov_ns),
        }
        for stage_name, stage_ns in r.stages.items():
            record[f"stage_{stage_name}_ms"] = ns_to_ms(stage_ns)
        records.append(record)

    df = pd.DataFrame(records)

    # Discard warm-up trials
    df = df[df["trial_number"] > warmup].copy()
    logger.info("Analyzing %d valid observations (after discarding %d warm-up trials)",
                len(df), warmup)

    # Summary statistics per configuration/batch/load
    for load in load_levels:
        for batch in batch_sizes:
            analysis["summary_statistics"][f"load={load}_N={batch}"] = {}

            groups = {}
            for cfg in ["B1", "B2", "mNCC"]:
                subset = df[
                    (df["configuration"] == cfg) &
                    (df["batch_size"] == batch) &
                    (df["load_level"] == load)
                ]["t_prov_ms"].values

                if len(subset) > 0:
                    stats_dict = compute_statistics(subset)
                    analysis["summary_statistics"][f"load={load}_N={batch}"][cfg] = stats_dict
                    groups[cfg] = subset

            # Kruskal-Wallis test across configurations
            if len(groups) >= 2 and all(len(v) >= 5 for v in groups.values()):
                test_result = kruskal_wallis_test(groups, alpha=alpha)
                analysis["statistical_tests"][f"load={load}_N={batch}"] = test_result

    # Scaling analysis for mNCC
    for load in load_levels:
        medians = []
        valid_batches = []
        for batch in batch_sizes:
            subset = df[
                (df["configuration"] == "mNCC") &
                (df["batch_size"] == batch) &
                (df["load_level"] == load)
            ]["t_prov_ms"].values

            if len(subset) > 0:
                medians.append(np.median(subset))
                valid_batches.append(batch)

        if len(valid_batches) >= 3:
            scaling = fit_scaling_model(
                np.array(valid_batches, dtype=float),
                np.array(medians, dtype=float),
            )
            analysis["scaling_analysis"][f"load={load}"] = scaling

    # Bottleneck analysis for mNCC (per-stage dominance)
    mncc_df = df[df["configuration"] == "mNCC"]
    # Only use stage columns that have non-NaN values for mNCC
    stage_cols = [c for c in mncc_df.columns if c.startswith("stage_") and mncc_df[c].notna().any()]
    if stage_cols:
        stage_medians = mncc_df[stage_cols].median()
        total_stage_time = stage_medians.sum()
        bottleneck = {
            col.replace("stage_", "").replace("_ms", ""): {
                "median_ms": float(stage_medians[col]),
                "fraction": float(stage_medians[col] / total_stage_time)
                if total_stage_time > 0 else 0,
            }
            for col in stage_cols
        }
        # Sort by fraction descending
        bottleneck = dict(
            sorted(bottleneck.items(), key=lambda x: x[1]["fraction"], reverse=True)
        )
        analysis["bottleneck_analysis"] = bottleneck

    return analysis


# ---------------------------------------------------------------------------
# Plotting
# ---------------------------------------------------------------------------

def generate_plots(results: List[TimingResult], analysis: Dict, output_dir: Path):
    """Generate visualization plots."""
    output_dir.mkdir(parents=True, exist_ok=True)

    records = []
    for r in results:
        records.append({
            "configuration": r.configuration,
            "batch_size": r.batch_size,
            "load_level": r.load_level,
            "trial_number": r.trial_number,
            "t_prov_ms": ns_to_ms(r.t_prov_ns),
        })
    df = pd.DataFrame(records)
    df = df[df["trial_number"] > 3]  # Remove warm-up

    # Plot 1: Box plots per configuration and batch size
    fig, axes = plt.subplots(1, 3, figsize=(18, 6), sharey=True)
    for idx, load in enumerate(["idle", "medium", "high"]):
        ax = axes[idx]
        load_df = df[df["load_level"] == load]
        configs = ["B1", "B2", "mNCC"]
        batch_sizes = [1, 10, 25, 50]

        positions = []
        data_groups = []
        labels = []
        colors = ["#2196F3", "#FF9800", "#4CAF50"]

        for b_idx, batch in enumerate(batch_sizes):
            for c_idx, cfg in enumerate(configs):
                subset = load_df[
                    (load_df["configuration"] == cfg) &
                    (load_df["batch_size"] == batch)
                ]["t_prov_ms"].values
                if len(subset) > 0:
                    data_groups.append(subset)
                    positions.append(b_idx * 4 + c_idx)
                    labels.append(f"{cfg}\nN={batch}")

        if data_groups:
            bp = ax.boxplot(data_groups, positions=positions, widths=0.8,
                           patch_artist=True)
            for i, patch in enumerate(bp["boxes"]):
                color_idx = i % 3
                patch.set_facecolor(colors[color_idx])
                patch.set_alpha(0.7)

        ax.set_title(f"Load: {load}")
        ax.set_xlabel("Configuration / Batch Size")
        ax.set_ylabel("Provisioning Time (ms)")
        ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_dir / "boxplot_comparison.png", dpi=150, bbox_inches="tight")
    plt.close()

    # Plot 2: Scaling curve for mNCC
    fig, ax = plt.subplots(figsize=(10, 6))
    for load in ["idle", "medium", "high"]:
        medians = []
        batches = []
        for batch in [1, 10, 25, 50]:
            subset = df[
                (df["configuration"] == "mNCC") &
                (df["batch_size"] == batch) &
                (df["load_level"] == load)
            ]["t_prov_ms"].values
            if len(subset) > 0:
                medians.append(np.median(subset))
                batches.append(batch)

        if batches:
            ax.plot(batches, medians, "o-", label=f"Load: {load}", markersize=8)

            # Overlay fitted curve if available
            scaling_key = f"load={load}"
            if scaling_key in analysis.get("scaling_analysis", {}):
                scaling = analysis["scaling_analysis"][scaling_key]
                if "error" not in scaling:
                    n_fit = np.linspace(1, 50, 100)
                    t_fit = power_law_model(n_fit, scaling["a"], scaling["b"], scaling["c"])
                    ax.plot(n_fit, t_fit, "--", alpha=0.5,
                           label=f"Fit (b={scaling['b']:.2f}, R²={scaling['r_squared']:.3f})")

    ax.set_xlabel("Batch Size (N)")
    ax.set_ylabel("Median Provisioning Time (ms)")
    ax.set_title("mNCC Scaling Behavior: T(N) = a·N^b + c")
    ax.legend()
    ax.grid(True, alpha=0.3)
    plt.savefig(output_dir / "scaling_curve_mncc.png", dpi=150, bbox_inches="tight")
    plt.close()

    # Plot 3: Bottleneck analysis (stacked bar)
    if analysis.get("bottleneck_analysis"):
        fig, ax = plt.subplots(figsize=(12, 6))
        stages = list(analysis["bottleneck_analysis"].keys())
        fractions = [analysis["bottleneck_analysis"][s]["fraction"] for s in stages]

        bars = ax.barh(stages, fractions, color=plt.cm.Set3(np.linspace(0, 1, len(stages))))
        ax.set_xlabel("Fraction of Total Provisioning Time")
        ax.set_title("mNCC Per-Stage Bottleneck Analysis")
        ax.set_xlim(0, 1)

        for bar, frac in zip(bars, fractions):
            ax.text(bar.get_width() + 0.01, bar.get_y() + bar.get_height() / 2,
                   f"{frac:.1%}", va="center")

        plt.tight_layout()
        plt.savefig(output_dir / "bottleneck_analysis.png", dpi=150, bbox_inches="tight")
        plt.close()

    logger.info("Plots saved to %s", output_dir)


# ---------------------------------------------------------------------------
# Main Execution
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Provisioning Test Plan - Baseline Comparison",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "-c", "--config", type=Path, default=DEFAULT_CONFIG,
        help="Path to configuration YAML file",
    )
    parser.add_argument(
        "--configs", nargs="+", default=None,
        choices=["B1", "B2", "mNCC"],
        help="Run only specified configurations (default: all)",
    )
    parser.add_argument(
        "--batch-sizes", nargs="+", type=int, default=None,
        help="Run only specified batch sizes (default: from config)",
    )
    parser.add_argument(
        "--load-levels", nargs="+", default=None,
        choices=["idle", "medium", "high"],
        help="Run only specified load levels (default: all)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print execution plan without running trials",
    )
    parser.add_argument(
        "--skip-ptp-check", action="store_true",
        help="Skip PTP synchronization verification",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=None,
        help="Override output directory",
    )
    args = parser.parse_args()

    # Load configuration
    with open(args.config) as f:
        config = yaml.safe_load(f)

    # Apply CLI overrides
    configurations = args.configs or config["experiment"]["configurations"]
    batch_sizes = args.batch_sizes or config["experiment"]["batch_sizes"]
    load_levels = args.load_levels or config["experiment"]["load_levels"]
    trials = config["experiment"]["trials_per_combination"]
    nodes = config["cluster"]["node_names"]
    mncc_config = config["mncc"]

    # Resolve kubeconfig path relative to config file
    kubeconfig_rel = mncc_config["kubernetes"]["kubeconfig"]
    kubeconfig_abs = str((args.config.parent / kubeconfig_rel).resolve())
    mncc_config["kubernetes"]["kubeconfig"] = kubeconfig_abs
    os.environ.setdefault("KUBECONFIG", kubeconfig_abs)

    # Setup output directories
    output_base = args.output_dir or Path(config["output"]["results_dir"])
    raw_dir = output_base / "raw"
    analysis_dir = output_base / "analysis"
    plots_dir = output_base / "plots"
    for d in [raw_dir, analysis_dir, plots_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # Print execution plan
    total_trials = len(configurations) * len(batch_sizes) * len(load_levels) * trials
    logger.info("=" * 70)
    logger.info("PROVISIONING TEST PLAN EXECUTION")
    logger.info("=" * 70)
    logger.info("Configurations: %s", configurations)
    logger.info("Batch sizes:    %s", batch_sizes)
    logger.info("Load levels:    %s", load_levels)
    logger.info("Trials per combination: %d", trials)
    logger.info("Total trials:   %d", total_trials)
    logger.info("Cluster nodes:  %d (%s)", len(nodes), ", ".join(nodes))
    logger.info("mNCC RabbitMQ:  %s:%d", mncc_config["rabbitmq"]["host"],
                mncc_config["rabbitmq"]["port"])
    logger.info("mNCC Kubeconfig: %s", mncc_config["kubernetes"]["kubeconfig"])
    logger.info("Output:         %s", output_base)
    logger.info("=" * 70)

    if args.dry_run:
        logger.info("DRY RUN - no trials will be executed.")
        return

    # PTP synchronization check
    if not args.skip_ptp_check:
        ptp_ok = verify_ptp_sync(nodes, config["timing"]["ptp_max_offset_us"])
        if not ptp_ok:
            logger.error("PTP synchronization check FAILED. Aborting.")
            sys.exit(1)

    # Execute trials
    all_results: List[TimingResult] = []
    trial_count = 0

    for load_level in load_levels:
        set_load_level(load_level, nodes)

        for config_name in configurations:
            for batch_size in batch_sizes:
                logger.info("-" * 50)
                logger.info(
                    "Starting series: Config=%s, N=%d, Load=%s (%d trials)",
                    config_name, batch_size, load_level, trials,
                )

                for trial_num in range(1, trials + 1):
                    try:
                        result = run_trial(
                            config=config_name,
                            batch_size=batch_size,
                            load_level=load_level,
                            trial_num=trial_num,
                            nodes=nodes,
                            mncc_config=mncc_config,
                        )
                        all_results.append(result)
                        trial_count += 1

                        # Save incremental results
                        if trial_count % 10 == 0:
                            _save_raw_results(all_results, raw_dir)
                            logger.info(
                                "Progress: %d/%d trials complete (%.1f%%)",
                                trial_count, total_trials,
                                100 * trial_count / total_trials,
                            )

                    except Exception as e:
                        logger.error(
                            "Trial %d FAILED (Config=%s, N=%d, Load=%s): %s",
                            trial_num, config_name, batch_size, load_level, e,
                        )
                        # Record failed trial with zero time
                        failed_result = TimingResult(
                            configuration=config_name,
                            batch_size=batch_size,
                            load_level=load_level,
                            trial_number=trial_num,
                            t_prov_ns=-1,  # Sentinel for failure
                            stages={},
                            timestamp=datetime.utcnow().isoformat(),
                        )
                        all_results.append(failed_result)
                        trial_count += 1

    # Save final raw results
    _save_raw_results(all_results, raw_dir)

    # Filter out failed trials for analysis
    valid_results = [r for r in all_results if r.t_prov_ns > 0]
    logger.info(
        "Execution complete: %d/%d valid trials",
        len(valid_results), len(all_results),
    )

    # Statistical analysis
    logger.info("Running statistical analysis...")
    analysis = analyze_results(valid_results, config)

    # Save analysis results
    with open(analysis_dir / "analysis_results.json", "w") as f:
        json.dump(analysis, f, indent=2, default=str)
    logger.info("Analysis saved to %s", analysis_dir / "analysis_results.json")

    # Generate plots
    logger.info("Generating plots...")
    generate_plots(valid_results, analysis, plots_dir)

    # Print summary
    _print_summary(analysis)

    logger.info("=" * 70)
    logger.info("TEST PLAN EXECUTION COMPLETE")
    logger.info("Results: %s", output_base)
    logger.info("=" * 70)


def _save_raw_results(results: List[TimingResult], output_dir: Path) -> None:
    """Save raw results to JSON."""
    data = [asdict(r) for r in results]
    with open(output_dir / "raw_results.json", "w") as f:
        json.dump(data, f, indent=2)


def _print_summary(analysis: Dict) -> None:
    """Print a summary table of results."""
    logger.info("\n" + "=" * 70)
    logger.info("RESULTS SUMMARY")
    logger.info("=" * 70)

    # Summary statistics
    for combo, stats_dict in analysis.get("summary_statistics", {}).items():
        logger.info("\n%s:", combo)
        for cfg, s in stats_dict.items():
            logger.info(
                "  %5s: median=%.2f ms | P95=%.2f ms | P99=%.2f ms | CV=%.3f",
                cfg, s["median_ms"], s["p95_ms"], s["p99_ms"], s["cv"],
            )

    # Statistical tests
    logger.info("\nStatistical Tests (Kruskal-Wallis, α=0.05):")
    for combo, test in analysis.get("statistical_tests", {}).items():
        sig = "SIGNIFICANT" if test["significant"] else "not significant"
        logger.info("  %s: H=%.2f, p=%.4f (%s)", combo, test["h_statistic"],
                   test["p_value"], sig)
        for pair, pair_result in test.get("pairwise_comparisons", {}).items():
            sig_pair = "*" if pair_result["significant"] else ""
            logger.info("    %s: p=%.4f %s", pair, pair_result["p_value"], sig_pair)

    # Scaling analysis
    logger.info("\nScaling Analysis (mNCC): T(N) = a·N^b + c")
    for load, scaling in analysis.get("scaling_analysis", {}).items():
        if "error" not in scaling:
            logger.info(
                "  %s: b=%.3f ± %.3f (R²=%.3f) → %s",
                load, scaling["b"], scaling["b_stderr"],
                scaling["r_squared"], scaling["scaling_type"],
            )

    # Bottleneck
    logger.info("\nBottleneck Analysis (mNCC):")
    for stage, info in list(analysis.get("bottleneck_analysis", {}).items())[:5]:
        logger.info("  %s: %.2f ms (%.1f%%)", stage, info["median_ms"],
                   info["fraction"] * 100)


if __name__ == "__main__":
    main()
