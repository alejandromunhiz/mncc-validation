# mNCC Experimental Evaluation Suite

> **Empirical performance evaluation of the multi-domain Network Connectivity Controller (mNCC)**
> for intent-based overlay provisioning in Kubernetes environments.

This repository contains the complete experimental framework used to evaluate the mNCC system,
including provisioning benchmarks, self-healing fault injection tests, and security overhead
characterisation. All scripts, configuration, raw datasets, and analysis outputs are provided
to enable full reproducibility of the results presented in the accompanying paper.

---

## Table of Contents

- [Overview](#overview)
- [Experiments](#experiments)
  - [E1–E2: Provisioning Performance](#e1e2-provisioning-performance)
  - [E3: Self-Healing Evaluation](#e3-self-healing-evaluation)
  - [E4: Security Control Plane Overhead](#e4-security-control-plane-overhead)
  - [E5: Data Plane MACsec Overhead](#e5-data-plane-macsec-overhead)
- [Testbed](#testbed)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Output & Results](#output--results)
- [Statistical Methodology](#statistical-methodology)
- [Reproducibility](#reproducibility)
- [Citation](#citation)
- [License](#license)

---

## Overview

The mNCC (multi-domain Network Connectivity Controller) provides intent-based,
autonomous overlay network provisioning for Kubernetes clusters. This evaluation
suite quantifies its performance across five dimensions:

| Experiment | Goal | Metric |
|:---|:---|:---|
| **E1–E2** | Provisioning latency & scaling | $T_\text{prov}$, per-stage decomposition |
| **E3** | Autonomous self-healing | $\Delta T_\text{detect}$, $\Delta T_\text{recover}$, $\rho_\text{loss}$ |
| **E4** | Control plane security overhead | $\tau_\text{sec}$, $\rho_\text{sec}$ |
| **E5** | Data plane encryption impact | Throughput (Gbps), latency (µs), $\delta_\text{bw}$ |

All experiments follow a controlled repeated-measures design with statistical
rigour (Kruskal–Wallis tests, Bonferroni-corrected post-hoc comparisons,
non-linear scaling fits).

---

## Experiments

### E1–E2: Provisioning Performance

**Location:** `test-plan/`

Compares provisioning latency across three network configurations:

| Configuration | Description |
|:---|:---|
| $\mathcal{C}_\text{B1}$ | CNI + Manual scripting (Flannel + `kubectl apply`) |
| $\mathcal{C}_\text{B2}$ | Service Mesh (Istio sidecar injection) |
| $\mathcal{C}_\text{mNCC}$ | Proposed system (IBS + L2S-M + ONOS) |

**Parameters:**
- Batch sizes: $N \in \{1, 10, 25, 50\}$ simultaneous provisioning requests
- Background load levels: idle, medium (50% microservices), high (CI/CD burst)
- Trials: 30 per combination (first 3 discarded as warm-up)
- Timestamps: nanosecond precision via `clock_gettime(CLOCK_MONOTONIC)`

**Outputs:**
- Per-stage timing decomposition (intent publish, IBS processing, gRPC, network creation)
- Power-law scaling fit: $\hat{T}(N) = a \cdot N^b + c$
- Statistical comparison: Kruskal–Wallis + Dunn post-hoc tests

**Run:**
```bash
cd test-plan && ./run.sh
```

---

### E3: Self-Healing Evaluation

**Location:** `test-plan-advanced/run_selfhealing.py`

Evaluates autonomous fault detection and remediation by injecting three
fault classes:

| Fault | Method | Failure mode |
|:---|:---|:---|
| **F1** | `ip link set <iface> down` | Physical link failure |
| **F2** | `kubectl drain` + `cordon` | Worker node loss |
| **F3** | ExaBGP prefix withdrawal | BGP route failure |

**Protocol:**
1. Establish UDP probe stream (100-ms interval) between two pods
2. Record 5-minute baseline (latency, throughput)
3. Inject fault at randomised offset within 2-min window
4. Monitor detection ($T_\text{detect}$) and recovery ($T_\text{recover}$)
5. Recovery criterion: 10 consecutive probes with lat ≤ 1.1× baseline AND bw ≥ 0.9× baseline

**Configurations:**
- $\mathcal{C}_\text{mNCC}$: Autonomous self-healing (proposed)
- $\mathcal{C}_\text{B0}$: Manual remediation baseline (simulated operator delay ~45 s)

**Trials:** 20 per fault class × 2 configurations = 120 total

**Run:**
```bash
cd test-plan-advanced && ./run_selfhealing.sh
```

---

### E4: Security Control Plane Overhead

**Location:** `test-plan-advanced/run_security_controlplane.py`

Measures the incremental latency of each security layer in the
Connectivity Controller's provisioning pipeline:

| Config | Active layers | Description |
|:---|:---|:---|
| $\mathcal{S}_0$ | None | Baseline (no security) |
| $\mathcal{S}_1$ | JWT | Token verification (local) |
| $\mathcal{S}_2$ | JWT + Vault | + Identity resolution (network round-trip) |
| $\mathcal{S}_3$ | JWT + Vault + RBAC | + Kubernetes RBAC evaluation |
| $\mathcal{S}_4$ | Full stack | + CNI audit logging (production config) |

**Protocol:**
- 100 sequential requests per configuration ($N=1$, idle load)
- First 5 discarded as warm-up → 95 valid observations
- Per-layer timestamps: $\tau_\text{jwt}$, $\tau_\text{vault}$, $\tau_\text{rbac}$, $\tau_\text{audit}$
- Overhead ratio: $\rho_\text{sec}^{(i)} = \tau_\text{sec}^{(i)} / T_\text{prov}(\mathcal{S}_0)$

**Run:**
```bash
cd test-plan-advanced && ./run_security_controlplane.sh
```

---

### E5: Data Plane MACsec Overhead

**Location:** `test-plan-advanced/run_security_dataplane.py`

Characterises the throughput and latency penalty of IEEE 802.1AE
(MACsec) link-layer encryption on overlay traffic:

| Config | Cipher suite | Key length |
|:---|:---|:---|
| $\mathcal{D}_0$ | None | — (baseline) |
| $\mathcal{D}_1$ | GCM-AES-128 | 128-bit |
| $\mathcal{D}_2$ | GCM-AES-256 | 256-bit |

**Parameters:**
- Packet sizes: 64 B, 512 B, 1500 B, 9000 B (jumbo frames)
- Scenarios: intra-cluster, cross-cluster (VXLAN tunnel)
- Measurement: `iperf3` (8 streams, 60-s window) + ICMP ping (RTT/2)
- Trials: 10 per combination (first discarded as warm-up)
- Total combinations: 3 configs × 4 sizes × 2 scenarios × 10 = 240 measurements

**Reported metrics:**
- Sustained throughput $\overline{\text{bw}}$ (Gbps)
- One-way latency $\overline{\text{lat}}$ (µs)
- Degradation ratio $\delta_\text{bw} = 1 - \overline{\text{bw}}_d / \overline{\text{bw}}_0$
- CPU utilisation $u_\text{cpu}$ (sender node)

**Run:**
```bash
cd test-plan-advanced && ./run_security_dataplane.sh
# ⚠️  Estimated runtime: ~5 hours
```

---

## Testbed

| Property | Value |
|:---|:---|
| **Facility** | OneLab (KVM virtualisation) |
| **Nodes** | 6 (1 control-plane + 5 workers) |
| **CPU** | Intel Xeon Cascadelake, 2.89 GHz, 16 MB L3 |
| **Workers** | 10–12 vCPUs, 29.2 GiB RAM each |
| **NICs** | 2× virtio_net (10 Gbps virtual line rate) |
| **OS** | Ubuntu 24.04.2 LTS, kernel 6.8.0 |
| **Kubernetes** | v1.29.13, containerd 1.7.28 |
| **CNI** | Flannel v0.26.4 (VXLAN), Multus |
| **Underlay** | 192.168.111.0/24 (flat L2), 10 Gbps |
| **Overlay** | 10.244.0.0/16, MTU 1450 |
| **Time sync** | kvm-clock (hypervisor-synced), offset < 10 µs |

Full testbed documentation in LaTeX format: [`test-plan-advanced/testbed_documentation.tex`](test-plan-advanced/testbed_documentation.tex)

---

## Repository Structure

```
.
├── README.md                          # This file
├── upm-nemo-kubeconfig.yaml           # Cluster access credentials (⚠️  not committed)
│
├── test-plan/                         # E1–E2: Provisioning Performance
│   ├── run.sh                         # Launcher (port-forward + venv + execution)
│   ├── run_test_plan.py               # Main experiment script (~1600 lines)
│   ├── config.yaml                    # Experiment configuration
│   ├── requirements.txt               # Python dependencies
│   ├── manifests/
│   │   └── cicd-burst-job.yaml        # CI/CD burst simulation manifest
│   ├── results/
│   │   ├── raw/
│   │   │   └── raw_results.json       # 580 raw trial observations
│   │   ├── analysis/
│   │   │   └── analysis_results.json  # Statistical analysis output
│   │   └── plots/
│   │       ├── boxplot_comparison.png  # Config comparison box plots
│   │       ├── scaling_curve_mncc.png  # Power-law scaling fit
│   │       └── bottleneck_analysis.png # Per-stage bottleneck decomposition
│   └── test_plan_execution.log        # Execution log
│
├── test-plan-advanced/                # E3–E5: Self-Healing & Security
│   ├── config.yaml                    # Shared configuration for E3/E4/E5
│   ├── requirements.txt               # Python dependencies
│   │
│   ├── run_selfhealing.sh             # E3 launcher
│   ├── run_selfhealing.py             # E3 self-healing evaluation
│   │
│   ├── run_security_controlplane.sh   # E4 launcher
│   ├── run_security_controlplane.py   # E4 control plane overhead
│   │
│   ├── run_security_dataplane.sh      # E5 launcher
│   ├── run_security_dataplane.py      # E5 MACsec data plane overhead
│   │
│   ├── testbed_documentation.tex      # Full testbed description (LaTeX)
│   │
│   └── results/                       # Generated after execution
│       ├── raw/                        #   Raw JSON measurements
│       ├── analysis/                   #   Statistical analysis
│       └── plots/                      #   Visualisations (PNG)
│
└── docs/                              # Reference documentation
    ├── NEMO_D2.3-*.pdf                # mNCC architecture manual
    └── NEMO_D4.3-*.pdf                # Integration & testing manual
```

---

## Prerequisites

### System Requirements

- Python ≥ 3.10
- `kubectl` configured with cluster access
- Network access to Kubernetes API server
- Port-forward capability to in-cluster RabbitMQ (5672)

### Python Dependencies

```bash
pip install pyyaml numpy pandas scipy matplotlib pika
```

Or use the provided requirements files:
```bash
pip install -r test-plan/requirements.txt
pip install -r test-plan-advanced/requirements.txt
```

### Cluster Requirements

| Component | Required for |
|:---|:---|
| RabbitMQ (`nemo-sec` namespace) | E1–E4 (mNCC intent publishing) |
| mNCC IBS pod (`nemo-net`) | E1–E4 (intent processing) |
| L2S-M gRPC server (`nemo-net`) | E1–E5 (overlay provisioning) |
| Network Probe DaemonSet | E3 (fault detection) |
| NeMeX | E3 (fault classification) |
| iperf3 image availability | E5 (throughput measurement) |

---

## Quick Start

### Run all provisioning benchmarks (E1–E2):
```bash
cd test-plan
./run.sh                    # Full run (30 trials × 12 combinations ≈ 20 min)
./run.sh --dry-run          # Preview without execution
```

### Run advanced experiments (E3–E5):
```bash
cd test-plan-advanced

# Self-healing (~2 hours)
./run_selfhealing.sh

# Security control plane (~15 min)
./run_security_controlplane.sh

# Data plane MACsec (~5 hours)
./run_security_dataplane.sh
```

### Dry-run mode (all scripts):
```bash
python3 run_test_plan.py --dry-run
python3 run_selfhealing.py --dry-run
python3 run_security_controlplane.py --dry-run
python3 run_security_dataplane.py --dry-run
```

---

## Configuration

All experiments are configured via YAML files:

### `test-plan/config.yaml` (E1–E2)
```yaml
experiment:
  trials: 30              # Observations per combination
  warmup: 3              # Discarded warm-up trials
  batch_sizes: [1, 10, 25, 50]
  load_levels: [idle, medium, high]
  configurations: [B1, B2, mNCC]

mncc:
  rabbitmq:
    host: 127.0.0.1      # Via port-forward
    port: 5672
    intent_exchange: nemo.api.workload
    intent_routing_key: intent-notify
```

### `test-plan-advanced/config.yaml` (E3–E5)
```yaml
selfhealing:
  trials_per_fault: 20
  probe_interval_ms: 100
  recovery_window_samples: 10

security_controlplane:
  requests_per_config: 100
  warmup_requests: 5
  configurations: [S0, S1, S2, S3, S4]

security_dataplane:
  trials_per_combination: 10
  packet_sizes: [64, 512, 1500, 9000]
  scenarios: [intra-cluster, cross-cluster]
```

---

## Output & Results

Each experiment produces three output categories:

| Directory | Content | Format |
|:---|:---|:---|
| `results/raw/` | Individual trial measurements | JSON |
| `results/analysis/` | Aggregated statistics | JSON |
| `results/plots/` | Visualisations | PNG (150 DPI) |

### E1–E2 Results Structure
```json
// raw_results.json (per record)
{
  "configuration": "mNCC",
  "batch_size": 1,
  "load_level": "idle",
  "trial_number": 4,
  "t_prov_ns": 631284000,
  "stages": {"intent_publish": 430000000, "ibs_processing": 190000000, ...},
  "timestamp": "2026-05-31T12:34:56.789Z",
  "node_offsets_us": {"worker1": 2.3, "worker2": 1.8, ...}
}
```

### Generated Plots

| Experiment | Plot | Description |
|:---|:---|:---|
| E1–E2 | `boxplot_comparison.png` | Provisioning time distribution per config |
| E1–E2 | `scaling_curve_mncc.png` | Power-law fit $\hat{T}(N) = aN^b + c$ |
| E1–E2 | `bottleneck_analysis.png` | Per-stage time decomposition |
| E3 | `selfhealing_comparison.png` | Detection/recovery times (mNCC vs B0) |
| E4 | `security_overhead_stacked.png` | Per-layer latency decomposition |
| E4 | `security_overhead_ratio.png` | $\rho_\text{sec}$ bar chart |
| E4 | `security_boxplot.png` | Provisioning time by security level |
| E5 | `throughput_heatmap_*.png` | Throughput by config × packet size |
| E5 | `latency_vs_pktsize_*.png` | Latency curves per MACsec config |
| E5 | `throughput_degradation.png` | $\delta_\text{bw}$ per config |
| E5 | `cpu_utilization.png` | CPU overhead of encryption |

---

## Statistical Methodology

All experiments employ non-parametric statistical methods suitable for
right-skewed latency distributions:

- **Central tendency:** Median (robust to outliers)
- **Dispersion:** P95, P99, coefficient of variation ($\text{CV} = \sigma/\mu$)
- **Hypothesis testing:** Kruskal–Wallis test ($\alpha = 0.05$)
- **Post-hoc:** Dunn's test with Bonferroni correction
- **Scaling model:** Non-linear least squares fit (E1–E2)
- **Sample size:** Determined via a priori power analysis ($1-\beta = 0.90$, $\delta = 20\%$)

---

## Reproducibility

### Reproducing from scratch:

1. **Provision cluster:** Deploy Kubernetes v1.29 on 6 nodes with matching hardware
2. **Install mNCC:** Deploy IBS, L2S-M, NeMeX, network probes per NEMO documentation
3. **Configure access:** Place kubeconfig at project root
4. **Install dependencies:** `pip install -r requirements.txt`
5. **Run experiments:** Execute launcher scripts in order (E1→E5)

### Reproducing analysis only (from raw data):

```python
import json
import pandas as pd
from scipy import stats

# Load raw results
with open("test-plan/results/raw/raw_results.json") as f:
    data = json.load(f)

df = pd.DataFrame(data)
df["t_prov_ms"] = df["t_prov_ns"] / 1e6

# Reproduce statistical tests
for batch in [1, 10, 25, 50]:
    groups = [df[(df["batch_size"]==batch) & (df["configuration"]==c)]["t_prov_ms"]
              for c in ["B1", "B2", "mNCC"]]
    H, p = stats.kruskal(*groups)
    print(f"N={batch}: H={H:.2f}, p={p:.4f}")
```

### Environment variables:

| Variable | Description | Default |
|:---|:---|:---|
| `KUBECONFIG` | Path to cluster kubeconfig | `../upm-nemo-kubeconfig.yaml` |

---

## Citation

If you use this evaluation framework or dataset in your research, please cite:

```bibtex
@article{mncc2026,
  title   = {Intent-Based Multi-Domain Network Connectivity Controller
             for Kubernetes: Design and Empirical Evaluation},
  author  = {...},
  journal = {...},
  year    = {2026}
}
```

---

## License

This evaluation framework is released under the [MIT License](LICENSE).
The mNCC system components are subject to their respective licenses as
specified in the NEMO project documentation.
