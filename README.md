# Multi-Layer Intrusion Detection System for IoT Networks

A simulation-based **Multi-Layer Intrusion Detection System (MLIDS)** for IoT networks using a hierarchical **Mist–Edge–Fog–Cloud architecture** implemented in **OMNeT++**.

The system distributes intrusion detection across multiple computing layers instead of sending all network traffic directly to a centralized cloud server. Lightweight anomaly detection is performed at Mist nodes, more detailed classification is performed at Edge gateways, correlation is performed at Fog nodes, and global analysis and policy updates are handled by the Cloud.

---

## 📌 Project Overview

Modern IoT networks contain a large number of resource-constrained devices that continuously generate network traffic. Sending all traffic to a centralized cloud for security analysis can introduce high latency, network overhead, and unnecessary computation.

This project investigates a hierarchical IDS architecture where detection responsibilities are distributed across four layers:

```text
                    ┌──────────────────────┐
                    │     Cloud Server     │
                    │ Global Analysis      │
                    │ Gradient Boosting    │
                    │ Policy Updates       │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │      Fog Nodes       │
                    │ Alert Correlation    │
                    │ Random Forest        │
                    └──────────┬───────────┘
                               │
                 ┌─────────────┴─────────────┐
                 │                           │
        ┌────────▼────────┐        ┌────────▼────────┐
        │  Edge Gateway   │        │  Edge Gateway   │
        │ Rules + ML      │        │ Rules + ML      │
        │ Decision Tree   │        │ Decision Tree   │
        └────────┬────────┘        └────────┬────────┘
                 │                           │
          ┌──────┴──────┐              ┌─────┴──────┐
          │             │              │            │
       Mist Nodes    Mist Nodes      Mist Nodes   Mist Nodes
       Z-score       Z-score         Z-score      Z-score
```

The simulation contains:

* **20 Mist nodes**
* **4 Edge gateways**
* **2 Fog nodes**
* **1 Cloud server**

---

# 🏗️ Architecture

## 1. Mist Layer

Mist nodes represent resource-constrained IoT devices such as sensors.

Each Mist node:

* Replays traffic from an NSL-KDD dataset slice.
* Maintains rolling statistics.
* Performs lightweight **Z-score anomaly detection**.
* Estimates its CPU load.
* Supports adaptive offloading when CPU utilization exceeds the configured threshold.
* Sends traffic and alerts to its associated Edge gateway.

The Mist layer focuses on detecting simple statistical deviations without performing computationally expensive machine-learning inference.

### Main detection features

The Mist Z-score detector uses traffic statistics such as:

* Payload size
* Inter-arrival time
* Byte rate

Rolling mean and standard deviation are maintained for these measurements.

---

## 2. Edge Layer

Each Edge gateway aggregates traffic from multiple Mist nodes.

The Edge layer performs two-stage detection:

### Stage 1 — Rule-Based Detection

Snort-style rules are applied to identify suspicious traffic patterns.

### Stage 2 — Decision Tree Lookup

The traffic is mapped into discretized feature bins and classified using a lookup table generated during offline model training.

The Edge layer uses features including:

* Source bytes
* Error rates
* Host-related statistics
* Traffic characteristics

When suspicious traffic is detected, an `IDSAlert` is generated and forwarded toward the Fog layer.

---

## 3. Fog Layer

Fog nodes provide regional processing between Edge and Cloud.

The Fog layer:

* Receives alerts from multiple Edge gateways.
* Performs attack classification using a Random Forest-derived lookup table.
* Maintains a sliding correlation window.
* Correlates alerts originating from different Edge gateways.
* Escalates significant or distributed attacks to the Cloud.

This allows the system to identify attacks that may not be obvious from a single IoT device.

---

## 4. Cloud Layer

The Cloud acts as the global IDS authority.

It:

* Receives escalated alerts from Fog nodes.
* Samples selected traffic for deeper analysis.
* Performs global classification using a Gradient Boosting-derived lookup model.
* Maintains global detection policies.
* Periodically generates `PolicyUpdate` messages.
* Propagates updated policies down through the hierarchy.

The Cloud therefore provides computationally expensive global intelligence while avoiding the need to process every packet centrally.

---

# 🔄 Detection Workflow

The implemented simulation follows this general workflow:

```text
NSL-KDD Traffic
       │
       ▼
┌──────────────┐
│ Mist Node    │
│ Z-score IDS  │
└──────┬───────┘
       │
       │ suspicious / normal traffic
       ▼
┌──────────────┐
│ Edge Gateway │
│ Rules + DT   │
└──────┬───────┘
       │
       │ alerts
       ▼
┌──────────────┐
│ Fog Node     │
│ RF +         │
│ Correlation  │
└──────┬───────┘
       │
       │ escalation
       ▼
┌──────────────┐
│ Cloud Server │
│ GB Analysis  │
│ Policy Update│
└──────────────┘
```

---

# 🧠 Machine Learning Models

The project uses different levels of computational complexity at different layers.

| Layer | Detection Method      | Purpose                                 |
| ----- | --------------------- | --------------------------------------- |
| Mist  | Rolling Z-score       | Lightweight anomaly detection           |
| Edge  | Rules + Decision Tree | Fast local classification               |
| Fog   | Random Forest         | Regional classification and correlation |
| Cloud | Gradient Boosting     | Global/deep analysis                    |

The lookup tables used by the C++ simulation are generated offline from the training data rather than executing the complete Python ML models directly inside OMNeT++.

---

# 📊 Dataset

The primary dataset used for traffic replay is **NSL-KDD**.

The dataset contains network connection records with 41 traffic features and attack labels.

The project uses the following major attack categories:

| Category | Description                           | Examples          |
| -------- | ------------------------------------- | ----------------- |
| DoS      | Attempts to make services unavailable | Neptune, Smurf    |
| Probe    | Network reconnaissance/scanning       | Portsweep, Nmap   |
| R2L      | Remote unauthorized access            | Password guessing |
| U2R      | Local privilege escalation            | Buffer overflow   |

The NSL-KDD traffic is divided into **20 CSV files**, with one traffic slice assigned to each Mist node.

```text
KDDTrain+ / KDDTest+
          │
          ▼
   Dataset preprocessing
          │
          ▼
 ┌────────┼────────┐
 ▼        ▼        ▼
Mist 00  Mist 01  Mist 02 ... Mist 19
   │        │        │          │
   └────────┴────────┴──────────┘
                │
                ▼
         OMNeT++ Simulation
```

---

# 📁 Project Structure

```text
.
├── analysis/
│   ├── train_models.py
│   └── visualize_results.py
│
├── build/
│   └── libmultilayer_ids.so
│
├── dataset/
│   ├── KDDTrain+.txt
│   ├── KDDTest+.txt
│   └── mist_node_00.csv
│       ...
│   └── mist_node_19.csv
│
├── results/
│   └── plots/
│
├── scripts/
│   └── run_all.sh
│
├── simulations/
│   ├── network.ned
│   └── omnetpp.ini
│
├── src/
│   ├── cloud/
│   ├── common/
│   ├── edge/
│   ├── fog/
│   ├── lookupTables/
│   └── mist/
│
├── CMakeLists.txt
└── README.md
```

---

# 📂 Important Files

## `simulations/network.ned`

Defines the OMNeT++ network topology.

It connects:

```text
20 Mist Nodes
      ↓
4 Edge Gateways
      ↓
2 Fog Nodes
      ↓
1 Cloud Server
```

---

## `simulations/omnetpp.ini`

Contains simulation configuration parameters such as:

* Number of nodes
* Detection configuration
* Traffic generation
* Link parameters
* Simulation duration
* IDS configuration
* Adaptive offloading
* Latency-aware routing

---

## `src/mist/`

Contains the Mist node implementation.

Important files:

```text
MistNode.h
MistNode.cc
```

The Mist node performs rolling Z-score anomaly detection and adaptive offloading.

---

## `src/edge/`

Contains Edge gateway implementation.

Important files:

```text
EdgeGateway.h
EdgeGateway.cc
```

The Edge layer implements:

* Rule-based detection
* Decision Tree lookup
* Alert generation
* Queue management
* Latency-aware routing
* Policy propagation

---

## `src/fog/`

Contains Fog node implementation.

The Fog layer performs:

* Random Forest lookup classification
* Alert correlation
* Sliding-window analysis
* Escalation to Cloud

---

## `src/cloud/`

Contains Cloud server implementation.

The Cloud performs:

* Global classification
* Policy generation
* Policy propagation
* Model improvement simulation

---

## `src/common/`

Contains common structures and message definitions shared across layers.

---

## `src/lookupTables/`

Contains generated lookup tables used by the C++ simulation.

Examples:

```text
EdgeLookup.h
FogLookup.h
CloudLookup.h
```

These files are generated from the offline model-training process.

---

# 🧪 Model Training

The Python training pipeline is located in:

```text
analysis/train_models.py
```

The general process is:

```text
NSL-KDD Dataset
       │
       ▼
Preprocessing
       │
       ▼
Feature Selection
       │
       ▼
Model Training
       │
       ▼
Feature Discretization
       │
       ▼
Lookup Tables
       │
       ▼
C++ / OMNeT++ Simulation
```

The lookup tables allow the simulation to reproduce the behavior of the trained classifiers without requiring the complete Python ML environment during every OMNeT++ simulation event.

---

# ▶️ Running the Project

## Requirements

The project requires:

* OMNeT++
* C++
* CMake
* Python 3
* Python virtual environment
* Required Python ML/data-analysis packages

---

## 1. Activate the Python environment

```bash
source venv/bin/activate
```

---

## 2. Train/generate the lookup tables

From the project root:

```bash
python analysis/train_models.py
```

This generates the lookup tables used by the simulation.

---

## 3. Build the OMNeT++ project

Create or enter the build directory:

```bash
mkdir -p build
cd build
```

Configure:

```bash
cmake ..
```

Build:

```bash
make -j$(nproc)
```

---

## 4. Run the simulation

The main simulation configuration is:

```text
simulations/omnetpp.ini
```

The project can be run through the OMNeT++ IDE or using the configured simulation environment.

The helper script is also available:

```bash
./scripts/run_all.sh
```

---

# 📈 Results

The simulation records performance metrics such as:

* Detection rate
* True positives
* False positives
* False negatives
* True negatives
* End-to-end latency
* Throughput
* Jitter
* Bandwidth
* Packet loss
* CPU load
* Offloaded packets

OMNeT++ produces:

```text
.sca
.vec
```

files containing scalar and vector simulation results.

These results can subsequently be processed using:

```text
analysis/visualize_results.py
```

Generated plots are stored under:

```text
results/plots/
```

---

# 🔬 Experimental Configurations

The project evaluates different IDS deployment strategies to compare centralized and distributed detection.

Typical configurations include:

| Configuration       | Description                                                                              |
| ------------------- | ---------------------------------------------------------------------------------------- |
| No IDS              | Baseline network without intrusion detection                                             |
| Cloud Only          | Traffic is analyzed centrally by the Cloud                                               |
| Multi-Layer         | Detection distributed across Mist, Edge, Fog and Cloud                                   |
| Combined / Enhanced | Configuration combining the implemented detection mechanisms and optimization strategies |

The purpose of these comparisons is to evaluate the trade-off between **detection capability, latency, resource consumption, and network overhead**.

---

# 🎯 Research Contributions

The project investigates four main contributions.

## 1. Adaptive Offloading

Mist nodes monitor their estimated computational load. When the configured CPU overload threshold is exceeded, detection work can be offloaded toward the Edge layer.

**Goal:** Reduce computational pressure on resource-constrained IoT devices.

---

## 2. Latency-Aware Routing

Edge gateways maintain packet queues and consider packet timing/deadline information when processing traffic.

**Goal:** Prioritize time-sensitive IoT traffic and reduce detection-related delays.

---

## 3. Cascading Policy Updates

The Cloud periodically generates policy updates which propagate through the Fog and Edge layers toward Mist nodes.

**Goal:** Allow distributed IDS components to receive updated detection policies without manually updating every node.

---

## 4. Knowledge Distillation

The Cloud represents the computationally expensive global intelligence, while lighter detection logic is deployed closer to IoT devices.

**Goal:** Bring useful global detection intelligence closer to the network edge while reducing computational and communication overhead.

---

# 🧮 Algorithm

The implemented simulation workflow can be summarized as:

```text
Algorithm 1: Multi-Layer IDS Simulation

1. Initialize OMNeT++ simulation.
2. Deploy Mist, Edge, Fog and Cloud nodes.
3. Load NSL-KDD traffic traces.
4. Generate SensorPackets at Mist nodes.
5. Perform rolling Z-score anomaly detection.
6. Check Mist CPU load and perform adaptive offloading.
7. Forward traffic to the corresponding Edge gateway.
8. Apply rule-based detection at the Edge.
9. Perform Decision Tree lookup classification.
10. Generate IDSAlert when suspicious traffic is identified.
11. Forward alerts to the Fog layer.
12. Perform Random Forest lookup classification at Fog.
13. Correlate alerts within the configured sliding window.
14. Escalate significant attacks to the Cloud.
15. Perform global classification at the Cloud.
16. Periodically generate PolicyUpdate messages.
17. Propagate updated policies through the hierarchy.
18. Record detection and network-performance metrics.
19. Export OMNeT++ scalar and vector results.
20. Analyse results using Python.
```

---

# 📦 Implementation and Availability

The system is implemented using **OMNeT++ and C++**, with Python scripts used for dataset preprocessing, model training, lookup-table generation, and result analysis. The repository contains the `.ned`, `.msg`, `.cc`, `.h`, dataset-processing scripts, generated lookup tables, simulation configuration, and analysis utilities.

> **Repository:** `https://github.com/<your-username>/<repository-name>`

Simulation output files (`.sca` and `.vec`) and generated plots can also be included in the repository or archived through Zenodo for reproducibility.

---

# 🛠️ Technologies Used

| Technology | Purpose                              |
| ---------- | ------------------------------------ |
| OMNeT++    | Discrete-event network simulation    |
| C++        | IDS and network-layer implementation |
| Python     | Dataset processing and ML training   |
| NSL-KDD    | Network intrusion dataset            |
| CMake      | C++ project build system             |
| Git/GitHub | Source-code management               |
| Matplotlib | Result visualization                 |

---

# 📚 Research Context

This project is designed to investigate whether distributing intrusion detection across **Mist, Edge, Fog and Cloud computing layers** can provide a better balance between:

```text
              Detection Accuracy
                     ▲
                     │
                     │
Resource Efficiency ◄┼► Detection Latency
                     │
                     │
                     ▼
              Network Overhead
```

Rather than relying exclusively on centralized Cloud analysis, the architecture attempts to perform detection as close to the traffic source as practical while retaining higher-level analysis for complex or correlated attacks.

---

# ⚠️ Limitations

The current implementation has several limitations:

* The evaluation is simulation-based.
* NSL-KDD is an established benchmark but does not represent all modern IoT traffic.
* Some machine-learning models are represented inside OMNeT++ through generated lookup tables rather than executing full ML inference directly.
* Energy consumption is estimated through simulation parameters rather than measurements from physical IoT hardware.
* Real-world deployment would require additional testing on heterogeneous IoT hardware and networks.

---

# 🚀 Future Work

Possible extensions include:

* Evaluation using CICIDS2017, UNSW-NB15 and TON-IoT.
* Deployment on Raspberry Pi or other edge hardware.
* Real-time network traffic capture.
* More advanced deep-learning models.
* Federated learning across Fog/Edge nodes.
* Hardware-based energy measurements.
* Adversarial attack evaluation.
* Larger-scale IoT simulations.
* Automated model retraining and validation.


