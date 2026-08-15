# AI-Anomaly-IDS

### AI-Powered Anomaly-Based Intrusion Detection System using Isolation Forest

AI-Anomaly-IDS is an anomaly-based Intrusion Detection System (IDS) that monitors network traffic, extracts network-flow features, and identifies traffic behaviour that deviates from the learned baseline.

The system provides a web-based dashboard for continuously monitoring network telemetry and viewing anomaly-detection results.

---

## 🚀 Key Features

- 🔍 **Real Network Traffic Collection**
  - Captures live IPv4 and IPv6 network packets using Scapy.
  - Aggregates observed traffic by source IP.

- 📊 **Network-Flow Feature Extraction**
  - Number of connections
  - Unique destination ports
  - Bytes sent
  - Bytes received
  - SYN ratio
  - Average connection duration

- 🤖 **AI-Based Anomaly Detection**
  - Uses an Isolation Forest model to identify unusual network-flow behaviour.

- 🛡️ **Rule-Based Detection**
  - Complements machine-learning detection with security-oriented traffic indicators.

- ⚡ **Continuous Monitoring**
  - The dashboard continuously updates network-flow parameters.
  - The current prototype refreshes traffic analysis approximately every 10 seconds.

- 🌐 **Web-Based Dashboard**
  - Displays live network telemetry.
  - Shows source IP and traffic characteristics.
  - Displays security indicators and detection results.

- 🐍 **FastAPI Backend**
  - Provides APIs for traffic collection and analysis.
  - Connects the packet-capture layer with the detection pipeline.

- 💻 **React Frontend**
  - Provides the monitoring dashboard and user interface.

---

## 🏛️ System Architecture

```text
                    NETWORK TRAFFIC
                           |
                           v
                 +-------------------+
                 |  Packet Capture   |
                 |  Scapy + Npcap    |
                 +-------------------+
                           |
                           v
                 +-------------------+
                 | Traffic Collector |
                 |   & Aggregation   |
                 +-------------------+
                           |
                           v
                 +-------------------+
                 | Feature Extraction|
                 |                   |
                 | - Connections     |
                 | - Destination     |
                 |   Ports           |
                 | - Bytes           |
                 | - SYN Ratio       |
                 | - Duration        |
                 +-------------------+
                           |
                           v
                 +-------------------+
                 |  Detection Engine |
                 |                   |
                 |  Isolation Forest |
                 |         +         |
                 |    Rule Engine    |
                 +-------------------+
                           |
                           v
                 +-------------------+
                 |    FastAPI API    |
                 +-------------------+
                           |
                           v
                 +-------------------+
                 |  React Dashboard  |
                 |                   |
                 |  Live Monitoring  |
                 |  Traffic Features |
                 |  Detection Results|
                 +-------------------+
```

---

## 🧠 How It Works

The system operates as a network-monitoring and anomaly-detection pipeline.

### 1. Traffic Capture

The sensor captures live network packets using **Scapy**.

On Windows, packet capture is provided through **Npcap**.

```text
Network Interface
       |
       v
     Npcap
       |
       v
     Scapy
```

### 2. Traffic Aggregation

Captured packets are grouped according to their source IP address.

The traffic collector builds network-flow information over a fixed capture window.

### 3. Feature Extraction

The collector extracts measurable characteristics from the observed network traffic.

| Feature | Description |
|---|---|
| `src_ip` | Source IP address |
| `num_connections` | Number of observed connections |
| `unique_dst_ports` | Number of unique destination ports contacted |
| `bytes_sent` | Bytes transmitted by the source |
| `bytes_recv` | Bytes received by the source |
| `syn_ratio` | Ratio of SYN packets to TCP packets |
| `avg_conn_duration` | Average observed connection duration |

### 4. Anomaly Detection

The extracted traffic features are passed to the detection engine.

The project uses **Isolation Forest**, an unsupervised machine-learning algorithm designed to identify observations that differ significantly from the learned traffic pattern.

A rule-based detection layer is also used to complement the machine-learning result with security-oriented indicators.

### 5. Continuous Monitoring

The frontend continuously requests fresh traffic analysis from the backend.

The current prototype refreshes the traffic information approximately every **10 seconds**, allowing users to monitor changing network conditions without manually submitting every traffic sample.

---

## 🛠️ Technology Stack

**Backend**
- Python
- FastAPI
- Scapy
- Pydantic
- Uvicorn

**Machine Learning & Detection**
- Scikit-learn
- Isolation Forest
- Rule-based detection
- Network-flow feature extraction

**Frontend**
- React
- JavaScript
- Vite
- CSS

**Network Monitoring**
- Npcap
- Scapy

**Development & Version Control**
- Visual Studio Code
- Git
- GitHub

---

## 📁 Project Structure

```text
AI-Anomaly-IDS/
|
|-- backend/
|   |-- app/
|   |   |-- api/
|   |   |   |-- routes/
|   |   |       |-- analyze.py
|   |   |
|   |   |-- database/
|   |   |
|   |   |-- models/
|   |   |
|   |   |-- schemas/
|   |   |   |-- flow.py
|   |   |
|   |   |-- services/
|   |   |   |-- ml_service.py
|   |   |   |-- traffic_collector.py
|   |   |
|   |   |-- main.py
|   |
|   |-- requirements.txt
|
|-- data/
|
|-- detection/
|   |-- detector.py
|   |-- preprocessing.py
|
|-- frontend/
|   |-- src/
|   |   |-- components/
|   |   |   |-- AnalyzeForm.jsx
|   |   |   |-- Dashboard.jsx
|   |   |   |-- Login.jsx
|   |   |   |-- MatrixRain.jsx
|   |   |   |-- ResultCard.jsx
|   |   |   |-- ScoreChart.jsx
|   |   |   |-- ThreatLog.jsx
|   |   |
|   |   |-- App.jsx
|   |   |-- App.css
|   |   |-- main.jsx
|   |
|   |-- package.json
|   |-- vite.config.js
|
|-- tests/
|   |-- test_detection.py
|
|-- .gitignore
|-- README.md
```

---

## ⚙️ Installation

### Prerequisites

Before running the system, install:

- Python 3.x
- Node.js and npm
- Git
- Npcap (Windows)

### Npcap

The traffic collector requires a packet-capture driver on Windows.

Install Npcap from the official website: https://npcap.com/

During installation, enable **WinPcap API-compatible mode** if required by your environment.

### Backend Setup

Clone the repository:

```bash
git clone https://github.com/shriyans-deo/AI-Anomaly-IDS.git
```

Move into the project directory:

```bash
cd AI-Anomaly-IDS
```

Create a Python virtual environment:

```bash
python -m venv .venv
```

Activate the environment on Windows:

```bash
.venv\Scripts\activate
```

Install the backend dependencies:

```bash
pip install -r backend/requirements.txt
```

---

## ▶️ Running the Backend

From the project root:

```bash
python -m uvicorn backend.app.main:app --reload
```

The FastAPI server will normally be available at:

```text
http://127.0.0.1:8000
```

FastAPI documentation:

```text
http://127.0.0.1:8000/docs
```

The Swagger interface can be used to inspect and test the available API endpoints.

> **Windows note:** Packet capture may require running the terminal with appropriate administrator privileges depending on the Npcap configuration.

---

## 💻 Running the Frontend

Open another terminal.

Move into the frontend directory:

```bash
cd frontend
```

Install the frontend dependencies:

```bash
npm install
```

Start the Vite development server:

```bash
npm run dev
```

Vite will normally provide:

```text
http://localhost:5173
```

Open the displayed URL in your browser.

---

## 🌐 Network Interface Selection

The traffic collector operates on a network interface available to the host system.

The backend provides an interface-discovery endpoint:

```text
GET /interfaces
```

This allows the application to identify available capture-capable network interfaces.

On Windows, interface names are provided by Scapy/Npcap and may not resemble simple interface names such as `eth0`.

---

## 🔍 Traffic Collection API

The backend provides:

```text
GET /collect
```

This endpoint captures traffic over the configured collection window and returns the observed network flows.

A typical flow contains information such as:

```json
{
  "src_ip": "192.168.137.1",
  "num_connections": 2,
  "unique_dst_ports": 2,
  "bytes_sent": 2240.0,
  "bytes_recv": 369.0,
  "failed_logins": 0,
  "syn_ratio": 0.0,
  "avg_conn_duration": 0.668,
  "label": "normal"
}
```

---

## 🤖 Live Analysis

The backend provides a live analysis endpoint:

```text
POST /analyze/live
```

The live-analysis pipeline:

1. Captures live network traffic.
2. Identifies the primary/busiest observed flow.
3. Extracts its network-flow features.
4. Sends the features through the existing detection pipeline.
5. Returns the traffic information and detection result.

---

## 📊 Dashboard

The web dashboard displays the following categories of telemetry.

**Network Identity**
- Source IP
- Timestamp
- Traffic label

**Connection Metrics**
- Number of connections
- Unique destination ports
- Average connection duration

**Traffic Volume**
- Bytes sent
- Bytes received

**Security Indicators**
- Failed logins
- SYN ratio

The interface is designed for continuous monitoring so that the user can observe changing traffic characteristics without manually submitting every individual sample.

---

## 🔄 Continuous Monitoring

The current prototype refreshes live traffic information approximately every **10 seconds**.

The monitoring cycle can be represented as:

```text
Capture Traffic
      |
      v
Extract Features
      |
      v
Run Detection
      |
      v
Update Dashboard
      |
      v
Wait ~10 seconds
      |
      v
Capture Again
      |
      v
     ...
```

---

## 🧪 Testing

The project includes automated detection tests under:

```text
tests/
```

The prototype has been tested for:

- Traffic collection
- Feature extraction
- API communication
- Detection pipeline
- Dashboard data display
- Continuous monitoring behaviour

Further controlled attack testing can be performed in an isolated and authorized environment.

---

## ⚠️ Current Limitations

AI-Anomaly-IDS is currently a **working prototype** and is not intended to be presented as a production-grade enterprise IDS.

### 1. Host-Level Packet Capture

The sensor captures traffic visible to the network interface on the machine where it is running.

It does not automatically see all traffic from every device on a normal switched network.

For network-wide deployment, the sensor would require an appropriate authorized observation point such as:

- Network TAP
- SPAN/mirror port
- Gateway placement
- Other authorized traffic-monitoring architecture

### 2. Windows Packet-Capture Dependency

On Windows, Scapy requires an appropriate packet-capture driver such as Npcap.

Therefore, the machine running the sensor requires the appropriate packet-capture environment.

### 3. Authentication Logs

Failed authentication attempts cannot be reliably determined from ordinary network packets alone.

Authentication events would require integration with operating-system authentication logs or another authorized log source.

### 4. Ground-Truth Labels

A live packet collector cannot inherently know whether an observed flow is a genuine attack.

Ground-truth labels are therefore not treated as information that can be independently determined by the packet collector.

### 5. Prototype Detection Model

Isolation Forest is suitable for anomaly-detection research and prototyping.

A production IDS would require extensive validation using representative network traffic, attack scenarios, false-positive analysis, and continuous model evaluation.

---

## 🔐 Security & Responsible Use

AI-Anomaly-IDS is intended for:

- Authorized network monitoring
- Cybersecurity education
- Controlled laboratory environments
- Security research
- Testing on systems and networks where the operator has permission

**Do not use this system to monitor or inspect network traffic without appropriate authorization.**

Any penetration testing or attack simulation should only be performed against systems you own or have explicit permission to test.

---

## 🎥 Project Demonstration

### Demo Video

<!-- Drag and drop your screen recording here in the GitHub web editor. -->

> The demonstration shows the AI-Anomaly-IDS dashboard, live network telemetry, feature updates, and anomaly-detection workflow.

---

## 📸 Screenshots

### Live Monitoring Dashboard

<!-- Add a screenshot of the dashboard here -->

### Detection Results

<!-- Add a screenshot of the result card and threat log here -->

---

## 🎯 Project Objective

The objective of AI-Anomaly-IDS is to demonstrate how **network telemetry, feature engineering, machine learning, and a real-time web interface** can be combined to build an anomaly-based intrusion detection system.

Instead of relying exclusively on predefined attack signatures, the system analyzes network-flow characteristics and attempts to identify traffic behaviour that differs from the expected pattern.

The project combines:

```text
Network Monitoring
        +
Feature Engineering
        +
Machine Learning
        +
Rule-Based Detection
        +
Real-Time Web Dashboard
```

to create an end-to-end anomaly-based IDS prototype.

---

## 👥 Contributors

- Shriyans Deo
- Tanvir Laskar

---

## 📌 Project Status

**Prototype Complete ✅**

Current implementation includes:

- ✅ Real network traffic collection
- ✅ Network-flow feature extraction
- ✅ Isolation Forest anomaly detection
- ✅ Rule-based detection
- ✅ FastAPI backend
- ✅ React frontend
- ✅ Continuous traffic monitoring
- ✅ Live telemetry dashboard
- ✅ GitHub repository

Further real-world attack validation can be performed separately in an authorized test environment.

---

## ⭐ Repository

GitHub: https://github.com/shriyans-deo/AI-Anomaly-IDS
