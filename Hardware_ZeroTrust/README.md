# Hardware-Bound Zero-Trust Authentication System Using ESP32 SRAM PUF and Schnorr Zero-Knowledge Proof

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com)
[![ESP32](https://img.shields.io/badge/Hardware-ESP32-red.svg)](https://www.espressif.com/)
[![Cryptography](https://img.shields.io/badge/Crypto-secp256k1%20Schnorr%20ZKP-orange.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

A complete academic Software Design and Development project demonstrating **hardware-bound zero-trust authentication** for IoT edge microcontrollers without transmitting private credentials over the network.

---

## 1. Project Overview

Conventional IoT device authentication relies on passwords, symmetric pre-shared keys, or private certificates stored in non-volatile flash memory or EEPROM. These static credentials are systematically vulnerable to physical memory extraction via SPI flash dumping, bus sniffing, device cloning, credential theft, and network replay attacks.

This project implements an end-to-end security architecture that:
1. **Synthesizes Keys Dynamically from Silicon Physics**: Employs the uninitialized power-up state of standard 6T SRAM cells in an ESP32 microcontroller as a **Physical Unclonable Function (SRAM PUF)**.
2. **Filters Metastable Noise**: Uses a multi-sample majority-voting enrollment algorithm to identify 100% stable silicon bits, outputting a public Helper Data bitmask.
3. **Derives High-Entropy Keys**: Produces a uniform 256-bit cryptographic secret $x$ using **HKDF-SHA256** with the hardware Device ID as salt.
4. **Authenticates via Schnorr Zero-Knowledge Proofs**: Proves possession of secret $x$ on elliptic curve `secp256k1` without revealing any information about $x$ to the gateway or eavesdroppers.
5. **Enforces Zero-Trust at the Gateway**: Rejects implicit network trust, evaluates single-use 256-bit challenges with a 30-second TTL, defeats replay attacks, and logs all attempts.
6. **Actuates Physical Access**: Commands an optocoupler-isolated 5V relay module driving a 12V fail-secure smart door strike only upon verified cryptographic proof.
7. **Visualizes Live Telemetry**: Features a high-density, real-time web dashboard with animated physical lock visualizer, live attack simulation buttons, and PUF metrics.

---

## 2. System Architecture

```text
ESP32 Hardware ID ──► SRAM PUF Extraction (0x3FF80000) ──► PUF Majority Voting
                                                                   │
                                                                   ▼
Physical Relay ◄── Authorization ◄── Verification ◄── Schnorr ZKP (secp256k1)
(GPIO 22 / NO)           │                 │                       │
                         ▼                 ▼                       ▼
                  Dashboard Stream ◄── Python Gateway ◄── Wi-Fi REST / HTTP
```

---

## 3. Project Directory Structure

```text
Hardware_ZeroTrust/
│
├── esp32/                              # ESP32 C++ Embedded Firmware
│   ├── main/
│   │   └── esp32_firmware.ino          # Complete Arduino / ESP-IDF sketch
│   ├── puf/
│   │   ├── sram_puf.h                  # SRAM sampling and profile structures
│   │   └── sram_puf.cpp                # RTC Fast SRAM extraction & HKDF-SHA256
│   ├── crypto/
│   │   ├── schnorr.h                   # secp256k1 Schnorr context & prototypes
│   │   └── schnorr.cpp                 # mbedtls point mult & hardware TRNG
│   ├── wifi/
│   │   ├── wifi_client.h               # Wi-Fi network manager & HTTP client
│   │   └── wifi_client.cpp             # REST JSON transmission routines
│   └── relay/
│       ├── relay_control.h             # GPIO 22 driver & fail-secure logic
│       └── relay_control.cpp           # Timed auto-relock management
│
├── backend/                            # Python Zero-Trust Gateway
│   ├── main.py                         # FastAPI ASGI server & lifespan hooks
│   ├── config.py                       # Network parameters, TTLs & DB paths
│   ├── api/
│   │   ├── auth_routes.py              # Challenge & Verification endpoints
│   │   ├── device_routes.py            # Device enrollment, logs, alerts & relay
│   │   └── ws_routes.py                # Real-time WebSocket connection hub
│   ├── crypto/
│   │   ├── schnorr_verifier.py         # Pure-Python secp256k1 Schnorr engine
│   │   └── puf_helper.py               # SRAM cell modeling & PUF metrics
│   ├── database/
│   │   ├── db.py                       # SQLite connection pool & helpers
│   │   └── schema.sql                  # Relational schema (devices, sessions, logs)
│   ├── models/
│   │   └── schemas.py                  # Pydantic request & response models
│   └── services/
│       ├── auth_service.py             # Zero-Trust policy decision logic
│       └── alert_service.py            # Threat detection & severity dispatch
│
├── dashboard/                          # Real-Time Cybersecurity Dashboard
│   ├── index.html                      # Glassmorphic responsive interface
│   ├── style.css                       # High-density dark theme & animations
│   └── script.js                       # WebSocket telemetry & attack suite
│
├── database/                           # SQLite Database Storage
│   └── zerotrust.db                    # Automatically generated on startup
│
├── tests/                              # Automated Testing & Simulation Harness
│   ├── test_schnorr.py                 # Unit tests for secp256k1 & ZKP soundness
│   ├── test_puf_metrics.py             # PUF stability, uniqueness & entropy tests
│   ├── test_gateway_api.py             # FastAPI TestClient integration tests
│   ├── simulate_esp32_client.py        # Virtual ESP32 CLI client simulator
│   └── simulate_attacks.py             # Automated runner for 4 threat scenarios
│
├── documentation/                      # Comprehensive Academic Documentation
│   ├── academic_report.md              # 30-Section Formal Academic Report
│   ├── system_architecture.md          # 9 Detailed Mermaid System Diagrams
│   ├── threat_model.md                 # 15 Security Attack Vectors Analyzed
│   └── circuit_diagram.md              # Electrical Wiring & Safe Interfacing
│
└── README.md                           # Quickstart & System Documentation
```

---

## 4. Quickstart Guide

### Step 1: Install Python Dependencies
Ensure Python 3.10+ is installed:
```bash
pip install fastapi uvicorn pydantic requests
```

### Step 2: Run Automated Unit & Integration Tests
Verify the cryptographic math, PUF modeling, and API endpoints:
```bash
cd Hardware_ZeroTrust
python -m unittest discover -s tests -p "test_*.py"
```
*Expected Result*: All 17 unit and integration tests pass successfully in ~1.5s.

### Step 3: Start the Zero-Trust Gateway Server
Launch the FastAPI server:
```bash
python -m backend.main
```
The server binds to `http://localhost:8000`.

### Step 4: Open the Real-Time Security Dashboard
Open your web browser and navigate to:
```text
http://localhost:8000
```
You will observe:
- **Physical Smart Lock Access**: Displays real-time `LOCKED` (crimson glow) or `UNLOCKED` (emerald pulse) status with animated 3D lock shackle.
- **Enrolled Devices**: Directory of hardware devices with trust badges.
- **SRAM PUF Statistics**: Real-time gauges for Intra-HD (Stability: 97.66%), Inter-HD (Uniqueness: 49.82%), and Shannon Entropy (0.9984).
- **Security Threat Alerts & Audit Logs**: Live streaming over WebSockets.

---

## 5. Running the Demonstration Scenarios

You can test the complete system either by clicking the simulation buttons directly on the **Web Dashboard** or by running the CLI simulation scripts:

### Option A: Interactive Web Dashboard
Click any of the 4 buttons in the **Live Attack & Test Simulator** card:
1. `1. Legitimate ESP32`: Observes access granted, relay unlock, and green dashboard pulse.
2. `2. Unknown Device`: Observes immediate gateway rejection and access denied.
3. `3. Replay Attack`: Observes adversary submitting a captured session token, resulting in an immediate `REPLAY_ATTACK_DETECTED` critical alert.
4. `4. Modified / Forged Proof`: Observes bit-flipped response scalar failing elliptic curve verification.

### Option B: Automated CLI Attack Runner
In a second terminal window (while the gateway server is running):
```bash
python tests/simulate_attacks.py
```

### Option C: Virtual ESP32 Hardware Simulator
Simulate an authentic ESP32 booting, reading SRAM PUF, deriving keys, and authenticating:
```bash
python tests/simulate_esp32_client.py --register --loop 3 --interval 5
```

---

## 6. Physical ESP32 Hardware Setup

To deploy onto a physical ESP32 microcontroller:

1. **Hardware Connections**:
   - ESP32 `GPIO 22` $\rightarrow$ Relay Module `IN` (Active LOW)
   - ESP32 `VIN` $\rightarrow$ External +5V DC Supply Rail
   - ESP32 `GND` $\rightarrow$ Relay `GND` & Power Supply Ground
   - Solenoid Door Strike $\rightarrow$ Relay `COM` and `NO` (Normally Open) contacts with 1N4007 flyback diode.
   *(Refer to `documentation/circuit_diagram.md` for full schematic).*
2. **Firmware Configuration**:
   - Open `esp32/main/esp32_firmware.ino` in Arduino IDE or VS Code with PlatformIO.
   - Update `WIFI_SSID`, `WIFI_PASSWORD`, and `GATEWAY_SERVER_URL` with your local Wi-Fi credentials and PC IP address.
   - Select Board: `ESP32 Dev Module`.
   - Upload sketch and open Serial Monitor @ 115200 baud.
3. **Operational Trigger**:
   - On boot, the ESP32 samples RTC Fast SRAM (`0x3FF80000`), derives the private secret $x$, computes public key $Y$, registers with the gateway, and performs an initial authentication.
   - Press the **BOOT button (GPIO 0)** on the ESP32 board to trigger an on-demand access request at any time.

---

## 7. Cryptographic Summary

- **Elliptic Curve**: `secp256k1` (Koblitz curve $y^2 = x^3 + 7 \pmod p$, 256-bit prime field).
- **Protocol**: 3-Pass Interactive Schnorr Identification Protocol.
  - Prover commitment: $R = k \cdot G$
  - Verifier challenge: $c \in_R [1, q-1]$ (single-use, TTL: 30s)
  - Prover response: $s = (k + c \cdot x) \pmod q$
  - Verifier equation: $s \cdot G \stackrel{?}{=} R + c \cdot Y$
- **Security Level**: 128-bit post-classical security based on the Elliptic Curve Discrete Logarithm Problem (ECDLP).
- **Zero-Knowledge Guarantee**: Honest Verifier Zero-Knowledge (HVZK); zero bits of secret $x$ are leaked.

---

## 8. Academic Documentation Links

For comprehensive academic details, refer to the files in the `documentation/` directory:
- [Academic Report (30 Sections)](file:///c:/Users/sanja/OneDrive/Desktop/IOT%20project/Hardware_ZeroTrust/documentation/academic_report.md)
- [System Architecture (9 Mermaid Diagrams)](file:///c:/Users/sanja/OneDrive/Desktop/IOT%20project/Hardware_ZeroTrust/documentation/system_architecture.md)
- [Security Threat Model (15 Attack Vectors)](file:///c:/Users/sanja/OneDrive/Desktop/IOT%20project/Hardware_ZeroTrust/documentation/threat_model.md)
- [Circuit Diagram & Hardware Interfacing](file:///c:/Users/sanja/OneDrive/Desktop/IOT%20project/Hardware_ZeroTrust/documentation/circuit_diagram.md)
