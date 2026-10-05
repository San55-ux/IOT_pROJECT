# Hardware-Bound Zero-Trust Authentication System Using ESP32 SRAM PUF and Schnorr Zero-Knowledge Proof

The complete codebase, documentation, tests, firmware, and dashboard are located in:
👉 **[`Hardware_ZeroTrust/`](file:///c:/Users/sanja/OneDrive/Desktop/IOT%20project/Hardware_ZeroTrust)**

### Quick Links
- **[Main Project README](file:///c:/Users/sanja/OneDrive/Desktop/IOT%20project/Hardware_ZeroTrust/README.md)**
- **[Full Academic Report (30 Sections)](file:///c:/Users/sanja/OneDrive/Desktop/IOT%20project/Hardware_ZeroTrust/documentation/academic_report.md)**
- **[System Architecture & 9 Mermaid Diagrams](file:///c:/Users/sanja/OneDrive/Desktop/IOT%20project/Hardware_ZeroTrust/documentation/system_architecture.md)**
- **[Security Threat Model (15 Threat Vectors)](file:///c:/Users/sanja/OneDrive/Desktop/IOT%20project/Hardware_ZeroTrust/documentation/threat_model.md)**
- **[Hardware Circuit Diagram & Relay Wiring](file:///c:/Users/sanja/OneDrive/Desktop/IOT%20project/Hardware_ZeroTrust/documentation/circuit_diagram.md)**
- **[ESP32 Firmware Source](file:///c:/Users/sanja/OneDrive/Desktop/IOT%20project/Hardware_ZeroTrust/esp32/main/esp32_firmware.ino)**
- **[Python Zero-Trust Gateway Server](file:///c:/Users/sanja/OneDrive/Desktop/IOT%20project/Hardware_ZeroTrust/backend/main.py)**
- **[Real-Time Security Dashboard](file:///c:/Users/sanja/OneDrive/Desktop/IOT%20project/Hardware_ZeroTrust/dashboard/index.html)**
- **[Automated Attack Simulator](file:///c:/Users/sanja/OneDrive/Desktop/IOT%20project/Hardware_ZeroTrust/tests/simulate_attacks.py)**
- **[Virtual ESP32 Simulator](file:///c:/Users/sanja/OneDrive/Desktop/IOT%20project/Hardware_ZeroTrust/tests/simulate_esp32_client.py)**

### Quick Execution
```bash
cd Hardware_ZeroTrust
python -m unittest discover -s tests -p "test_*.py"   # Run 17 automated tests
python -m backend.main                               # Start Gateway server (Dashboard on http://localhost:8000)
python tests/simulate_attacks.py                     # Run the 4 demonstration attack scenarios
```
