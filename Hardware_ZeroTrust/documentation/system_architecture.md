# System Architecture and Design Diagrams

This document contains the complete formal architecture diagrams for the **Hardware-Bound Zero-Trust Authentication System Using ESP32 SRAM PUF and Schnorr Zero-Knowledge Proof**.

---

## 1. System Architecture Diagram

```mermaid
graph TB
    subgraph "Edge Device Layer (ESP32)"
        HW[ESP32 Hardware] --> EFUSE[eFuse Silicon MAC & Chip Info]
        HW --> SRAM[Uninitialized SRAM / RTC Fast Memory 0x3FF80000]
        SRAM --> PUF_MOD[SRAM PUF Engine]
        PUF_MOD --> HELPER[Helper Data / Stable Bitmask Filter]
        HELPER --> KDF[HKDF-SHA256 Key Derivation]
        KDF --> SECRET["Private Secret x (In-Memory Only)"]
        SECRET --> SCHNORR_PROVER[Schnorr ZKP Engine]
        SCHNORR_PROVER --> NET_CLIENT[Wi-Fi REST Client]
        RELAY_DRIVER[Relay Access Controller] --> RELAY_HW[5V Optocoupler Relay & Door Lock]
    end

    subgraph "Network Layer"
        NET_CLIENT <==>|Wi-Fi 802.11 b/g/n / HTTP REST| GATEWAY_API
    end

    subgraph "Zero-Trust Gateway Layer (Python / FastAPI)"
        GATEWAY_API[FastAPI Gateway Endpoints] --> AUTH_SVC[Zero-Trust Authentication Service]
        AUTH_SVC --> REPLAY_ENGINE[Replay Protection & Challenge Manager]
        AUTH_SVC --> VERIFIER[Schnorr secp256k1 Verifier]
        AUTH_SVC --> ALERT_SVC[Security Threat & Alert Service]
        VERIFIER --> DB[(SQLite Database)]
        ALERT_SVC --> WS_BROADCASTER[WebSocket Telemetry Hub]
    end

    subgraph "Presentation & Operations Layer"
        WS_BROADCASTER ==>|WebSocket Duplex Stream| DASHBOARD[Real-Time Security Dashboard]
        DASHBOARD --> TELEMETRY[Live Threat Telemetry & PUF Metrics]
        DASHBOARD --> SIM_SUITE[Interactive Attack Demonstration Suite]
        DASHBOARD --> LOCK_STATUS[Physical Relay Lock Visualizer]
    end

    AUTH_SVC -.->|Unlock Signal| NET_CLIENT
    NET_CLIENT -.->|Command| RELAY_DRIVER
```

---

## 2. System Flowchart

```mermaid
flowchart TD
    Start([System Power-On / Boot]) --> ReadHW[Read eFuse MAC & Chip Model]
    ReadHW --> ReadSRAM[Sample RTC Fast SRAM Startup State]
    ReadSRAM --> CheckEnroll{Device Enrolled?}
    
    CheckEnroll -- No --> MultiSample[Acquire N=11 Power-On Samples]
    MultiSample --> MajVote[Majority Voting & Filter Stable Bits]
    MajVote --> GenHelper[Generate Helper Data Bitmask]
    GenHelper --> DeriveEnrollKey[Derive Secret x via HKDF-SHA256]
    DeriveEnrollKey --> CalcPub[Compute Public Key Y = x * G]
    CalcPub --> RegGateway[POST /api/device/register]
    RegGateway --> EnrolledState[State: Registered & UNTRUSTED]
    
    CheckEnroll -- Yes --> ReadCurrent[Read Current Power-On SRAM]
    EnrolledState --> ReadCurrent
    ReadCurrent --> FilterHelper[Filter Noise via Helper Data Mask]
    FilterHelper --> DeriveSecret[Derive Secret x via HKDF-SHA256]
    
    DeriveSecret --> GenNonce[Generate Random Ephemeral Nonce k]
    GenNonce --> CalcR[Compute Commitment R = k * G]
    CalcR --> SendCommit[POST /api/auth/challenge with DeviceID & R]
    
    SendCommit --> RecvChal{Challenge Issued?}
    RecvChal -- Error/Timeout --> DenyAccess[Access Denied & Relay LOCKED]
    RecvChal -- Success --> ComputeS[Compute Response s = k + c * x mod q]
    ComputeS --> WipeK[Securely Wipe Nonce k from Memory]
    WipeK --> SendProof[POST /api/auth/verify with SessionID, DeviceID & s]
    
    SendProof --> VerifyProof{s * G == R + c * Y?}
    VerifyProof -- Valid & Fresh --> MarkTrusted[Mark Device: TRUSTED]
    MarkTrusted --> UnlockRelay[Actuate Relay: UNLOCKED for 5s]
    UnlockRelay --> LogPass[Log Authentication SUCCESS]
    LogPass --> PushWS[Push Telemetry over WebSocket]
    
    VerifyProof -- Invalid / Replayed --> MarkUntrusted[Mark Device: UNTRUSTED]
    MarkUntrusted --> LockRelay[Ensure Relay: LOCKED]
    LockRelay --> TriggerAlert[Trigger SECURITY ALERT: Replay/Tampered]
    TriggerAlert --> LogFail[Log Authentication FAILED]
    LogFail --> PushWS
    
    UnlockRelay --> TimerRelock{Timer >= 5s?}
    TimerRelock -- Yes --> AutoLock[Auto-Relock Door]
    AutoLock --> EndCycle([End of Cycle / Standby])
    LockRelay --> EndCycle
```

---

## 3. Data Flow Diagram (DFD Level 0 & Level 1)

### Level 0 Context Diagram
```mermaid
graph LR
    ESP32[ESP32 IoT Node] -- "1. Registration (ID, MAC, Public Key Y)" --> GATEWAY((Zero-Trust Gateway))
    ESP32 -- "2. Commitment R = k*G" --> GATEWAY
    GATEWAY -- "3. Ephemeral Challenge c" --> ESP32
    ESP32 -- "4. Schnorr Response s" --> GATEWAY
    GATEWAY -- "5. Verification Status & Relay Command" --> ESP32
    GATEWAY -- "6. Real-Time Telemetry & Alerts" --> DASHBOARD[Security Dashboard]
    ADMIN[Security Administrator] -- "7. Manual Override / Attack Trigger" --> DASHBOARD
    DASHBOARD -- "8. API Requests" --> GATEWAY
```

### Level 1 DFD
```mermaid
graph TB
    subgraph ESP32 Boundary
        D1[Silicon SRAM & eFuse] --> P1[PUF Extraction & KDF]
        P1 -->|Private Secret x| P2[Schnorr Prover]
        P2 -->|Commitment R| P3[Network Interface]
        P3 -->|Response s| P2
    end

    subgraph Gateway Boundary
        P3 ==>|HTTP POST| P4[Authentication Controller]
        P4 -->|Store Session| D2[(Session Store)]
        P4 -->|Fetch Key Y| D3[(Device Registry)]
        P4 --> P5[secp256k1 Verifier]
        D2 --> P5
        D3 --> P5
        P5 -->|Log Result| D4[(Audit Logs)]
        P5 -->|Raise Event| P6[Alert & Threat Engine]
        P6 -->|Write Alert| D5[(Security Alerts)]
        P5 -->|State Change| P7[Relay State Manager]
        P7 --> D6[(Relay State)]
        P6 --> P8[WebSocket Broadcaster]
        P7 --> P8
    end

    P8 ==>|WS JSON Stream| UI[Dashboard UI]
```

---

## 4. Use Case Diagram

```mermaid
graph TD
    ACT_IOT((ESP32 Microcontroller))
    ACT_ADMIN((Security Officer))
    ACT_ATTACKER((Network Adversary))

    subgraph Zero-Trust Authentication System
        UC1[Extract SRAM PUF & Hardware ID]
        UC2[Enroll Device & Register Public Key]
        UC3[Request Single-Use Authentication Challenge]
        UC4[Generate Schnorr Zero-Knowledge Proof]
        UC5[Verify Proof & Enforce Zero-Trust Rules]
        UC6[Actuate Physical Smart Lock Relay]
        UC7[Detect Replay Attacks & Forged Proofs]
        UC8[Monitor Telemetry & PUF Metrics in Real Time]
        UC9[Trigger Attack Simulations]
        UC10[Manual Relay Administrative Override]
    end

    ACT_IOT --> UC1
    ACT_IOT --> UC2
    ACT_IOT --> UC3
    ACT_IOT --> UC4
    ACT_IOT --> UC6

    UC3 --> UC5
    UC4 --> UC5
    UC5 --> UC6
    UC5 --> UC7

    ACT_ADMIN --> UC8
    ACT_ADMIN --> UC9
    ACT_ADMIN --> UC10

    ACT_ATTACKER -.->|Attempts Replay| UC7
    ACT_ATTACKER -.->|Attempts Proof Modification| UC7
    ACT_ATTACKER -.->|Spoofs MAC Address| UC5
```

---

## 5. Sequence Diagram: Complete System Interaction

```mermaid
sequenceDiagram
    autonumber
    participant ESP as ESP32 Hardware
    participant GW as Zero-Trust Gateway
    participant DB as SQLite Database
    participant REL as Physical Relay
    participant DASH as Security Dashboard

    Note over ESP: Cold Boot / Reset
    ESP->>ESP: Read eFuse MAC & Chip Info
    ESP->>ESP: Sample RTC Fast SRAM (0x3FF80000)
    ESP->>ESP: Apply Helper Data & HKDF-SHA256 -> Secret x
    ESP->>ESP: Derive Public Key Y = x * G

    ESP->>GW: POST /api/device/register (ID, MAC, Y, Helper Data)
    GW->>DB: Store Device Record (Status: UNTRUSTED)
    GW->>DASH: WS Broadcast: DEVICE_REGISTERED

    Note over ESP: User Presses Button / Periodic Auth
    ESP->>ESP: Pick Random k in [1, q-1], Compute R = k * G
    ESP->>GW: POST /api/auth/challenge (DeviceID, Commitment R)
    GW->>DB: Validate Device ID
    GW->>GW: Generate Cryptographic Challenge c in [1, q-1]
    GW->>DB: Store Session (SessionID, R, c, TTL=30s, used=0)
    GW->>DASH: WS Broadcast: AUTH_CHALLENGE_ISSUED
    GW-->>ESP: Return {session_id, challenge: c, expires_in: 30}

    ESP->>ESP: Compute Response s = (k + c * x) mod q
    ESP->>ESP: Securely Wipe Nonce k
    ESP->>GW: POST /api/auth/verify (SessionID, DeviceID, Response s)

    GW->>DB: Query Session & Check used == 0 AND now <= expires_at
    GW->>DB: Mark Session used = 1 (Atomically Prevents Replay)
    GW->>DB: Fetch Public Key Y for DeviceID
    GW->>GW: Verify s * G == R + c * Y

    alt Verification Succeeded
        GW->>DB: Update Trust Status -> TRUSTED, Success Count++
        GW->>DB: Update Relay State -> UNLOCKED (Auto-lock in 5s)
        GW->>DB: Write Authentication Log (Result: SUCCESS)
        GW->>DASH: WS Broadcast: AUTH_SUCCESS, Relay: UNLOCKED
        GW-->>ESP: Return {authenticated: true, relay_status: "UNLOCKED"}
        ESP->>REL: Drive GPIO 22 LOW -> Relay Energizes (Door Unlocks)
        Note over ESP,REL: 5 Second Access Window
        ESP->>REL: Drive GPIO 22 HIGH -> Relay De-energizes (Door Locks)
    else Verification Failed / Replay Detected
        GW->>DB: Update Trust Status -> UNTRUSTED, Fail Count++
        GW->>DB: Write Alert (Type: REPLAY_ATTACK / INVALID_PROOF)
        GW->>DB: Write Authentication Log (Result: REPLAY_ATTACK / FAILED)
        GW->>DASH: WS Broadcast: SECURITY_ALERT, Relay: LOCKED
        GW-->>ESP: Return {authenticated: false, relay_status: "LOCKED"}
        ESP->>REL: Keep GPIO 22 HIGH -> Door Remains Locked
    end
```

---

## 6. Entity Relationship (ER) Diagram

```mermaid
erDiagram
    DEVICES ||--o{ AUTH_SESSIONS : initiates
    DEVICES ||--o{ AUTHENTICATION_LOGS : produces
    DEVICES ||--o{ SECURITY_ALERTS : targets

    DEVICES {
        int id PK
        string device_id UK
        string mac_address
        string chip_model
        int chip_revision
        string public_key
        string helper_data
        string trust_status
        timestamp registration_time
        timestamp last_seen
        int auth_success_count
        int auth_fail_count
    }

    AUTH_SESSIONS {
        string session_id PK
        string device_id FK
        string commitment
        string challenge
        timestamp created_at
        timestamp expires_at
        int used
    }

    AUTHENTICATION_LOGS {
        int id PK
        string device_id FK
        timestamp timestamp
        string result
        float latency_ms
        string failure_reason
        string client_ip
    }

    SECURITY_ALERTS {
        int id PK
        string device_id FK
        string alert_type
        string description
        timestamp timestamp
        string severity
        int resolved
    }

    RELAY_STATE {
        int id PK
        string status
        timestamp last_changed
        string triggered_by
        timestamp auto_lock_at
    }
```

---

## 7. Interactive 3-Pass Schnorr Authentication Sequence

```mermaid
sequenceDiagram
    participant P as ESP32 Prover (Holds Secret x)
    participant V as Gateway Verifier (Holds Public Key Y = x*G)

    Note over P: Phase 1: Commitment
    P->>P: Sample Ephemeral Nonce k ← {1, ..., q-1}
    P->>P: Calculate Commitment Point R = k · G
    P->>V: Message 1: { Device_ID, Commitment R }

    Note over V: Phase 2: Fresh Challenge
    V->>V: Verify Device_ID registered
    V->>V: Generate Challenge c ← {1, ..., q-1}
    V->>V: Start Session Timer (TTL = 30s)
    V->>P: Message 2: { Session_ID, Challenge c }

    Note over P: Phase 3: Response
    P->>P: Calculate Scalar Response s = (k + c · x) mod q
    P->>P: Overwrite Nonce k with 0x00
    P->>V: Message 3: { Session_ID, Device_ID, Response s }

    Note over V: Phase 4: Verification
    V->>V: Ensure Session_ID is fresh, valid & unconsumed
    V->>V: Consume Session_ID immediately (used := 1)
    V->>V: Check: s · G =?= R + c · Y
    Note over V: [Completeness Proof: (k + c·x)·G = k·G + c·(x·G) = R + c·Y]
    V-->>P: Decision: GRANTED (if equal) / DENIED (if unequal)
```

---

## 8. Deployment Diagram

```mermaid
graph TB
    subgraph "Edge Field Environment"
        subgraph "Smart Door Enclosure"
            ESP[ESP32-WROOM-32 Microcontroller]
            PSU_ESP[3.3V / 5V DC Power Supply] --> ESP
            RELAY_MOD[5V Optocoupler Relay Board]
            LOCK[12V Solenoid Smart Door Strike]
            EXT_PSU[12V DC Auxiliary Supply] --> LOCK
            ESP -- GPIO 22 Logic --> RELAY_MOD
            RELAY_MOD -- Normally Open NO Relay Contacts --> LOCK
        end
    end

    subgraph "Local Network (WLAN 802.11 b/g/n)"
        AP[Wi-Fi Access Point / Router]
        ESP <==>|WPA2-PSK 2.4GHz| AP
    end

    subgraph "Zero-Trust Gateway Server"
        SRV[Python FastAPI Application Server]
        UVICORN[Uvicorn ASGI Engine :8000]
        SQLITE[(SQLite Embedded Database)]
        AP <==>|TCP/IP Ethernet or Wi-Fi| UVICORN
        UVICORN --> SRV
        SRV --> SQLITE
    end

    subgraph "Control Room / Client Station"
        BROWSER[Web Browser Dashboard Client]
        BROWSER <==>|HTTP / WebSocket :8000| UVICORN
    end
```

---

## 9. Hardware Connection Diagram

```mermaid
graph LR
    subgraph "ESP32 DevKit V1"
        ESP_3V3[3V3]
        ESP_GND[GND]
        ESP_GPIO22[GPIO 22]
        ESP_GPIO0[GPIO 0 - BOOT]
        ESP_VIN[VIN / 5V]
    end

    subgraph "5V Relay Module (Optocoupler Isolated)"
        R_VCC[VCC (+5V)]
        R_GND[GND]
        R_IN[IN (Active LOW)]
        R_JD_VCC[JD-VCC (Relay Coil 5V)]
        R_COM[COM (Common Contact)]
        R_NO[NO (Normally Open Contact)]
        R_NC[NC (Normally Closed Contact)]
    end

    subgraph "Power Supply & Lock"
        DC5V_POS[+5V DC Rail]
        DC_GND[Common GND Rail]
        DC12V_POS[+12V DC Power]
        SOLENOID[12V Solenoid Door Strike]
        FLYBACK[1N4007 Flyback Diode]
    end

    DC5V_POS --> ESP_VIN
    DC5V_POS --> R_VCC
    DC5V_POS --> R_JD_VCC
    DC_GND --> ESP_GND
    DC_GND --> R_GND

    ESP_GPIO22 -->|Logic Signal| R_IN

    DC12V_POS --> R_COM
    R_NO --> SOLENOID
    SOLENOID --> DC_GND
    FLYBACK -.->|Reverse Biased across Coil| SOLENOID
```
