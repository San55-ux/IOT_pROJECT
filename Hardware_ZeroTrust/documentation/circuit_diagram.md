# Hardware Integration & Electrical Circuit Design

## ESP32 to 5V Relay Access Control Module

This document outlines the electrical schematic, component specifications, GPIO assignments, and safety interfacing required to interface the ESP32 microcontroller with a 5V relay module for physical access control (smart door lock simulation).

---

## 1. Pin Assignment Table

| ESP32 DevKit V1 Pin | Pin Type | Connected Device Pin | Function / Description |
|----------------------|----------|----------------------|------------------------|
| **GPIO 22** | Digital Output | Relay Module **IN** | Controls the optocoupler driving the relay coil. Active LOW. |
| **GPIO 0 (BOOT)** | Digital Input (Pull-up) | Tactile Pushbutton / Ground | Manual access request trigger (on-demand authentication). |
| **GPIO 2** | Digital Output | Built-in Blue LED | Visual indicator: High during authentication cycle. |
| **VIN (5V Rail)** | Power Input / 5V Rail | External 5V DC Supply (+) | Supplies 5V to ESP32 onboard regulator and Relay VCC. |
| **GND** | Ground | Relay Module **GND** & Power GND | Common electrical return path for logic and control. |

---

## 2. Electrical Schematic Diagram (ASCII & Functional Representation)

```text
       +5V External DC Power Supply
              │
              ├───► ESP32 VIN (Pin 19)
              │
              └───► Relay Module VCC & JD-VCC (with jumper in place)
                     │
                     ▼
           [ 5V Relay Board Internals ]
           ┌──────────────────────────────────────────────┐
           │                                              │
  VCC ─────┤───[ 1kΩ Resistor ]───( Optocoupler Anode )    │
           │                                              │
   IN ◄────┤──────────────────────( Optocoupler Cathode ) │
  (GPIO22) │                                              │
           │           ( Phototransistor Collector )      │
           │                     │                        │
           │               [ NPN Transistor ]             │
           │                     │                        │
           │            ┌────────┴────────┐               │
           │            │   Relay Coil    │  [1N4007 Diode]
           │            │     (5V DC)     │◄──(Flyback)───┤
           │            └────────┬────────┘               │
           │                     │                        │
  GND ─────┴─────────────────────┴────────────────────────┤
                                                          │
                    ┌────────────┬────────────┐           │
                    │ COM        │ NO         │ NC        │
           └────────┼────────────┼────────────┼───────────┘
                    │            │            │
                    │            │            └── (Unused)
                    │            ▼
                    │    [ 12V Solenoid Smart Door Strike ]
                    │            │
                    │            ▼
                    │       Common Ground
                    ▼
          +12V Auxiliary Supply (+)
```

---

## 3. Safe Electrical Interfacing Principles

### 3.1. Voltage Level Compatibility (3.3V Logic vs 5V Relay Module)
- The ESP32 GPIO operates at **3.3V LVCMOS** logic levels with a maximum current sink/source rating of **12 mA** per pin.
- Most standard hobby relay boards require 5V on their coils ($I_{coil} \approx 70\text{ mA}$), which exceeds the current handling capability of an ESP32 GPIO.
- **Optocoupler Isolation (PC817)**: The relay board contains an onboard PC817 optoisolator and an NPN driver transistor (e.g., S8050). The ESP32 pin only sinks ~3 mA through the internal infrared emitter LED of the optocoupler when pulled LOW.
- **Active LOW Logic**: In the default state, GPIO 22 is driven HIGH (3.3V). The voltage across the optocoupler LED is $5\text{V} - 3.3\text{V} = 1.7\text{V}$, which remains below the LED's forward threshold voltage ($V_f \approx 1.8\text{V}-2.0\text{V}$), keeping the phototransistor turned OFF and the relay de-energized. When GPIO 22 is driven LOW (0V), full forward current flows, turning the relay ON.

### 3.2. Inductive Kickback & Flyback Diode (1N4007)
- The mechanical relay coil possesses significant inductance ($L \approx 100\text{ mH}$).
- When the transistor turns OFF, the magnetic field in the coil collapses rapidly, generating a reverse voltage spike according to Faraday's law:
  $$V_{spike} = -L \frac{di}{dt}$$
  This reverse electromotive force (EMF) can exceed **100V**, which would instantly destroy unprotected silicon transistors.
- A **1N4007 rectifier diode** is placed in parallel across the relay coil in **reverse-bias polarity** (cathode to +5V, anode to transistor collector). When the coil is de-energized, the diode provides a safe dissipation path for the circulating freewheeling current.

### 3.3. Fail-Secure Smart Door Lock Design
- Access control mechanisms are categorized as:
  - **Fail-Safe (Normally Closed)**: Power failure unlocks the door. (Used in emergency fire exits).
  - **Fail-Secure (Normally Open - NO)**: Power failure keeps the door locked. (Used in security barriers and vault access).
- In this implementation, the door strike solenoid is wired through the **Normally Open (NO)** contact:
  - Default State (Relay De-energized): Circuit is OPEN $\rightarrow$ Door is **LOCKED**.
  - Power Loss / Wire Cut: Circuit remains OPEN $\rightarrow$ Door remains **LOCKED**.
  - Verified Authentication: ESP32 energizes relay for **5000 ms** $\rightarrow$ NO contact closes $\rightarrow$ Solenoid pulls back $\rightarrow$ Door is **UNLOCKED**.
  - Auto-Relock: After 5 seconds, relay de-energizes $\rightarrow$ NO contact opens $\rightarrow$ Spring returns bolt $\rightarrow$ Door is **LOCKED**.

---

## 4. Bill of Materials (BOM)

| Item | Component Description | Quantity | Approximate Cost (USD) |
|------|-----------------------|----------|------------------------|
| 1 | ESP32-WROOM-32 DevKit V1 Microcontroller | 1 | $4.50 |
| 2 | 5V 1-Channel Relay Module with Optocoupler Isolation | 1 | $1.20 |
| 3 | 12V DC Solenoid Electric Door Strike Lock | 1 | $8.00 |
| 4 | 1N4007 General-Purpose Rectifier Diode (Flyback) | 1 | $0.10 |
| 5 | AC/DC Dual Output Power Supply (5V 2A / 12V 2A) | 1 | $6.50 |
| 6 | Tactile Pushbutton (Manual Authentication Trigger) | 1 | $0.20 |
| 7 | Breadboard & Jumper Wire Interconnects | 1 Set | $2.50 |
| **Total** | | | **~$23.00** |
