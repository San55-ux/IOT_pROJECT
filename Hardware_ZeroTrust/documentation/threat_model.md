# Security Threat Model and Vulnerability Analysis

## Hardware-Bound Zero-Trust Authentication System Using ESP32 SRAM PUF & Schnorr ZKP

This document presents a rigorous threat model evaluating the prototype against 15 key cybersecurity attack vectors. In accordance with academic honesty, the system acknowledges the physical and architectural limitations inherent to low-cost commodity microcontrollers (ESP32) and explains where theoretical guarantees transition into prototype engineering constraints.

---

## 1. Security Analysis Matrix

| # | Threat Vector | Attack Method | System Protection Status | Protection Mechanism | Remaining Limitations |
|---|---------------|---------------|--------------------------|----------------------|-----------------------|
| **1** | **Physical Key Extraction** | Adversary reads flash memory chips (SPI flash dumping) or executes JTAG/SWD debug dumps to extract persistent private keys. | **Protected** | Authentication secret $x$ is **never stored in non-volatile flash or EEPROM**. It is dynamically derived from volatile SRAM startup behavior on boot and resides solely in transient RAM during operation. | If device remains powered continuously in deep sleep with RAM retention, a cold-boot physical memory probing or cryo-memory readout could theoretically sample decaying SRAM contents. |
| **2** | **Device Cloning** | Adversary flashes identical firmware binary image onto a second ESP32 microcontroller to impersonate the legitimate node. | **Protected** | The derived authentication secret $x$ depends on the unique sub-micron physical threshold voltage mismatch ($\Delta V_{th}$) of the specific silicon die. A cloned firmware on a second ESP32 extracts a radically different PUF response (Inter-HD $\approx 49.8\%$), yielding a different private key that fails Schnorr verification. | If an adversary physically copies the entire silicon die via integrated circuit reverse engineering (destructive micro-probing), they could recreate the transistor geometries. |
| **3** | **MAC Address Spoofing** | Adversary modifies their network adapter Wi-Fi MAC to mimic the legitimate ESP32 eFuse MAC address. | **Protected** | Under the Zero-Trust architecture, **the MAC address is explicitly treated as a public identifier, never a cryptographic secret**. Spoofing the MAC allows requesting a challenge, but the attacker cannot generate a valid Schnorr response $s$ without knowing $x$. | Spoofed requests consume network bandwidth and gateway challenge resources, which must be rate-limited by IP/MAC firewall rules. |
| **4** | **Credential Sniffing** | Adversary captures all Wi-Fi packets between the ESP32 and Gateway using promiscuous mode packet sniffers (e.g. Wireshark). | **Protected** | The Schnorr Zero-Knowledge Proof protocol ensures that the prover conveys **zero bits of the secret $x$** to the verifier or network observers. Transmission consists only of $(R, c, s)$, which are computationally indistinguishable from uniform random group elements. | Passive sniffing reveals traffic volume, authentication frequency, and device identifiers (metadata). |
| **5** | **Replay Attacks** | Adversary intercepts a previously successful authentication sequence $(R_1, c_1, s_1)$ and transmits it again to unlock the smart door. | **Protected** | The Gateway issues a **cryptographically fresh, single-use 256-bit challenge $c$** with a 30-second TTL. Every session token is atomically marked `used = 1` immediately upon the first evaluation. Replayed session tokens are rejected, logged, and trigger a critical dashboard alert. | An attacker replaying a captured payload within milliseconds of transmission could trigger a race condition if database transactions were non-atomic (mitigated here via SQLite row locks). |
| **6** | **Man-in-the-Middle (MITM)** | Adversary intercepts communication in transit and attempts to substitute their own public key or redirect traffic. | **Mitigated** | Public keys $Y$ are registered during enrollment and bound to the Device ID. During verification, Gateway validates $s \cdot G == R + c \cdot Y$ using the **locally stored registered public key**, rendering MITM key substitution ineffective. | In plain HTTP over unencrypted Wi-Fi, an active MITM can alter gateway return commands (e.g. telling the ESP32 not to unlock). Transport Layer Security (TLS 1.3 / HTTPS) must be enabled in production. |
| **7** | **Unauthorized Device Access** | An unknown, unregistered ESP32 sends authentication requests to the Gateway. | **Protected** | Gateway enforces **Deny-by-Default (Zero-Trust baseline)**. Unregistered device IDs are immediately rejected at the challenge endpoint (`HTTP 400`), logged as unauthorized access, and raise a security alert. | If an adversary guesses or sniffs a registered Device ID, they can obtain a challenge, but cannot solve the Schnorr response. |
| **8** | **Modified Authentication Payload** | Adversary flips bits in the commitment $R$ or response $s$ while packets traverse the network. | **Protected** | Any bit modification in $s$, $R$, or $c$ violates the elliptic curve equation $s \cdot G == R + c \cdot Y$. Because discrete logarithm computation is intractable in secp256k1, forging an offsetting modification is computationally infeasible ($2^{128}$ security level). | Repeated corrupted payloads consume verifier CPU cycles for point multiplication until rate-limiting engages. |
| **9** | **Invalid Schnorr Proof** | A rogue device generates arbitrary scalar responses or uses an incorrect private secret. | **Protected** | Evaluated via point multiplication. Left-hand side $s \cdot G$ will not match right-hand side $R + c \cdot Y$. The gateway rejects access, sets device trust status to `UNTRUSTED`, and keeps the relay locked. | None. Soundness property of Schnorr protocol ensures cheating probability is bounded by $1/q \approx 2^{-256}$. |
| **10** | **Challenge Reuse** | A compromised or malfunctioning verifier attempts to reuse an old challenge $c$ with the same commitment $R$. | **Protected** | The ESP32 prover generates an ephemeral nonce $k$ for every attempt and securely wipes $k$ from memory immediately after computing $s$. Prover rejects repeated challenges for the same ephemeral session. | Firmware must ensure the hardware TRNG does not fail silently (e.g. checking entropy health status). |
| **11** | **Weak Random Nonce** | Predictable or biased generation of ephemeral nonce $k$, leading to secret key recovery: $x = (s_1 - s_2) / (c_1 - c_2) \pmod q$. | **Protected** | Nonce $k$ is sampled using the **ESP32 Hardware True Random Number Generator (TRNG)**, which harvests thermal noise from Wi-Fi and Bluetooth RF circuitry (`esp_fill_random()`). In the Python test simulator, `secrets.randbelow()` (CSPRNG) is used. | If ESP32 RF peripherals are unpowered or uncalibrated during early boot, TRNG entropy could be degraded without adequate delay/seeding. |
| **12** | **SRAM PUF Instability** | Thermal fluctuations, aging, and power supply ramp variations cause random bit flips in startup SRAM cells, preventing key reconstruction. | **Protected** | Implements **Majority Voting enrollment** over $N=11$ reads to generate **Helper Data (stable bitmask)**. Only cells with 100% agreement across all rounds are retained for key derivation. Noisy/metastable bits are masked out. | Helper data generation requires a stable enrollment phase under nominal room temperature. Under extreme temperature extremes (-20°C to +80°C), additional error correction codes (e.g., BCH or Repetition Code) are required. |
| **13** | **Firmware Compromise** | Adversary exploits buffer overflow in third-party library to inject malicious shellcode into ESP32 application memory. | **Partially Protected** | Private key $x$ is held in memory only during key derivation and response computation. However, an in-memory runtime exploit could theoretically read the memory segment if executed during an active session. | Firmware integrity must be secured using ESP32 Hardware Secure Boot v2 and Flash Encryption in production hardware. |
| **14** | **Side-Channel Attacks** | Adversary measures power consumption variations (DPA) or electromagnetic emanations (EMA) during scalar multiplication $s = (k + c \cdot x) \pmod q$. | **Partially Protected** | Scalar multiplication on ESP32 is performed via `mbedtls` which incorporates basic blinding. Furthermore, the private key is not used directly in repeated point multiplications against known inputs. | Standard ESP32 lacks the dedicated side-channel countermeasures found in high-grade Secure Elements (e.g. ATECC608A or smartcard chips). |
| **15** | **Physical Invasive Attacks** | Adversary decapsulates the ESP32 chip package using acid and uses Focused Ion Beam (FIB) or Scanning Electron Microscopy (SEM) to inspect silicon traces. | **Limitation of Prototype** | SRAM PUF cells are erased when powered down. However, advanced semiconductor lab attacks using micro-probing needles on active buses are outside the defensive perimeter of a standard $4 ESP32 module. | High-security applications requiring anti-tamper envelopes and active mesh shields must integrate dedicated Common Criteria EAL6+ secure hardware. |

---

## 2. Deep Dive: Replay Attack Defense Mechanism

The replay vulnerability is one of the most pervasive weaknesses in conventional IoT authentication schemes.

### Mathematical & State Sequence:
1. **Initial Legitimate Transaction**:
   - ESP32 commits: $R_1 = k_1 \cdot G$.
   - Gateway generates session $S_1$ with unique challenge $c_1 \in_R \mathbb{Z}_q^*$, timestamps it, and sets $used = 0$.
   - ESP32 calculates $s_1 = (k_1 + c_1 \cdot x) \pmod q$.
   - Gateway receives $(S_1, s_1)$, checks $used == 0$, immediately updates $used := 1$, and checks $s_1 \cdot G \stackrel{?}{=} R_1 + c_1 \cdot Y$. Equality holds $\rightarrow$ Access Granted.
2. **Adversary Replay Attempt**:
   - Adversary replays $(S_1, s_1)$.
   - Gateway looks up $S_1$, detects $used == 1$.
   - Gateway immediately halts processing, flags **`REPLAY_ATTACK_DETECTED` (Severity: CRITICAL)**, locks the physical relay, and pushes an alert to the security dashboard.
3. **Alternative Adversary Replay (New Session, Old Response)**:
   - If adversary initiates a new session $S_2$ to receive a new challenge $c_2$, and attempts to reuse the previous response $s_1$:
     $$s_1 \cdot G = R_1 + c_1 \cdot Y \neq R_1 + c_2 \cdot Y \quad (\text{since } c_1 \neq c_2)$$
   - Verification fails mathematically on the elliptic curve with overwhelming probability $1 - 2^{-256}$.

---

## 3. Engineering Realities & Honest Limitations

1. **ESP32 Bootloader Memory Clearing**:
   As acknowledged in Section 5 of the design specification, the ESP32 second-stage bootloader clears standard internal DRAM (`.bss` section and heap). Therefore, authentic SRAM PUF startup behavior must be captured from the **RTC Fast Memory (0x3FF80000)** segment configured with the `RTC_NOINIT_ATTR` attribute, or sampled before the bootloader zeroing routine executes.
2. **Helper Data Leakage**:
   The helper data bitmask specifies *which* bits are stable, but discloses **zero information regarding the binary state** ('0' or '1') of those bits. Hence, helper data can be publicly stored or transmitted to the gateway without compromising zero-knowledge confidentiality.
3. **No Direct Secret Storage**:
   Unlike legacy IoT architectures that store an AES or private RSA key in SPI flash (which can be read out in under 60 seconds with an inexpensive flash programmer clip), this design re-synthesizes the private key dynamically on each power ramp from intrinsic manufacturing variations.
