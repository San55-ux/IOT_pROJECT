/**
 * @file esp32_firmware.ino
 * @brief Complete ESP32 Firmware for Hardware-Bound Zero-Trust Authentication
 * 
 * Implements:
 * 1. Hardware ID Extraction (eFuse MAC, Wi-Fi MAC, Chip Model, Revision)
 * 2. SRAM PUF Startup Extraction & Helper Data Filtering
 * 3. Cryptographic Key Derivation (HKDF-SHA256)
 * 4. Schnorr Zero-Knowledge Proof (secp256k1)
 * 5. Wi-Fi Client & REST Communication
 * 6. Physical Relay Actuation (Smart Door Lock Simulation)
 */

#include <Arduino.h>
#include <WiFi.h>
#include <esp_system.h>
#include <esp_spi_flash.h>
#include <esp_mac.h>
#include <esp_chip_info.h>

#include "esp32/puf/sram_puf.h"
#include "esp32/crypto/schnorr.h"
#include "esp32/wifi/wifi_client.h"
#include "esp32/relay/relay_control.h"

// =============================================================================
// Configuration Constants
// =============================================================================
#define WIFI_SSID           "No"
#define WIFI_PASSWORD       "Sanjay12"
#define GATEWAY_SERVER_URL  "http://10.148.225.139:8000"  // Set to Python Gateway Host IP

#define AUTH_TRIGGER_PIN    0      // BOOT button on ESP32 DevKit (GPIO 0)
#define STATUS_LED_PIN      2      // Built-in LED on most ESP32 boards

// Global System State
static char g_device_id[32] = {0};
static char g_efuse_mac_str[20] = {0};
static char g_wifi_mac_str[20] = {0};
static char g_pubkey_hex[70] = {0};
static char g_helper_data_hex[PUF_BUFFER_SIZE_BYTES * 2 + 1] = {0};

static puf_profile_t g_puf_profile;
static schnorr_context_t g_schnorr_ctx;
static bool g_device_enrolled = false;
static unsigned long g_last_auth_millis = 0;
static const unsigned long AUTH_INTERVAL_MS = 60000; // Auto-authenticate every 60s

// =============================================================================
// Hardware ID Extraction
// =============================================================================
void extract_hardware_identity(void) {
    uint8_t mac[6];
    esp_efuse_mac_get_default(mac);
    snprintf(g_efuse_mac_str, sizeof(g_efuse_mac_str),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // Unique non-secret Device ID derived from eFuse
    snprintf(g_device_id, sizeof(g_device_id), "ESP32-%02X%02X%02X",
             mac[3], mac[4], mac[5]);

    // Chip details
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);

    Serial.println("\n========================================================");
    Serial.println("  HARDWARE IDENTIFICATION (PUBLIC NON-SECRET IDENTITY)");
    Serial.println("========================================================");
    Serial.printf("  Device ID    : %s\n", g_device_id);
    Serial.printf("  Chip Model   : ESP32 (Cores: %d, Rev: %d)\n", chip_info.cores, chip_info.revision);
    Serial.printf("  eFuse MAC    : %s\n", g_efuse_mac_str);
    Serial.printf("  Wi-Fi MAC    : %s\n", WiFi.macAddress().c_str());
    Serial.println("  SECURITY NOTICE: MAC address and Device ID are public");
    Serial.println("  identifiers. True zero-trust proof relies on SRAM PUF.");
    Serial.println("========================================================\n");
}

// =============================================================================
// SRAM PUF & Schnorr Key Setup
// =============================================================================
bool setup_puf_and_crypto(void) {
    Serial.println("[PUF] Initializing SRAM PUF Extraction...");
    sram_puf_init();

    // 1. Enroll SRAM PUF and identify stable cells
    Serial.println("[PUF] Evaluating startup bit patterns across samples...");
    if (!sram_puf_enroll(&g_puf_profile)) {
        Serial.printf("[PUF] Enrollment Warning: Insufficient stable bits (%u found)!\n",
                      g_puf_profile.stable_bit_count);
        return false;
    }

    Serial.printf("[PUF] Stable bits identified: %u / %d (Stability: %.2f%%, BER: %.2f%%)\n",
                  g_puf_profile.stable_bit_count, PUF_BUFFER_SIZE_BITS,
                  100.0f - g_puf_profile.bit_error_rate, g_puf_profile.bit_error_rate);

    bytes_to_hex(g_puf_profile.helper_data, PUF_BUFFER_SIZE_BYTES, g_helper_data_hex);

    // 2. Derive 256-bit cryptographic secret x from stabilized PUF response
    uint8_t derived_secret[32];
    if (!sram_puf_derive_secret(derived_secret, g_device_id, g_puf_profile.helper_data)) {
        Serial.println("[PUF] Failed to derive cryptographic secret!");
        return false;
    }
    Serial.println("[Crypto] 256-bit Private Secret derived via HKDF-SHA256.");
    Serial.println("[Crypto] CONFIDENTIALITY: Secret x never leaves ESP32 SRAM.");

    // 3. Initialize Schnorr Cryptographic Context & Public Key Y = x * G
    if (!schnorr_init(&g_schnorr_ctx)) {
        Serial.println("[Crypto] Failed to initialize secp256k1 group!");
        return false;
    }

    if (!schnorr_derive_public_key(&g_schnorr_ctx, derived_secret)) {
        Serial.println("[Crypto] Failed to derive Schnorr public key Y!");
        return false;
    }

    bytes_to_hex(g_schnorr_ctx.public_key, SCHNORR_PUBKEY_COMPRESSED_BYTES, g_pubkey_hex);
    Serial.printf("[Crypto] Schnorr Public Key Y: %s\n", g_pubkey_hex);

    // Wipe temporary raw key material from stack
    memset(derived_secret, 0, sizeof(derived_secret));
    return true;
}

// =============================================================================
// Gateway Registration
// =============================================================================
bool register_with_gateway(void) {
    Serial.println("[Gateway] Registering device with Zero-Trust Gateway...");
    char json_payload[1024];
    snprintf(json_payload, sizeof(json_payload),
             "{\"device_id\":\"%s\",\"mac_address\":\"%s\",\"chip_model\":\"ESP32\",\"chip_revision\":1,\"public_key\":\"%s\",\"helper_data\":\"%s\"}",
             g_device_id, g_efuse_mac_str, g_pubkey_hex, g_helper_data_hex);

    char response[512] = {0};
    int http_code = 0;
    bool ok = gateway_post_json("/api/device/register", json_payload, response, sizeof(response), &http_code);

    if (ok && http_code == 200) {
        Serial.println("[Gateway] Registration successful! Trust Status: UNTRUSTED (Pending Proof)");
        g_device_enrolled = true;
        return true;
    } else {
        Serial.printf("[Gateway] Registration failed! HTTP %d, Response: %s\n", http_code, response);
        return false;
    }
}

// =============================================================================
// Interactive Schnorr Zero-Knowledge Proof Authentication
// =============================================================================
bool perform_schnorr_authentication(void) {
    digitalWrite(STATUS_LED_PIN, HIGH);
    Serial.println("\n--------------------------------------------------------");
    Serial.println(">>> INITIATING ZERO-TRUST SCHNORR IDENTIFICATION <<<");
    Serial.println("--------------------------------------------------------");

    unsigned long start_ms = millis();

    // STEP 1: Generate Ephemeral Nonce k and Commitment R = k * G
    char commitment_hex[70] = {0};
    if (!schnorr_generate_commitment(&g_schnorr_ctx, commitment_hex)) {
        Serial.println("[ZKP] Error: Failed to generate Schnorr commitment R!");
        digitalWrite(STATUS_LED_PIN, LOW);
        return false;
    }
    Serial.printf("[ZKP] 1. Commitment R: %s\n", commitment_hex);

    // Send Commitment to Gateway to obtain fresh Challenge c
    char challenge_req[256];
    snprintf(challenge_req, sizeof(challenge_req),
             "{\"device_id\":\"%s\",\"commitment\":\"%s\"}",
             g_device_id, commitment_hex);

    char challenge_resp[512] = {0};
    int http_code = 0;
    if (!gateway_post_json("/api/auth/challenge", challenge_req, challenge_resp, sizeof(challenge_resp), &http_code)) {
        Serial.printf("[ZKP] Challenge request failed (HTTP %d)\n", http_code);
        digitalWrite(STATUS_LED_PIN, LOW);
        return false;
    }

    // Parse session_id and challenge c
    // Simple JSON extraction to minimize overhead
    char session_id[40] = {0};
    char challenge_hex[70] = {0};

    char* sess_ptr = strstr(challenge_resp, "\"session_id\":\"");
    if (sess_ptr) {
        sess_ptr += 14;
        char* end_ptr = strchr(sess_ptr, '\"');
        if (end_ptr) {
            size_t len = end_ptr - sess_ptr;
            strncpy(session_id, sess_ptr, len);
            session_id[len] = '\0';
        }
    }

    char* chal_ptr = strstr(challenge_resp, "\"challenge\":\"");
    if (chal_ptr) {
        chal_ptr += 13;
        char* end_ptr = strchr(chal_ptr, '\"');
        if (end_ptr) {
            size_t len = end_ptr - chal_ptr;
            strncpy(challenge_hex, chal_ptr, len);
            challenge_hex[len] = '\0';
        }
    }

    if (strlen(session_id) == 0 || strlen(challenge_hex) == 0) {
        Serial.println("[ZKP] Failed to parse Gateway challenge response!");
        digitalWrite(STATUS_LED_PIN, LOW);
        return false;
    }

    Serial.printf("[ZKP] 2. Gateway Challenge c: %s\n", challenge_hex);
    Serial.printf("[ZKP]    Session ID: %s\n", session_id);

    // STEP 2: Compute Response s = (k + c * x) mod q
    char response_hex[70] = {0};
    if (!schnorr_compute_response(&g_schnorr_ctx, challenge_hex, response_hex)) {
        Serial.println("[ZKP] Error: Failed to compute Schnorr response s!");
        digitalWrite(STATUS_LED_PIN, LOW);
        return false;
    }
    Serial.printf("[ZKP] 3. Response s: %s\n", response_hex);

    // STEP 3: Submit Response to Gateway for Verification
    char verify_req[384];
    snprintf(verify_req, sizeof(verify_req),
             "{\"session_id\":\"%s\",\"device_id\":\"%s\",\"response\":\"%s\"}",
             session_id, g_device_id, response_hex);

    char verify_resp[512] = {0};
    bool ok = gateway_post_json("/api/auth/verify", verify_req, verify_resp, sizeof(verify_resp), &http_code);

    unsigned long elapsed_ms = millis() - start_ms;

    if (ok && http_code == 200 && strstr(verify_resp, "\"authenticated\":true")) {
        Serial.println("\n[RESULT] **********************************************");
        Serial.println("[RESULT] >>> AUTHENTICATION GRANTED! DEVICE TRUSTED <<<");
        Serial.printf("[RESULT] Total Round-Trip Latency: %lu ms\n", elapsed_ms);
        Serial.println("[RESULT] **********************************************\n");

        // Actuate Relay to Unlock Smart Door Lock
        relay_unlock_timed(DEFAULT_UNLOCK_TIME_MS);
        digitalWrite(STATUS_LED_PIN, LOW);
        return true;
    } else {
        Serial.println("\n[RESULT] XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        Serial.println("[RESULT] >>> AUTHENTICATION DENIED! DEVICE UNTRUSTED <<<");
        Serial.printf("[RESULT] Gateway Response: %s\n", verify_resp);
        Serial.println("[RESULT] XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");

        relay_lock();
        digitalWrite(STATUS_LED_PIN, LOW);
        return false;
    }
}

// =============================================================================
// Arduino Setup & Main Loop
// =============================================================================
void setup(void) {
    Serial.begin(115200);
    delay(1000);

    pinMode(AUTH_TRIGGER_PIN, INPUT_PULLUP);
    pinMode(STATUS_LED_PIN, OUTPUT);
    digitalWrite(STATUS_LED_PIN, LOW);

    // 1. Initialize Relay in Fail-Secure Locked State
    relay_init(DEFAULT_RELAY_GPIO);

    // 2. Extract Hardware Identity
    extract_hardware_identity();

    // 3. Extract SRAM PUF and initialize Schnorr Crypto
    if (!setup_puf_and_crypto()) {
        Serial.println("[CRITICAL] Hardware PUF extraction failed. Halting.");
        while (1) { delay(1000); }
    }

    // 4. Connect to Wi-Fi
    network_config_t net_cfg = {
        .ssid = WIFI_SSID,
        .password = WIFI_PASSWORD,
        .gateway_base_url = GATEWAY_SERVER_URL
    };
    if (wifi_network_init(&net_cfg)) {
        // 5. Register with Zero-Trust Gateway
        register_with_gateway();
        // Perform initial authentication
        perform_schnorr_authentication();
    } else {
        Serial.println("[Wi-Fi] Running in offline mode. Press BOOT to re-try.");
    }

    g_last_auth_millis = millis();
}

void loop(void) {
    // Service relay auto-relock timer
    relay_update();

    // Check physical BOOT button for on-demand access request
    if (digitalRead(AUTH_TRIGGER_PIN) == LOW) {
        delay(50); // Debounce
        if (digitalRead(AUTH_TRIGGER_PIN) == LOW) {
            Serial.println("\n[Button] Access request triggered by physical user button.");
            perform_schnorr_authentication();
            while (digitalRead(AUTH_TRIGGER_PIN) == LOW) {
                delay(10);
            }
        }
    }

    // Periodic automatic Zero-Trust re-authentication
    if (millis() - g_last_auth_millis >= AUTH_INTERVAL_MS) {
        g_last_auth_millis = millis();
        if (wifi_network_is_connected()) {
            Serial.println("\n[Timer] Executing periodic Zero-Trust re-authentication...");
            perform_schnorr_authentication();
        }
    }

    delay(20);
}
