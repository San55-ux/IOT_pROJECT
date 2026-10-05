/**
 * @file sram_puf.cpp
 * @brief Implementation of SRAM PUF Acquisition, Filtering & Key Derivation for ESP32
 */

#include "sram_puf.h"
#include <Arduino.h>
#include <string.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>

/**
 * TECHNICAL REALITY NOTE ON ESP32 SRAM:
 * Standard ESP32 DRAM (.bss and heap) is wiped to 0x00 or 0xCE by the second-stage bootloader.
 * However, the RTC Fast Memory region (0x3FF80000 - 0x3FF81FFF, 8KB) is not zeroed by the
 * standard bootloader when tagged with RTC_NOINIT_ATTR. We therefore bind our PUF sampling
 * to this specific physical region for authentic startup hardware behavior.
 */

// Designated 128-byte uninitialized RTC SRAM region
RTC_NOINIT_ATTR static uint8_t sram_sample_region[PUF_BUFFER_SIZE_BYTES];

void sram_puf_init(void) {
    // If memory is completely uninitialized at initial flashing,
    // ensure pointers and peripheral clocks are ready.
}

void sram_puf_read_raw(uint8_t* buffer) {
    if (!buffer) return;
    
    // Copy directly from RTC Fast SRAM segment
    const volatile uint8_t* rtc_ptr = (const volatile uint8_t*)sram_sample_region;
    for (size_t i = 0; i < PUF_BUFFER_SIZE_BYTES; i++) {
        buffer[i] = rtc_ptr[i];
    }
}

bool sram_puf_enroll(puf_profile_t* profile) {
    if (!profile) return false;

    // Simulate/sample across enrollment cycles
    // In laboratory testing, this is sampled across multiple power cycles.
    uint8_t samples[PUF_ENROLLMENT_ROUNDS][PUF_BUFFER_SIZE_BYTES];

    // First read directly from power-on RTC state
    sram_puf_read_raw(samples[0]);

    // For demonstration and initial enrollment testing without requiring 11 physical power-cycles:
    // Generate realistic Gaussian noise perturbations on unstable bits (~4% flip rate)
    for (int r = 1; r < PUF_ENROLLMENT_ROUNDS; r++) {
        for (int i = 0; i < PUF_BUFFER_SIZE_BYTES; i++) {
            samples[r][i] = samples[0][i];
            // Simulate 4% metastable bit flips in unshielded SRAM cells
            for (int b = 0; b < 8; b++) {
                if ((random(100) < 4)) {
                    samples[r][i] ^= (1 << b);
                }
            }
        }
    }

    // Initialize helper data and reference response
    memset(profile->helper_data, 0, PUF_BUFFER_SIZE_BYTES);
    memset(profile->raw_response, 0, PUF_BUFFER_SIZE_BYTES);
    profile->stable_bit_count = 0;

    int total_flips = 0;

    // Majority voting across all rounds
    for (int byte_idx = 0; byte_idx < PUF_BUFFER_SIZE_BYTES; byte_idx++) {
        for (int bit_idx = 0; bit_idx < 8; bit_idx++) {
            int ones_count = 0;
            for (int r = 0; r < PUF_ENROLLMENT_ROUNDS; r++) {
                if (samples[r][byte_idx] & (1 << bit_idx)) {
                    ones_count++;
                }
            }

            // Unanimous agreement indicates a stable physical PUF cell
            if (ones_count == 0) {
                // Stable 0
                profile->helper_data[byte_idx] |= (1 << bit_idx);
                // raw_response bit remains 0
                profile->stable_bit_count++;
            } else if (ones_count == PUF_ENROLLMENT_ROUNDS) {
                // Stable 1
                profile->helper_data[byte_idx] |= (1 << bit_idx);
                profile->raw_response[byte_idx] |= (1 << bit_idx);
                profile->stable_bit_count++;
            } else {
                // Metastable bit - discarded by leaving helper_data bit 0
                total_flips += (ones_count < (PUF_ENROLLMENT_ROUNDS - ones_count)) ? 
                               ones_count : (PUF_ENROLLMENT_ROUNDS - ones_count);
            }
        }
    }

    profile->bit_error_rate = ((float)total_flips / (PUF_BUFFER_SIZE_BITS * PUF_ENROLLMENT_ROUNDS)) * 100.0f;

    return (profile->stable_bit_count >= MIN_STABLE_BITS_NEEDED);
}

bool sram_puf_derive_secret(uint8_t output_key_material[32], const char* device_id, const uint8_t* helper_data) {
    if (!output_key_material || !device_id || !helper_data) return false;

    // 1. Read current power-up SRAM state
    uint8_t current_read[PUF_BUFFER_SIZE_BYTES];
    sram_puf_read_raw(current_read);

    // 2. Filter using Helper Data (extract only stable bits)
    uint8_t stabilized_bits[PUF_BUFFER_SIZE_BYTES];
    memset(stabilized_bits, 0, PUF_BUFFER_SIZE_BYTES);

    for (int i = 0; i < PUF_BUFFER_SIZE_BYTES; i++) {
        stabilized_bits[i] = current_read[i] & helper_data[i];
    }

    // 3. Cryptographic Key Derivation using HKDF-SHA256
    // HKDF-Extract: PRK = HMAC-SHA256(Salt=DeviceID, IKM=Stabilized_PUF_Bits)
    // HKDF-Expand:  OKM = HMAC-SHA256(PRK, Info="ESP32-PUF-SCHNORR-V1" || 0x01)
    
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    uint8_t prk[32];
    mbedtls_md_hmac_starts(&md_ctx, (const unsigned char*)device_id, strlen(device_id));
    mbedtls_md_hmac_update(&md_ctx, stabilized_bits, PUF_BUFFER_SIZE_BYTES);
    mbedtls_md_hmac_finish(&md_ctx, prk);

    const char* info = "ESP32-PUF-SCHNORR-V1";
    uint8_t info_with_counter[32];
    size_t info_len = strlen(info);
    memcpy(info_with_counter, info, info_len);
    info_with_counter[info_len] = 0x01;

    mbedtls_md_hmac_starts(&md_ctx, prk, 32);
    mbedtls_md_hmac_update(&md_ctx, info_with_counter, info_len + 1);
    mbedtls_md_hmac_finish(&md_ctx, output_key_material);

    mbedtls_md_free(&md_ctx);

    // Ensure secret is not all zeros
    bool non_zero = false;
    for (int i = 0; i < 32; i++) {
        if (output_key_material[i] != 0) {
            non_zero = true;
            break;
        }
    }
    if (!non_zero) output_key_material[31] = 0x01;

    return true;
}

void bytes_to_hex(const uint8_t* in, size_t len, char* out) {
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hex_chars[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex_chars[in[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

bool hex_to_bytes(const char* in, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char c1 = in[i * 2];
        char c2 = in[i * 2 + 1];
        if (c1 == '\0' || c2 == '\0') return false;

        uint8_t byte = 0;
        if (c1 >= '0' && c1 <= '9') byte = (c1 - '0') << 4;
        else if (c1 >= 'a' && c1 <= 'f') byte = (c1 - 'a' + 10) << 4;
        else if (c1 >= 'A' && c1 <= 'F') byte = (c1 - 'A' + 10) << 4;
        else return false;

        if (c2 >= '0' && c2 <= '9') byte |= (c2 - '0');
        else if (c2 >= 'a' && c2 <= 'f') byte |= (c2 - 'a' + 10);
        else if (c2 >= 'A' && c2 <= 'F') byte |= (c2 - 'A' + 10);
        else return false;

        out[i] = byte;
    }
    return true;
}
