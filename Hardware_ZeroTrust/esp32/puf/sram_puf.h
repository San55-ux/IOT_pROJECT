/**
 * @file sram_puf.h
 * @brief ESP32 SRAM Physical Unclonable Function (PUF) Extraction and Key Derivation
 * 
 * Hardware-Bound Zero-Trust Authentication System
 */

#ifndef SRAM_PUF_H
#define SRAM_PUF_H

#include <stdint.h>
#include <stddef.h>

#define PUF_BUFFER_SIZE_BYTES 128     // 1024 bits of SRAM
#define PUF_BUFFER_SIZE_BITS  (PUF_BUFFER_SIZE_BYTES * 8)
#define MIN_STABLE_BITS_NEEDED 256    // At least 256 stable bits to derive 256-bit key
#define PUF_ENROLLMENT_ROUNDS  11     // Number of power-on reads for majority voting

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t raw_response[PUF_BUFFER_SIZE_BYTES];
    uint8_t helper_data[PUF_BUFFER_SIZE_BYTES]; // Bitmask of stable bits (1=stable, 0=unstable)
    uint16_t stable_bit_count;
    float bit_error_rate;
} puf_profile_t;

/**
 * @brief Initializes and extracts SRAM startup fingerprint.
 * Targets ESP32 RTC Fast Memory (0x3FF80000) or uninitialized memory region.
 */
void sram_puf_init(void);

/**
 * @brief Reads the startup SRAM block into buffer before overwrite.
 * @param buffer Output buffer of at least PUF_BUFFER_SIZE_BYTES
 */
void sram_puf_read_raw(uint8_t* buffer);

/**
 * @brief Enrolls device by performing repeated sampling and majority voting.
 * Generates the stable bitmask (helper data) and reference response.
 */
bool sram_puf_enroll(puf_profile_t* profile);

/**
 * @brief Reconstructs the stabilized PUF response using stored helper data.
 * @param output_key_material 32-byte buffer for derived 256-bit cryptographic secret
 * @param device_id Unique hardware identifier string used as KDF salt
 */
bool sram_puf_derive_secret(uint8_t output_key_material[32], const char* device_id, const uint8_t* helper_data);

/**
 * @brief Converts binary buffer to hex string for network transmission.
 */
void bytes_to_hex(const uint8_t* in, size_t len, char* out);

/**
 * @brief Converts hex string to binary buffer.
 */
bool hex_to_bytes(const char* in, uint8_t* out, size_t len);

#ifdef __cplusplus
}
#endif

#endif // SRAM_PUF_H
