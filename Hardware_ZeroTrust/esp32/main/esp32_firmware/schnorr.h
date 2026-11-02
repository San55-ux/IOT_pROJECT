/**
 * @file schnorr.h
 * @brief Schnorr Identification / Zero-Knowledge Proof Cryptographic Module for ESP32
 * 
 * Hardware-Bound Zero-Trust Authentication System
 */

#ifndef SCHNORR_H
#define SCHNORR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCHNORR_KEY_SIZE_BYTES 32
#define SCHNORR_PUBKEY_COMPRESSED_BYTES 33

typedef struct {
    uint8_t private_secret[SCHNORR_KEY_SIZE_BYTES];     // Secret x derived from PUF
    uint8_t public_key[SCHNORR_PUBKEY_COMPRESSED_BYTES]; // Public key Y = x * G (compressed)
    uint8_t ephemeral_nonce[SCHNORR_KEY_SIZE_BYTES];     // Random nonce k
    uint8_t commitment[SCHNORR_PUBKEY_COMPRESSED_BYTES]; // Commitment R = k * G
} schnorr_context_t;

/**
 * @brief Initializes elliptic curve group (secp256k1) and cryptographic context.
 */
bool schnorr_init(schnorr_context_t* ctx);

/**
 * @brief Derives public key Y = x * G from private secret x.
 */
bool schnorr_derive_public_key(schnorr_context_t* ctx, const uint8_t secret[32]);

/**
 * @brief Generates ephemeral random nonce k and commitment R = k * G.
 * Nonce k is generated using ESP32 True Random Number Generator (TRNG).
 */
bool schnorr_generate_commitment(schnorr_context_t* ctx, char* commitment_hex_out);

/**
 * @brief Computes Schnorr response s = (k + c * x) mod q given challenge c.
 * @param challenge_hex 64-character hex string of challenge scalar c from Gateway
 * @param response_hex_out 65-character buffer to receive response s in hex
 */
bool schnorr_compute_response(schnorr_context_t* ctx, const char* challenge_hex, char* response_hex_out);

/**
 * @brief Cleans up and securely wipes ephemeral sensitive state from memory.
 */
void schnorr_cleanup(schnorr_context_t* ctx);

#ifdef __cplusplus
}
#endif

#endif // SCHNORR_H
