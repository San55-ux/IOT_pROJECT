/**
 * @file schnorr.cpp
 * @brief Embedded Implementation of Schnorr Identification Protocol using mbedtls
 */

#include "schnorr.h"
#include <Arduino.h>
#include <string.h>
#include <esp_system.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

static mbedtls_ecp_group ecp_grp;
static bool ecp_initialized = false;

// Hardware TRNG entropy feeder for ESP32
static int esp32_trng_random(void* ctx, unsigned char* output, size_t len) {
    (void)ctx;
    esp_fill_random(output, len);
    return 0;
}

bool schnorr_init(schnorr_context_t* ctx) {
    if (!ctx) return false;
    memset(ctx, 0, sizeof(schnorr_context_t));

    if (!ecp_initialized) {
        mbedtls_ecp_group_init(&ecp_grp);
        int ret = mbedtls_ecp_group_load(&ecp_grp, MBEDTLS_ECP_DP_SECP256K1);
        if (ret != 0) {
            return false;
        }
        ecp_initialized = true;
    }
    return true;
}

bool schnorr_derive_public_key(schnorr_context_t* ctx, const uint8_t secret[32]) {
    if (!ctx || !secret || !ecp_initialized) return false;

    memcpy(ctx->private_secret, secret, 32);

    mbedtls_mpi x;
    mbedtls_ecp_point Y;
    size_t olen = 0;
    mbedtls_mpi_init(&x);
    mbedtls_ecp_point_init(&Y);

    int ret = mbedtls_mpi_read_binary(&x, secret, 32);
    if (ret != 0) goto cleanup;

    // Y = x * G
    ret = mbedtls_ecp_mul(&ecp_grp, &Y, &x, &ecp_grp.G, esp32_trng_random, NULL);
    if (ret != 0) goto cleanup;

    // Serialize compressed point (33 bytes)
    ret = mbedtls_ecp_point_write_binary(&ecp_grp, &Y, MBEDTLS_ECP_PF_COMPRESSED, &olen, ctx->public_key, SCHNORR_PUBKEY_COMPRESSED_BYTES);
    if (ret != 0 || olen != SCHNORR_PUBKEY_COMPRESSED_BYTES) goto cleanup;

    mbedtls_mpi_free(&x);
    mbedtls_ecp_point_free(&Y);
    return true;

cleanup:
    mbedtls_mpi_free(&x);
    mbedtls_ecp_point_free(&Y);
    return false;
}

bool schnorr_generate_commitment(schnorr_context_t* ctx, char* commitment_hex_out) {
    if (!ctx || !commitment_hex_out || !ecp_initialized) return false;

    mbedtls_mpi k;
    mbedtls_ecp_point R;
    size_t olen = 0;
    mbedtls_mpi_init(&k);
    mbedtls_ecp_point_init(&R);

    // Generate random ephemeral nonce k in [1, q-1] using hardware TRNG
    int ret = mbedtls_ecp_gen_privkey(&ecp_grp, &k, esp32_trng_random, NULL);
    if (ret != 0) goto cleanup;

    // Export k to context
    ret = mbedtls_mpi_write_binary(&k, ctx->ephemeral_nonce, 32);
    if (ret != 0) goto cleanup;

    // Compute commitment R = k * G
    ret = mbedtls_ecp_mul(&ecp_grp, &R, &k, &ecp_grp.G, esp32_trng_random, NULL);
    if (ret != 0) goto cleanup;

    // Serialize compressed point R
    ret = mbedtls_ecp_point_write_binary(&ecp_grp, &R, MBEDTLS_ECP_PF_COMPRESSED, &olen, ctx->commitment, SCHNORR_PUBKEY_COMPRESSED_BYTES);
    if (ret != 0 || olen != SCHNORR_PUBKEY_COMPRESSED_BYTES) goto cleanup;

    // Format as hex string
    for (size_t i = 0; i < SCHNORR_PUBKEY_COMPRESSED_BYTES; i++) {
        sprintf(commitment_hex_out + (i * 2), "%02x", ctx->commitment[i]);
    }
    commitment_hex_out[SCHNORR_PUBKEY_COMPRESSED_BYTES * 2] = '\0';

    mbedtls_mpi_free(&k);
    mbedtls_ecp_point_free(&R);
    return true;

cleanup:
    mbedtls_mpi_free(&k);
    mbedtls_ecp_point_free(&R);
    return false;
}

bool schnorr_compute_response(schnorr_context_t* ctx, const char* challenge_hex, char* response_hex_out) {
    if (!ctx || !challenge_hex || !response_hex_out || !ecp_initialized) return false;

    mbedtls_mpi k, x, c, s, cx, sum;
    mbedtls_mpi_init(&k);
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&c);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&cx);
    mbedtls_mpi_init(&sum);

    // Load k, x, c
    int ret = mbedtls_mpi_read_binary(&k, ctx->ephemeral_nonce, 32);
    if (ret != 0) goto cleanup;

    ret = mbedtls_mpi_read_binary(&x, ctx->private_secret, 32);
    if (ret != 0) goto cleanup;

    ret = mbedtls_mpi_read_string(&c, 16, challenge_hex);
    if (ret != 0) goto cleanup;

    // s = (k + c * x) mod q
    ret = mbedtls_mpi_mul_mpi(&cx, &c, &x);
    if (ret != 0) goto cleanup;

    ret = mbedtls_mpi_add_mpi(&sum, &k, &cx);
    if (ret != 0) goto cleanup;

    ret = mbedtls_mpi_mod_mpi(&s, &sum, &ecp_grp.N);
    if (ret != 0) goto cleanup;

    // Export s to binary and hex
    uint8_t s_bytes[32];
    ret = mbedtls_mpi_write_binary(&s, s_bytes, 32);
    if (ret != 0) goto cleanup;

    for (int i = 0; i < 32; i++) {
        sprintf(response_hex_out + (i * 2), "%02x", s_bytes[i]);
    }
    response_hex_out[64] = '\0';

    // SECURE PURGE: Ephemeral nonce k must never be reused or retained
    memset(ctx->ephemeral_nonce, 0, 32);
    mbedtls_mpi_free(&k);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&c);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&cx);
    mbedtls_mpi_free(&sum);
    return true;

cleanup:
    memset(ctx->ephemeral_nonce, 0, 32);
    mbedtls_mpi_free(&k);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&c);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&cx);
    mbedtls_mpi_free(&sum);
    return false;
}

void schnorr_cleanup(schnorr_context_t* ctx) {
    if (ctx) {
        memset(ctx->ephemeral_nonce, 0, sizeof(ctx->ephemeral_nonce));
        // Private secret is kept in SRAM for session duration or purged when powered down
    }
}
