/**
 * @file wifi_client.h
 * @brief Wi-Fi Network & HTTP REST Client for Zero-Trust Gateway Communication
 */

#ifndef WIFI_CLIENT_H
#define WIFI_CLIENT_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* ssid;
    const char* password;
    const char* gateway_base_url; // e.g., "http://192.168.1.100:8000"
} network_config_t;

/**
 * @brief Connects to Wi-Fi access point.
 */
bool wifi_network_init(const network_config_t* config);

/**
 * @brief Checks if Wi-Fi is actively connected.
 */
bool wifi_network_is_connected(void);

/**
 * @brief Sends an HTTP POST request with JSON payload to the Gateway.
 * @param endpoint Relative URL path (e.g., "/api/auth/challenge")
 * @param json_payload JSON request string
 * @param response_buffer Buffer to receive response string
 * @param buffer_len Maximum capacity of response_buffer
 * @param http_code_out Pointer to receive HTTP response status code
 */
bool gateway_post_json(
    const char* endpoint,
    const char* json_payload,
    char* response_buffer,
    size_t buffer_len,
    int* http_code_out
);

#ifdef __cplusplus
}
#endif

#endif // WIFI_CLIENT_H
