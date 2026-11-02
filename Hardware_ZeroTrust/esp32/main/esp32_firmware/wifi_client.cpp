/**
 * @file wifi_client.cpp
 * @brief Implementation of Wi-Fi Connectivity & HTTP POST client for ESP32
 */

#include "wifi_client.h"
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>

static network_config_t g_net_config;

bool wifi_network_init(const network_config_t* config) {
    if (!config) return false;
    g_net_config = *config;

    Serial.printf("[Wi-Fi] Connecting to SSID: %s ...\n", g_net_config.ssid);
    WiFi.mode(WIFI_STA);
    WiFi.begin(g_net_config.ssid, g_net_config.password);

    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 25) {
        delay(500);
        Serial.print(".");
        attempts++;
    }
    Serial.println();

    if (WiFi.status() == WL_CONNECTED) {
        Serial.printf("[Wi-Fi] Connected! IP Address: %s, RSSI: %d dBm\n",
                      WiFi.localIP().toString().c_str(), WiFi.RSSI());
        return true;
    } else {
        Serial.println("[Wi-Fi] Connection timed out!");
        return false;
    }
}

bool wifi_network_is_connected(void) {
    return (WiFi.status() == WL_CONNECTED);
}

bool gateway_post_json(
    const char* endpoint,
    const char* json_payload,
    char* response_buffer,
    size_t buffer_len,
    int* http_code_out
) {
    if (!wifi_network_is_connected()) {
        Serial.println("[HTTP] Wi-Fi not connected!");
        return false;
    }

    HTTPClient http;
    char full_url[256];
    snprintf(full_url, sizeof(full_url), "%s%s", g_net_config.gateway_base_url, endpoint);

    http.begin(full_url);
    http.addHeader("Content-Type", "application/json");
    http.setTimeout(8000); // 8 second timeout

    int httpResponseCode = http.POST((uint8_t*)json_payload, strlen(json_payload));
    if (http_code_out) *http_code_out = httpResponseCode;

    bool success = false;
    if (httpResponseCode > 0) {
        String payload = http.getString();
        if (response_buffer && buffer_len > 0) {
            strncpy(response_buffer, payload.c_str(), buffer_len - 1);
            response_buffer[buffer_len - 1] = '\0';
        }
        success = (httpResponseCode >= 200 && httpResponseCode < 300);
    } else {
        Serial.printf("[HTTP] POST failed to %s, error: %s\n", full_url, http.errorToString(httpResponseCode).c_str());
        if (response_buffer && buffer_len > 0) {
            response_buffer[0] = '\0';
        }
    }

    http.end();
    return success;
}
