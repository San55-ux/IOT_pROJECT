/**
 * @file relay_control.cpp
 * @brief Implementation of Physical Relay Driver for Smart Lock Simulation
 */

#include "relay_control.h"
#include <Arduino.h>

static uint8_t g_relay_pin = DEFAULT_RELAY_GPIO;
static door_state_t g_lock_state = DOOR_LOCKED;
static unsigned long g_unlock_timestamp = 0;
static uint32_t g_unlock_duration = DEFAULT_UNLOCK_TIME_MS;

void relay_init(uint8_t gpio_pin) {
    g_relay_pin = gpio_pin;
    pinMode(g_relay_pin, OUTPUT);
    // Enforce Fail-Secure default state: LOCKED
    digitalWrite(g_relay_pin, RELAY_INACTIVE_LEVEL);
    g_lock_state = DOOR_LOCKED;
    Serial.printf("[Relay] Initialized on GPIO %d (State: LOCKED - Fail-Secure)\n", g_relay_pin);
}

void relay_unlock_timed(uint32_t duration_ms) {
    g_unlock_duration = duration_ms;
    g_unlock_timestamp = millis();
    digitalWrite(g_relay_pin, RELAY_ACTIVE_LEVEL);
    g_lock_state = DOOR_UNLOCKED;
    Serial.printf("[Relay] >>> DOOR UNLOCKED <<< for %u ms (Relay Pin LOW)\n", duration_ms);
}

void relay_lock(void) {
    digitalWrite(g_relay_pin, RELAY_INACTIVE_LEVEL);
    g_lock_state = DOOR_LOCKED;
    Serial.println("[Relay] >>> DOOR LOCKED <<< (Relay Pin HIGH)");
}

void relay_update(void) {
    if (g_lock_state == DOOR_UNLOCKED) {
        if (millis() - g_unlock_timestamp >= g_unlock_duration) {
            relay_lock();
            Serial.println("[Relay] Timed unlock expired. Door automatically secured.");
        }
    }
}

door_state_t relay_get_state(void) {
    return g_lock_state;
}
