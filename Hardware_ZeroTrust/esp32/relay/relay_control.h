/**
 * @file relay_control.h
 * @brief Relay & Physical Access Control Driver for ESP32
 * 
 * Configures GPIO output driving a 5V relay module with optocoupler isolation.
 * Defaults to Fail-Secure (Normally Open - Door Locked).
 */

#ifndef RELAY_CONTROL_H
#define RELAY_CONTROL_H

#include <stdint.h>
#include <stdbool.h>

#define DEFAULT_RELAY_GPIO 22          // GPIO pin driving relay module
#define RELAY_ACTIVE_LEVEL LOW        // Most Arduino relay modules are active LOW
#define RELAY_INACTIVE_LEVEL HIGH
#define DEFAULT_UNLOCK_TIME_MS 5000   // 5 seconds unlock duration

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DOOR_LOCKED = 0,
    DOOR_UNLOCKED = 1
} door_state_t;

/**
 * @brief Initializes GPIO pin and ensures relay is safely locked.
 * @param gpio_pin GPIO pin number (default: 22)
 */
void relay_init(uint8_t gpio_pin);

/**
 * @brief Commands relay to unlock door for specified duration (in milliseconds),
 * after which it automatically relocks.
 */
void relay_unlock_timed(uint32_t duration_ms);

/**
 * @brief Forces relay into locked state immediately.
 */
void relay_lock(void);

/**
 * @brief Updates relay timer; must be called repeatedly in loop().
 */
void relay_update(void);

/**
 * @brief Returns current state of the door lock.
 */
door_state_t relay_get_state(void);

#ifdef __cplusplus
}
#endif

#endif // RELAY_CONTROL_H
