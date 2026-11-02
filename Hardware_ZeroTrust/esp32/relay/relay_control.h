/**
 * @file relay_control.h
 * @brief Physical Access Control Actuator Driver for ESP32 (SG90 Servo / Relay)
 * 
 * Supports:
 * 1. SG90 Micro Servo Motor (Default: PWM 50Hz, 0° Locked, 90° Unlocked)
 * 2. 5V Relay Module (Active LOW / HIGH fail-secure fallback)
 */

#ifndef RELAY_CONTROL_H
#define RELAY_CONTROL_H

#include <stdint.h>
#include <stdbool.h>

// Actuator Mode: Set to 1 for SG90 Servo Motor (Recommended), 0 for 5V Relay
#define USE_SERVO_ACTUATOR      1

#define DEFAULT_ACTUATOR_GPIO   22          // GPIO pin driving SG90 Servo PWM / Relay
#define DEFAULT_RELAY_GPIO      DEFAULT_ACTUATOR_GPIO  // Backward-compatibility alias
#define DEFAULT_UNLOCK_TIME_MS  5000        // 5 seconds unlock duration

// Status LED Indicator Pins (match physical wiring)
#define RED_LED_PIN             23          // Red LED: Door Locked (D23)
#define GREEN_LED_PIN           19          // Green LED: Lock Released (Unlocked) (D19)
#define WHITE_LED_PIN           GREEN_LED_PIN // Alias for compatibility

// SG90 Servo Angles
#define SERVO_ANGLE_LOCKED      0           // 0 degrees: Door Latch Locked
#define SERVO_ANGLE_UNLOCKED    90          // 90 degrees: Door Latch Retracted / Unlocked

// Relay Active Levels (Used if USE_SERVO_ACTUATOR == 0)
#define RELAY_ACTIVE_LEVEL      0           // LOW (Active LOW relay)
#define RELAY_INACTIVE_LEVEL    1           // HIGH

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DOOR_LOCKED = 0,
    DOOR_UNLOCKED = 1
} door_state_t;

/**
 * @brief Initializes GPIO pin and sets actuator to fail-secure default (LOCKED).
 * @param gpio_pin GPIO pin number (default: 22)
 */
void actuator_init(uint8_t gpio_pin);

/**
 * @brief Legacy alias for actuator_init.
 */
void relay_init(uint8_t gpio_pin);

/**
 * @brief Commands actuator to unlock door for specified duration (in milliseconds),
 * rotating SG90 servo to 90° or triggering relay. Automatically relocks after timeout.
 */
void actuator_unlock_timed(uint32_t duration_ms);

/**
 * @brief Legacy alias for actuator_unlock_timed.
 */
void relay_unlock_timed(uint32_t duration_ms);

/**
 * @brief Forces actuator into locked state immediately (SG90 servo to 0°).
 */
void actuator_lock(void);

/**
 * @brief Legacy alias for actuator_lock.
 */
void relay_lock(void);

/**
 * @brief Updates actuator timer; must be called repeatedly in loop().
 */
void actuator_update(void);

/**
 * @brief Legacy alias for actuator_update.
 */
void relay_update(void);

/**
 * @brief Returns current state of the door lock.
 */
door_state_t actuator_get_state(void);

/**
 * @brief Legacy alias for actuator_get_state.
 */
door_state_t relay_get_state(void);

#ifdef __cplusplus
}
#endif

#endif // RELAY_CONTROL_H
