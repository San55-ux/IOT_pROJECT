/**
 * @file relay_control.cpp
 * @brief Implementation of Physical Actuator Driver (SG90 Servo / Relay)
 */

#include "relay_control.h"
#include <Arduino.h>

static uint8_t g_actuator_pin = DEFAULT_ACTUATOR_GPIO;
static door_state_t g_lock_state = DOOR_LOCKED;
static unsigned long g_unlock_timestamp = 0;
static uint32_t g_unlock_duration = DEFAULT_UNLOCK_TIME_MS;

#if USE_SERVO_ACTUATOR
// LEDC PWM Configuration for SG90 Servo (50Hz = 20ms period)
static const int SERVO_PWM_CHANNEL = 0;
static const int SERVO_PWM_FREQ = 50;
static const int SERVO_PWM_RES_BITS = 16;
static const uint32_t PWM_MAX_DUTY = (1 << SERVO_PWM_RES_BITS) - 1; // 65535

/**
 * @brief Sets SG90 servo angle (0 to 180 degrees) via PWM duty cycle.
 * At 50Hz, period = 20,000 us.
 * 0°   -> ~500 us  (duty = 1638)
 * 90°  -> ~1500 us (duty = 4915)
 * 180° -> ~2500 us (duty = 8192)
 */
static void set_servo_angle(int angle) {
    if (angle < 0) angle = 0;
    if (angle > 180) angle = 180;

    uint32_t pulse_us = 500 + (angle * 2000 / 180);
    uint32_t duty = (pulse_us * PWM_MAX_DUTY) / 20000;

#if defined(ESP_ARDUINO_VERSION_MAJOR) && (ESP_ARDUINO_VERSION_MAJOR >= 3)
    ledcWrite(g_actuator_pin, duty);
#else
    ledcWrite(SERVO_PWM_CHANNEL, duty);
#endif
}
#endif

void actuator_init(uint8_t gpio_pin) {
    g_actuator_pin = gpio_pin;

#if USE_SERVO_ACTUATOR
    // Initialize LEDC PWM for SG90 Servo
#if defined(ESP_ARDUINO_VERSION_MAJOR) && (ESP_ARDUINO_VERSION_MAJOR >= 3)
    ledcAttach(g_actuator_pin, SERVO_PWM_FREQ, SERVO_PWM_RES_BITS);
#else
    ledcSetup(SERVO_PWM_CHANNEL, SERVO_PWM_FREQ, SERVO_PWM_RES_BITS);
    ledcAttachPin(g_actuator_pin, SERVO_PWM_CHANNEL);
#endif
    // Set to 0 degrees (Locked)
    set_servo_angle(SERVO_ANGLE_LOCKED);
    g_lock_state = DOOR_LOCKED;
    Serial.printf("[Actuator] SG90 Servo initialized on GPIO %d (State: LOCKED at %d°)\n",
                  g_actuator_pin, SERVO_ANGLE_LOCKED);
#else
    // Initialize Relay GPIO
    pinMode(g_actuator_pin, OUTPUT);
    digitalWrite(g_actuator_pin, RELAY_INACTIVE_LEVEL);
    g_lock_state = DOOR_LOCKED;
    Serial.printf("[Actuator] 5V Relay initialized on GPIO %d (State: LOCKED - Fail-Secure)\n",
                  g_actuator_pin);
#endif

    // Initialize Status Indicator LEDs (Red = Locked, Green = Released/Unlocked)
    pinMode(RED_LED_PIN, OUTPUT);
    pinMode(GREEN_LED_PIN, OUTPUT);
    digitalWrite(RED_LED_PIN, HIGH);   // Default state: LOCKED (Red ON)
    digitalWrite(GREEN_LED_PIN, LOW);  // Green OFF
    Serial.printf("[Actuator] Status LEDs configured: RED on GPIO %d (ON), GREEN on GPIO %d (OFF)\n",
                  RED_LED_PIN, GREEN_LED_PIN);
}

void actuator_unlock_timed(uint32_t duration_ms) {
    g_unlock_duration = duration_ms;
    g_unlock_timestamp = millis();

    // Turn ON Green LED (Lock Released) and turn OFF Red LED
    digitalWrite(RED_LED_PIN, LOW);
    digitalWrite(GREEN_LED_PIN, HIGH);

#if USE_SERVO_ACTUATOR
    set_servo_angle(SERVO_ANGLE_UNLOCKED);
    g_lock_state = DOOR_UNLOCKED;
    Serial.printf("[Actuator] >>> DOOR UNLOCKED <<< SG90 rotated to %d° for %u ms (GREEN LED ON)\n",
                  SERVO_ANGLE_UNLOCKED, duration_ms);
#else
    digitalWrite(g_actuator_pin, RELAY_ACTIVE_LEVEL);
    g_lock_state = DOOR_UNLOCKED;
    Serial.printf("[Actuator] >>> DOOR UNLOCKED <<< Relay Pin active for %u ms (GREEN LED ON)\n", duration_ms);
#endif
}

void actuator_lock(void) {
    // Turn ON Red LED (Locked) and turn OFF Green LED
    digitalWrite(RED_LED_PIN, HIGH);
    digitalWrite(GREEN_LED_PIN, LOW);

#if USE_SERVO_ACTUATOR
    set_servo_angle(SERVO_ANGLE_LOCKED);
    g_lock_state = DOOR_LOCKED;
    Serial.printf("[Actuator] >>> DOOR LOCKED <<< SG90 rotated back to %d° (RED LED ON)\n", SERVO_ANGLE_LOCKED);
#else
    digitalWrite(g_actuator_pin, RELAY_INACTIVE_LEVEL);
    g_lock_state = DOOR_LOCKED;
    Serial.println("[Actuator] >>> DOOR LOCKED <<< Relay Pin inactive (RED LED ON)");
#endif
}

void actuator_update(void) {
    if (g_lock_state == DOOR_UNLOCKED) {
        if (millis() - g_unlock_timestamp >= g_unlock_duration) {
            actuator_lock();
            Serial.println("[Actuator] Timed unlock expired. Door latch automatically secured.");
        }
    }
}

door_state_t actuator_get_state(void) {
    return g_lock_state;
}

// Backward compatibility aliases
void relay_init(uint8_t gpio_pin) { actuator_init(gpio_pin); }
void relay_unlock_timed(uint32_t duration_ms) { actuator_unlock_timed(duration_ms); }
void relay_lock(void) { actuator_lock(); }
void relay_update(void) { actuator_update(); }
door_state_t relay_get_state(void) { return actuator_get_state(); }
