/**
 * ir_cycle.h — IR Command Cycle / Brute-force Scanner
 *
 * Captures a single IR signal (protocol + address), then sweeps every
 * possible command value (0x0000 – 0xFFFF) sending each one in sequence.
 * Useful for discovering unknown button codes on a device.
 *
 * Controls:
 *   Encoder (dial)  → adjust send speed (delay between commands)
 *   OK / Sel        → pause / resume
 *   ESC / Back      → stop and return to IR menu
 */

#pragma once

#include <Arduino.h>
#include <IRremoteESP8266.h>
#include <IRsend.h>

/**
 * Main entry point.
 * Call from the IR options menu — blocks until the user exits.
 */
void startIrCycle();
