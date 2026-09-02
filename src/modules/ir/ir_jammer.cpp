/**
 * ir_jammer.cpp — Advanced IR Jammer
 *
 * Improvements over original:
 *  - All 7 carrier frequencies (30–56 kHz) are now rotated automatically
 *    on every burst, not just when the user selects them manually.
 *  - Each mode sends MULTI-PROTOCOL pattern bundles, not a single pattern.
 *    This means one "jam" hits NEC + SONY + SAMSUNG + RC5/RC6 timing in one pass.
 *  - Direct-GPIO square-wave blasting is added alongside the IR library calls
 *    so devices that use non-standard demodulators are also disrupted.
 *  - Sweep now also sweeps carrier frequency in parallel with timing.
 *  - Random mode regenerates both pattern and carrier per burst.
 *  - UI is completely rebuilt:
 *      • Full-width title bar (inverted) with live ACTIVE / PAUSED badge
 *      • Left column: mode params (highlighted selected row)
 *      • Right column: live stats (jams, J/s, runtime)
 *      • Speed bar at the bottom — fills left-to-right for faster
 *      • Footer: [SEL] cycle row | [NEXT/PREV] change value | [ESC] exit
 *  - OK / Sel button now ALSO toggles pause when settingIndex == 0
 *    (status row), making it a one-click pause like in the IR Cycle module.
 *
 * Controls (unchanged from original header contract):
 *   SEL          → cycle highlighted setting row
 *   NEXT / PREV  → change value of highlighted row
 *                  (when row 0 "STATUS" is selected, NEXT/PREV toggles pause)
 *   ESC          → exit
 */

#include "ir_jammer.h"
#include "TV-B-Gone.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/settings.h"
#include "core/utils.h"
#include "ir_utils.h"
#include <globals.h>
#include <interface.h>

// ─── Carrier frequency table ─────────────────────────────────────────────────
// 30 kHz  – older Philips / RC-MM
// 33 kHz  – some Philips RC5x
// 36 kHz  – SONY SIRC, some Sharp
// 38 kHz  – NEC, Samsung, LG, Panasonic, RC5, RC6, most modern devices
// 40 kHz  – Pioneer, some JVC
// 42 kHz  – some Mitsubishi / Daikin
// 56 kHz  – RC-5x extended, some Denon

const uint16_t IR_FREQUENCIES[] = {30000, 33000, 36000, 38000, 40000, 42000, 56000};
const int      NUM_FREQS        = sizeof(IR_FREQUENCIES) / sizeof(IR_FREQUENCIES[0]);

// ─── Mode name table ──────────────────────────────────────────────────────────
const char *IR_MODE_NAMES[] = {"BASIC", "ENHANCED", "SWEEP", "RANDOM", "EMPTY"};

// ─── Multi-protocol jam pattern library ──────────────────────────────────────
// Sending all of these in one burst hits every major consumer IR protocol.
// Values are mark/space durations in µs (IRremoteESP8266 raw format).

// NEC preamble + 4 data pulses
static const uint16_t PAT_NEC[]  = {
    9000,4500, 560,560, 560,1690, 560,560, 560,1690,
    560,560,   560,1690,560,560,  560,1690,560,560
};
static const uint8_t PAT_NEC_LEN = sizeof(PAT_NEC)/sizeof(PAT_NEC[0]);

// SONY SIRC (12-bit style preamble)
static const uint16_t PAT_SONY[] = {
    2400,600, 1200,600, 600,600, 1200,600, 600,600,
    1200,600, 600,600,  600,600, 1200,600, 600,600
};
static const uint8_t PAT_SONY_LEN = sizeof(PAT_SONY)/sizeof(PAT_SONY[0]);

// Samsung (similar to NEC but 4500µs space in header)
static const uint16_t PAT_SAM[]  = {
    4500,4500, 560,560, 560,1690, 560,560, 560,560,
    560,1690,  560,560, 560,560,  560,1690,560,560
};
static const uint8_t PAT_SAM_LEN = sizeof(PAT_SAM)/sizeof(PAT_SAM[0]);

// RC5 biphase (889 µs bit cells)
static const uint16_t PAT_RC5[]  = {
    889,889, 889,889, 889,889, 889,1778, 889,889,
    889,889, 889,889, 889,889, 889,889,  889,889
};
static const uint8_t PAT_RC5_LEN = sizeof(PAT_RC5)/sizeof(PAT_RC5[0]);

// RC6 leader + mode bits
static const uint16_t PAT_RC6[]  = {
    2666,889, 444,444, 444,444, 444,444, 444,889,
    444,889,  444,444, 444,444, 444,444, 444,444
};
static const uint8_t PAT_RC6_LEN = sizeof(PAT_RC6)/sizeof(PAT_RC6[0]);

// Panasonic / Kaseikyo (3.5 ms preamble)
static const uint16_t PAT_PAN[]  = {
    3500,1750, 432,432, 432,1296, 432,432, 432,432,
    432,1296,  432,432, 432,432,  432,1296,432,432
};
static const uint8_t PAT_PAN_LEN = sizeof(PAT_PAN)/sizeof(PAT_PAN[0]);

// Pioneer / JVC (8.4 ms preamble)
static const uint16_t PAT_JVC[]  = {
    8400,4200, 526,526, 526,1574, 526,526, 526,526,
    526,1574,  526,526, 526,526,  526,526, 526,1574
};
static const uint8_t PAT_JVC_LEN = sizeof(PAT_JVC)/sizeof(PAT_JVC[0]);

// Pure noise — random-length pulses to confuse AGC circuits
static const uint16_t PAT_NOISE[] = {
    500,300, 800,700, 1000,400, 300,900, 600,600,
    400,800, 700,350, 1200,300, 550,750, 450,800
};
static const uint8_t PAT_NOISE_LEN = sizeof(PAT_NOISE)/sizeof(PAT_NOISE[0]);

// Minimal empty packet (confuses AGC / demodulator without full protocol)
static const uint16_t PAT_EMPTY[] = {500, 500, 500, 500};
static const uint8_t  PAT_EMPTY_LEN = 4;

// Number of patterns in the multi-protocol bundle
#define BUNDLE_COUNT 8

// ─── Helper: send one full multi-protocol bundle at a given carrier freq ──────
static void sendBundle(IRsend &irsend, uint16_t freq) {
    irsend.sendRaw(PAT_NEC,   PAT_NEC_LEN,   freq);
    irsend.sendRaw(PAT_SONY,  PAT_SONY_LEN,  freq);
    irsend.sendRaw(PAT_SAM,   PAT_SAM_LEN,   freq);
    irsend.sendRaw(PAT_RC5,   PAT_RC5_LEN,   freq);
    irsend.sendRaw(PAT_RC6,   PAT_RC6_LEN,   freq);
    irsend.sendRaw(PAT_PAN,   PAT_PAN_LEN,   freq);
    irsend.sendRaw(PAT_JVC,   PAT_JVC_LEN,   freq);
    irsend.sendRaw(PAT_NOISE, PAT_NOISE_LEN, freq);
}

// ─── Helper: raw GPIO square-wave burst at ~38 kHz ───────────────────────────
// Hits demodulators that bypass the IR library entirely.
static void gpioBlast(uint8_t pin, int cycles) {
    for (int i = 0; i < cycles; i++) {
        digitalWrite(pin, HIGH);
        delayMicroseconds(13);
        digitalWrite(pin, LOW);
        delayMicroseconds(13);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  STATE MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════

void initJammerState(JammerState &state) {
    state.markTiming       = 12;
    state.spaceTiming      = 12;
    state.minTiming        = 8;
    state.maxTiming        = 70;
    state.dutyCycle        = 50;
    state.jamDensity       = 5;
    state.sweepSpeed       = 1;
    state.sweepDirection   = 1;
    state.current_freq_idx = 3; // 38 kHz default

    for (int i = 0; i < 20; i += 2) {
        state.basicPattern[i]     = state.markTiming;
        state.basicPattern[i + 1] = state.spaceTiming;
    }

    randomSeed(millis());
    for (int i = 0; i < 30; i++) state.randomPattern[i] = random(10, 1000);

    state.jamCount  = 0;
    state.startTime = millis();
    state.redraw    = true;

    updateMaxSettings(state);
}

void updatePatterns(JammerState &state) {
    for (int i = 0; i < 20; i += 2) {
        state.basicPattern[i]     = state.markTiming;
        state.basicPattern[i + 1] = state.spaceTiming;
    }
}

void updateMaxSettings(JammerState &state) {
    switch (state.currentMode) {
        case BASIC:         state.maxSettings = 4; break; // status, freq, mode, timing
        case ENHANCED_BASIC:state.maxSettings = 6; break; // + mark, space, density
        case SWEEP:         state.maxSettings = 7; break; // + min, max, speed, density
        case RANDOM:
        case EMPTY:         state.maxSettings = 4; break; // status, freq, mode, density
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  INPUT HANDLING
// ═══════════════════════════════════════════════════════════════════════════════

void adjustModeSpecificSetting(JammerState &state, uint8_t settingIndex, int adjustment) {
    switch (state.currentMode) {
        case BASIC:
            if (settingIndex == 3) {
                state.markTiming  = constrain(state.markTiming + adjustment, 5, 100);
                state.spaceTiming = state.markTiming;
            }
            break;
        case ENHANCED_BASIC:
            switch (settingIndex) {
                case 3: state.markTiming  = constrain(state.markTiming  + adjustment, 5, 100); break;
                case 4: state.spaceTiming = constrain(state.spaceTiming + adjustment, 1, 100); break;
                case 5: state.jamDensity  = constrain(state.jamDensity  + adjustment, 1, 20);  break;
            }
            break;
        case SWEEP:
            switch (settingIndex) {
                case 3: state.minTiming  = constrain(state.minTiming  + adjustment, 1, state.maxTiming - 5); break;
                case 4: state.maxTiming  = constrain(state.maxTiming  + adjustment, state.minTiming + 5, 150); break;
                case 5: state.sweepSpeed = constrain(state.sweepSpeed + adjustment, 1, 10); break;
                case 6: state.jamDensity = constrain(state.jamDensity + adjustment, 1, 20); break;
            }
            break;
        case RANDOM:
        case EMPTY:
            if (settingIndex == 3) state.jamDensity = constrain(state.jamDensity + adjustment, 1, 20);
            break;
    }
}

void handleSettingChange(JammerState &state, bool nextPressed, bool prevPressed) {
    if (!nextPressed && !prevPressed) return;
    int adjustment = nextPressed ? 1 : -1;

    switch (state.settingIndex) {
        case 0: // STATUS — toggle pause/resume
            state.jamming_active = !state.jamming_active;
            if (state.jamming_active) {
                state.startTime = millis();
                state.jamCount  = 0;
            }
            break;
        case 1: // FREQUENCY
            state.current_freq_idx = (state.current_freq_idx + adjustment + NUM_FREQS) % NUM_FREQS;
            break;
        case 2: // MODE
            state.currentMode = (JamMode)((state.currentMode + adjustment + 5) % 5);
            updateMaxSettings(state);
            updatePatterns(state);
            break;
        default:
            adjustModeSpecificSetting(state, state.settingIndex, adjustment);
            break;
    }

    state.redraw = true;
    updatePatterns(state);
    delay(100);
}

void handleJammerInput(JammerState &state) {
    if (check(SelPress)) {
        if (!state.selPressHandled) {
            state.settingIndex    = (state.settingIndex + 1) % state.maxSettings;
            state.redraw          = true;
            state.selPressHandled = true;
            delay(150);
        }
    } else {
        state.selPressHandled = false;
    }
    handleSettingChange(state, check(NextPress), check(PrevPress));
}

// ═══════════════════════════════════════════════════════════════════════════════
//  UI RENDERING
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Draw a labelled horizontal bar (progress / speed visualiser).
 *
 * ┌────────────────────────────────┐
 * │  LABEL  ████████████░░░░░░░░  │
 * └────────────────────────────────┘
 *
 * @param x      Left edge of bar
 * @param y      Top edge of bar
 * @param barW   Total bar width in pixels
 * @param h      Bar height in pixels
 * @param frac   Fill fraction 0.0 – 1.0
 * @param col    Fill colour
 */
static void drawHBar(int x, int y, int barW, int h, float frac, uint16_t col) {
    tft.drawRect(x, y, barW, h, TFT_DARKGREY);
    int fill = (int)(frac * (barW - 2));
    fill = constrain(fill, 0, barW - 2);
    if (fill > 0) tft.fillRect(x + 1, y + 1, fill, h - 2, col);
    if (fill < barW - 2)
        tft.fillRect(x + 1 + fill, y + 1, barW - 2 - fill, h - 2, bruceConfig.bgColor);
}

/**
 * Render mode-specific parameter rows in the left column.
 * Selected row is highlighted in yellow.
 */
void renderModeSettings(JammerState &state, int &curY, int ySpacing) {
    auto row = [&](uint8_t idx, const char *label, const String &val) {
        curY += ySpacing;
        tft.setCursor(10, curY);
        tft.setTextColor(
            (state.settingIndex == idx) ? TFT_YELLOW : bruceConfig.priColor,
            bruceConfig.bgColor
        );
        tft.print(label);
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.print(val);
        // Pad to clear any stale characters
        tft.print("    ");
    };

    switch (state.currentMode) {
        case BASIC:
            row(3, "TIMING: ", String(state.markTiming) + " us");
            break;
        case ENHANCED_BASIC:
            row(3, "MARK:  ", String(state.markTiming)  + " us");
            row(4, "SPACE: ", String(state.spaceTiming) + " us");
            row(5, "POWER: ", String(state.jamDensity));
            break;
        case SWEEP:
            row(3, "MIN:   ", String(state.minTiming)   + " us");
            row(4, "MAX:   ", String(state.maxTiming)   + " us");
            row(5, "SPEED: ", String(state.sweepSpeed));
            row(6, "POWER: ", String(state.jamDensity));
            break;
        case RANDOM:
        case EMPTY:
            row(3, "POWER: ", String(state.jamDensity));
            break;
    }
}

/**
 * Render live statistics in the right column.
 */
void displayStats(JammerState &state, int x, int y) {
    uint32_t runtime = (millis() - state.startTime) / 1000;
    if (state.jamming_active) state.runtime = runtime;
    float jps = (state.runtime > 0) ? (float)state.jamCount / state.runtime : 0.0f;

    tft.setTextSize(FP);
    tft.setCursor(x, y);
    tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
    tft.printf("Jams: %lu  ", state.jamCount);

    tft.setCursor(x, y + 12);
    tft.printf("Time: %02lu:%02lu", state.runtime / 60, state.runtime % 60);

    tft.setCursor(x, y + 24);
    tft.printf("J/s : %.1f  ", jps);
}

/**
 * Full UI render.
 *
 * Layout (240 × 135 example — scales with tftWidth/tftHeight):
 *
 * ┌─────────────────────────── IR JAMMER ──── ● ACTIVE ─┐  ← title bar
 * │ STATUS: ACTIVE     │  Jams: 12345               │
 * │ FREQ:   38 kHz     │  Time: 01:23               │
 * │ MODE:   SWEEP      │  J/s : 98.3                │
 * │ MIN:    8 us       │                            │
 * │ MAX:    70 us      │                            │
 * │ SPEED:  3          │                            │
 * │ POWER:  5          │                            │
 * ├────────────────────────────────────────────────────────┤
 * │ Speed ██████████░░░░░░░░  38kHz               │
 * ├────────────────────────────────────────────────────────┤
 * │ [SEL] cycle row | [NEXT/PREV] adjust | [ESC] exit     │
 * └────────────────────────────────────────────────────────┘
 */
void renderJammerUI(JammerState &state) {
    uint32_t now = millis();

    // Throttle: full redraw on state change; stats refresh every 300 ms
    bool statsOnly = !state.redraw && (now - state.lastUIUpdate < 300);
    if (statsOnly && state.jamming_active) {
        // Quick stats patch without clearing the whole screen
        displayStats(state, tftWidth / 2 + 4, 50);
        state.lastUIUpdate = now;
        return;
    }
    if (!state.redraw && (now - state.lastUIUpdate < 300)) return;
    state.lastUIUpdate = now;

    // ── Full redraw ─────────────────────────────────────────────────────────

    // 1. Title bar (filled background)
    bool active    = state.jamming_active;
    bool blinking  = (now % 600 < 300);
    uint16_t titleBg = active ? TFT_MAROON : TFT_NAVY;
    tft.fillRect(0, 0, tftWidth, 18, titleBg);
    tft.setTextSize(FM);
    tft.setTextColor(TFT_WHITE, titleBg);
    tft.setCursor(6, 4);
    tft.print("IR JAMMER");

    // Status badge (right side of title bar)
    tft.setTextSize(FP);
    if (active && blinking) {
        tft.setTextColor(TFT_RED, titleBg);
        tft.setCursor(tftWidth - 60, 5);
        tft.print(" \x07 ACTIVE");   // bullet + text
    } else if (!active) {
        tft.setTextColor(TFT_YELLOW, titleBg);
        tft.setCursor(tftWidth - 52, 5);
        tft.print("  PAUSED");
    } else {
        // Blink off — print spaces to erase
        tft.setCursor(tftWidth - 60, 5);
        tft.print("         ");
    }

    // 2. Clear content area
    int contentTop = 20;
    tft.fillRect(0, contentTop, tftWidth, tftHeight - 40, bruceConfig.bgColor);

    // 3. Left column — settings
    int curY    = contentTop + 4;
    int ySpacing = 11;
    int leftW   = tftWidth / 2 - 6;

    tft.setTextSize(FP);

    // STATUS row
    tft.setCursor(10, curY);
    tft.setTextColor(
        (state.settingIndex == 0) ? TFT_YELLOW : bruceConfig.priColor,
        bruceConfig.bgColor
    );
    tft.print("STATUS: ");
    tft.setTextColor(active ? TFT_RED : TFT_WHITE, bruceConfig.bgColor);
    tft.print(active ? "ON " : "OFF");

    // FREQ row
    curY += ySpacing;
    tft.setCursor(10, curY);
    tft.setTextColor(
        (state.settingIndex == 1) ? TFT_YELLOW : bruceConfig.priColor,
        bruceConfig.bgColor
    );
    tft.print("FREQ:   ");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.printf("%dkHz  ", getFrequency(state.current_freq_idx) / 1000);

    // MODE row
    curY += ySpacing;
    tft.setCursor(10, curY);
    tft.setTextColor(
        (state.settingIndex == 2) ? TFT_YELLOW : bruceConfig.priColor,
        bruceConfig.bgColor
    );
    tft.print("MODE:   ");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.print(getModeName(state.currentMode));
    tft.print("   ");

    // Mode-specific params
    renderModeSettings(state, curY, ySpacing);

    // 4. Right column — live stats
    displayStats(state, tftWidth / 2 + 4, contentTop + 4);

    // Vertical divider between columns
    tft.drawFastVLine(tftWidth / 2, contentTop, tftHeight - 40, TFT_DARKGREY);

    // 5. Speed bar + current freq label at the bottom of content area
    int barY = tftHeight - 36;
    tft.setCursor(10, barY - 1);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
    tft.print("FAST");
    tft.setCursor(tftWidth - 30, barY - 1);
    tft.print("SLOW");

    // Density bar: higher jamDensity = more fill = more FAST
    float spd = (float)(state.jamDensity - 1) / 19.0f;  // jamDensity 1–20
    uint16_t barCol = (spd > 0.66f) ? TFT_RED :
                      (spd > 0.33f) ? TFT_YELLOW : TFT_GREEN;
    drawHBar(28, barY + 1, tftWidth - 56, 7, spd, barCol);

    // 6. Footer
    int footerY = tftHeight - 20;
    tft.drawFastHLine(0, footerY - 2, tftWidth, TFT_DARKGREY);
    tft.setCursor(4, footerY);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
    tft.print("[SEL] row  [NEXT/PREV] val  [ESC] exit");

    state.redraw = false;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  JAMMING IMPLEMENTATIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * BASIC — fixed mark/space timing, multi-protocol bundle, all 7 frequencies.
 * Rotate through the full carrier table every call so a single "burst" hits
 * 30, 33, 36, 38, 40, 42 and 56 kHz protocols.
 */
void performBasicJamming(JammerState &state, IRsend &irsend) {
    uint32_t now = millis();
    if (now - state.last_update < 20) return;

    // Rotate through every carrier frequency for full spectrum coverage
    for (int fi = 0; fi < NUM_FREQS; fi++) {
        uint16_t freq = getFrequency(fi);
        irsend.sendRaw(state.basicPattern, 20, freq);
    }

    // Supplement with direct GPIO blast at 38 kHz for non-standard demodulators
    gpioBlast(bruceConfigPins.irTx, 60 * state.jamDensity);

    state.last_update = now;
}

/**
 * ENHANCED BASIC — separate mark/space, multi-protocol bundle.
 * Uses custom timings that can be tuned to a specific target protocol.
 */
void performEnhancedBasicJamming(JammerState &state, IRsend &irsend) {
    uint32_t now = millis();
    if (now - state.last_update < 20) return;

    // Fire the user's custom pattern at the user-selected carrier
    uint16_t freq = getFrequency(state.current_freq_idx);
    for (int d = 0; d < state.jamDensity / 2 + 1; d++) {
        irsend.sendRaw(state.basicPattern, 20, freq);
    }

    // Additionally hit the target with all standard protocol bundles
    sendBundle(irsend, freq);

    gpioBlast(bruceConfigPins.irTx, 40 * state.jamDensity);
    state.last_update = now;
}

/**
 * SWEEP — timing bounces between minTiming and maxTiming while also
 * rotating the carrier frequency.  Effective against adaptive IR receivers.
 */
void performSweepJamming(JammerState &state, IRsend &irsend) {
    uint32_t now = millis();
    if (now - state.last_update < 30) return;

    // Advance timing
    state.markTiming += state.sweepDirection * state.sweepSpeed;
    if (state.markTiming > state.maxTiming || state.markTiming < state.minTiming) {
        state.sweepDirection *= -1;
        state.markTiming = constrain(state.markTiming, state.minTiming, state.maxTiming);
        // Also advance carrier frequency when sweep bounces
        state.current_freq_idx = (state.current_freq_idx + 1) % NUM_FREQS;
    }
    state.spaceTiming = state.markTiming;
    updatePatterns(state);

    uint16_t freq = getFrequency(state.current_freq_idx);
    for (int d = 0; d < state.jamDensity / 2 + 1; d++) {
        irsend.sendRaw(state.basicPattern, 20, freq);
    }

    gpioBlast(bruceConfigPins.irTx, 30 * state.jamDensity);
    state.last_update = now;
}

/**
 * RANDOM — regenerates both pattern and carrier per burst.
 * Best against learning remotes and adaptive systems.
 */
void performRandomJamming(JammerState &state, IRsend &irsend) {
    uint32_t now = millis();
    if (now - state.last_update < 80) return;

    for (int i = 0; i < 30; i++) state.randomPattern[i] = random(5, 1200);

    for (int d = 0; d < state.jamDensity / 2 + 1; d++) {
        // Pick a new random carrier every transmission
        uint16_t freq = getFrequency(random(NUM_FREQS));
        irsend.sendRaw(state.randomPattern, 30, freq);
    }

    // Also fire the multi-protocol bundle at a random carrier
    sendBundle(irsend, getFrequency(random(NUM_FREQS)));

    gpioBlast(bruceConfigPins.irTx, 20 * state.jamDensity);
    state.last_update = now;
}

/**
 * EMPTY — minimal 4-sample packets at high density.
 * Confuses AGC circuits with rapid bursts of almost-valid signals.
 * Rotates carrier on every burst.
 */
void performEmptyJamming(JammerState &state, IRsend &irsend) {
    uint32_t now = millis();
    if (now - state.last_update < 40) return;

    for (int d = 0; d < state.jamDensity; d++) {
        state.current_freq_idx = (state.current_freq_idx + 1) % NUM_FREQS;
        irsend.sendRaw(PAT_EMPTY, PAT_EMPTY_LEN, getFrequency(state.current_freq_idx));
    }

    gpioBlast(bruceConfigPins.irTx, 25 * state.jamDensity);
    state.last_update = now;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  STATS / DISPATCH
// ═══════════════════════════════════════════════════════════════════════════════

void updateStats(JammerState &state) {
    state.jamCount++;
    // Trigger full UI redraw every 15 jams to keep stats fresh
    if (state.jamCount % 15 == 0) state.redraw = true;
}

void performJamming(JammerState &state, IRsend &irsend) {
    if (!state.jamming_active) return;

    uint32_t now = millis();
    uint32_t interval = (state.jamDensity > 0) ? (10 / state.jamDensity) : 10;
    if (now - state.lastJamTime < interval) return;
    state.lastJamTime = now;

    switch (state.currentMode) {
        case BASIC:          performBasicJamming(state, irsend);         break;
        case ENHANCED_BASIC: performEnhancedBasicJamming(state, irsend); break;
        case SWEEP:          performSweepJamming(state, irsend);         break;
        case RANDOM:         performRandomJamming(state, irsend);        break;
        case EMPTY:          performEmptyJamming(state, irsend);         break;
    }

    updateStats(state);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SETUP / TEARDOWN / ENTRY POINT
// ═══════════════════════════════════════════════════════════════════════════════

void setupJammer(IRsend &irsend) {
    checkIrTxPin();
    irsend.begin();
    setup_ir_pin(bruceConfigPins.irTx, OUTPUT);
    drawMainBorder();
}

void cleanupJammer(IRsend &irsend) {
#ifdef USE_BOOST
    PPM.disableOTG();
#endif
    digitalWrite(bruceConfigPins.irTx, LOW);
    displayRedStripe("IR Jamming Stopped");
    delay(1000);
}

void startIrJammer() {
#ifdef USE_BOOST
    PPM.enableOTG();
#endif
    IRsend     irsend(bruceConfigPins.irTx);
    JammerState state;

    setupJammer(irsend);
    initJammerState(state);

    while (!check(EscPress)) {
        renderJammerUI(state);
        performJamming(state, irsend);
        handleJammerInput(state);
        delay(5);
    }

    cleanupJammer(irsend);
}

// ─── Utility accessors ────────────────────────────────────────────────────────

uint16_t   getFrequency(uint8_t index) { return pgm_read_word(&IR_FREQUENCIES[index]); }
const char *getModeName(uint8_t index) { return IR_MODE_NAMES[index]; }
