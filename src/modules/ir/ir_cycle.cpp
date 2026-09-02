/**
 * ir_cycle.cpp — IR Command Brute-force Scanner
 *
 * Captures a base signal (protocol + address) then cycles every command
 * value 0x0000–0xFFFF, sending each one at an adjustable speed.
 *
 * Controls
 * ─────────
 *  Dial / encoder   → Up = faster (less delay), Down = slower (more delay)
 *  OK / Sel         → Pause / Resume
 *  ESC / Back       → Stop and exit
 *
 * Layout (128 × 64 display)
 * ─────────────────────────
 *  ┌──────────────────────────────┐
 *  │       IR CYCLE               │  ← title bar (inverse)
 *  ├──────────────────────────────┤
 *  │  Proto: NEC   Addr: 0x1234   │
 *  │  CMD ▶  0x00AB               │  ← big current command
 *  │  1234 / 65536   1%           │  ← progress
 *  │  ████████░░░░░░░░░░░░░░░░░░  │  ← progress bar
 *  │  Spd: ████░░  42ms  1m 23s   │  ← speed bar + elapsed
 *  ├──────────────────────────────┤
 *  │  [OK]=Pause [ENC]=Speed [ESC]│
 *  └──────────────────────────────┘
 */

#include "ir_cycle.h"
#include "TV-B-Gone.h"       // checkIrTxPin()
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/settings.h"
#include "core/utils.h"
#include "ir_read.h"
#include "ir_utils.h"
#include <globals.h>
#include <interface.h>

// ─── Constants ───────────────────────────────────────────────────────────────

static const uint32_t TOTAL_COMMANDS    = 65536;  // 0x0000 – 0xFFFF
static const uint32_t SPEED_STEP_MS     = 5;      // how much dial changes delay
static const uint32_t SPEED_MIN_MS      = 5;      // fastest: 5 ms between commands
static const uint32_t SPEED_MAX_MS      = 500;    // slowest: 500 ms between commands
static const uint32_t SPEED_DEFAULT_MS  = 35;     // comfortable default

// How many pixels wide the progress bar and speed bar are
static const int BAR_W = 116;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Draw title bar (filled rectangle with white inverse text).
 */
static void drawTitleBar(const char *text, bool paused) {
    // Title background
    u8g2.setDrawColor(1);
    u8g2.drawBox(0, 0, 128, 11);
    u8g2.setDrawColor(0);
    u8g2.setFont(u8g2_font_6x10_tf);
    u8g2.drawStr(4, 9, text);

    // Pause badge on the right
    if (paused) {
        u8g2.setFont(u8g2_font_5x7_tf);
        u8g2.drawStr(86, 9, "PAUSED");
    }
    u8g2.setDrawColor(1);
}

/**
 * Draw a filled progress bar at (x, y) of width w, height h, fill fraction 0.0–1.0.
 */
static void drawBar(int x, int y, int w, int h, float frac) {
    u8g2.drawRFrame(x, y, w, h, 1);
    int fill = (int)((w - 2) * frac);
    if (fill > 0) u8g2.drawBox(x + 1, y + 1, fill, h - 2);
}

/**
 * Format elapsed time as "Xs", "Xm Ys" or "Xh Ym".
 */
static String fmtTime(uint32_t ms) {
    uint32_t s = ms / 1000;
    if (s < 60)  return String(s) + "s";
    if (s < 3600) return String(s / 60) + "m " + String(s % 60) + "s";
    return String(s / 3600) + "h " + String((s % 3600) / 60) + "m";
}

// ─── Screen draw ─────────────────────────────────────────────────────────────

static void drawCycleScreen(
    decode_type_t proto, uint16_t address,
    uint32_t currentCmd, uint32_t totalCmds,
    uint32_t delayMs, unsigned long startMs,
    bool paused
) {
    u8g2.clearBuffer();

    // ---- Title bar ----
    drawTitleBar("IR CYCLE", paused);

    // ---- Protocol + Address row ----
    u8g2.setFont(u8g2_font_5x7_tf);
    u8g2.setDrawColor(1);

    char protoStr[20];
    // typeToString is from IRutils; fallback to raw int if not available
    snprintf(protoStr, sizeof(protoStr), "Proto:%-4d  Addr:0x%04X", (int)proto, address);
    u8g2.drawStr(2, 20, protoStr);

    // ---- Big current command ----
    u8g2.setFont(u8g2_font_8x13B_tf);
    char cmdHex[12];
    snprintf(cmdHex, sizeof(cmdHex), "0x%04X", (unsigned int)currentCmd);
    // Draw label in small font, then value large
    u8g2.setFont(u8g2_font_5x7_tf);
    u8g2.drawStr(2, 30, "CMD");
    u8g2.setFont(u8g2_font_8x13B_tf);
    u8g2.drawStr(22, 31, cmdHex);

    // ---- Progress numbers ----
    u8g2.setFont(u8g2_font_5x7_tf);
    char progStr[24];
    int pct = (int)(((float)currentCmd / (float)totalCmds) * 100.0f);
    snprintf(progStr, sizeof(progStr), "%lu/%lu   %d%%", currentCmd, totalCmds, pct);
    u8g2.drawStr(2, 40, progStr);

    // ---- Progress bar ----
    float progFrac = (float)currentCmd / (float)totalCmds;
    drawBar(6, 42, BAR_W, 5, progFrac);

    // ---- Speed bar + elapsed time ----
    // speed fraction: full bar = fastest (min delay), empty = slowest (max delay)
    float speedFrac = 1.0f - (float)(delayMs - SPEED_MIN_MS) / (float)(SPEED_MAX_MS - SPEED_MIN_MS);
    if (speedFrac < 0.0f) speedFrac = 0.0f;
    if (speedFrac > 1.0f) speedFrac = 1.0f;

    u8g2.setFont(u8g2_font_4x6_tf);
    u8g2.drawStr(2, 50, "Spd");
    drawBar(18, 45, 60, 5, speedFrac);

    char spdStr[12];
    snprintf(spdStr, sizeof(spdStr), "%lums", delayMs);
    u8g2.drawStr(80, 50, spdStr);

    // Elapsed time
    String elapsed = fmtTime(millis() - startMs);
    u8g2.drawStr(2, 56, elapsed.c_str());

    // ---- Footer ----
    u8g2.drawHLine(0, 57, 128);
    u8g2.setFont(u8g2_font_4x6_tf);
    u8g2.drawStr(0, 63, "[OK]Pause [ENC]Spd [ESC]Stop");

    u8g2.sendBuffer();
}

// ─── Capture screen ──────────────────────────────────────────────────────────

static void drawWaitScreen() {
    u8g2.clearBuffer();
    drawTitleBar("IR CYCLE", false);
    u8g2.setFont(u8g2_font_6x10_tf);
    u8g2.drawStr(4, 26, "Point remote at");
    u8g2.drawStr(4, 37, "IR sensor and");
    u8g2.drawStr(4, 48, "press a button.");
    u8g2.setFont(u8g2_font_4x6_tf);
    u8g2.drawStr(2, 62, "[ESC] Cancel");
    u8g2.sendBuffer();
}

static void drawCapturedScreen(decode_type_t proto, uint16_t address, uint16_t command) {
    u8g2.clearBuffer();
    drawTitleBar("CAPTURED!", false);
    u8g2.setFont(u8g2_font_5x7_tf);
    char line[24];
    snprintf(line, sizeof(line), "Proto: %d", (int)proto);
    u8g2.drawStr(4, 22, line);
    snprintf(line, sizeof(line), "Addr : 0x%04X", address);
    u8g2.drawStr(4, 31, line);
    snprintf(line, sizeof(line), "Cmd  : 0x%04X", command);
    u8g2.drawStr(4, 40, line);
    u8g2.drawHLine(0, 49, 128);
    u8g2.setFont(u8g2_font_4x6_tf);
    u8g2.drawStr(2, 56, "[OK/RIGHT] Start cycle");
    u8g2.drawStr(2, 63, "[LEFT]  Retry  [ESC] Back");
    u8g2.sendBuffer();
}

static void drawCompletedScreen(uint32_t totalCmds, unsigned long elapsedMs) {
    u8g2.clearBuffer();
    drawTitleBar("COMPLETE!", false);
    u8g2.setFont(u8g2_font_6x10_tf);
    u8g2.drawStr(10, 25, "All commands sent!");
    char line[24];
    snprintf(line, sizeof(line), "%lu commands", totalCmds);
    u8g2.drawStr(10, 37, line);
    String elapsed = "Time: " + fmtTime(elapsedMs);
    u8g2.drawStr(10, 49, elapsed.c_str());
    u8g2.setFont(u8g2_font_4x6_tf);
    u8g2.drawStr(2, 63, "Any button to exit");
    u8g2.sendBuffer();
}

// ─── Capture phase ───────────────────────────────────────────────────────────

/**
 * Wait for an IR signal and decode it.
 * Returns true if a valid signal was captured, false if the user cancelled.
 */
static bool captureSignal(decode_type_t &proto, uint16_t &address, uint16_t &command,
                           uint16_t *rawBuf, uint8_t &rawLen) {
    IrReceiver.begin(bruceConfigPins.irRx, ENABLE_LED_FEEDBACK);

    while (true) {
        drawWaitScreen();

        if (check(EscPress)) {
            IrReceiver.end();
            return false;
        }

        if (IrReceiver.decode()) {
            if (IrReceiver.decodedIRData.decodedRawData != 0 &&
                IrReceiver.decodedIRData.protocol != UNKNOWN) {
                proto   = IrReceiver.decodedIRData.protocol;
                address = (uint16_t)IrReceiver.decodedIRData.address;
                command = (uint16_t)IrReceiver.decodedIRData.command;
                rawLen  = IrReceiver.decodedIRData.rawDataPtr->rawlen;
                for (int i = 0; i < rawLen && i < RAW_BUFFER_LENGTH; i++)
                    rawBuf[i] = IrReceiver.decodedIRData.rawDataPtr->rawbuf[i];

                IrReceiver.resume();
                IrReceiver.end();
                return true;
            }
            IrReceiver.resume();
        }
        delay(10);
    }
}

// ─── Send a single command ────────────────────────────────────────────────────

static void sendCycleCommand(IRsend &irsend, decode_type_t proto,
                              uint16_t address, uint16_t command) {
    switch (proto) {
        case NEC:       irsend.sendNEC(address, command, 0);       break;
        case SONY:      irsend.sendSony(address, command, 2);      break;
        case RC5:       irsend.sendRC5(address, command, 0);       break;
        case RC6:       irsend.sendRC6(address, command, 0);       break;
        case SAMSUNG:   irsend.sendSamsung(address, command, 0);   break;
        case SAMSUNG36: irsend.sendSamsung36(address, command, 0); break;
        case LG:        irsend.sendLG(address, command, 0);        break;
        case PANASONIC: irsend.sendPanasonic(address, command, 0); break;
        case PIONEER:   irsend.sendPioneer(address, command, 0);   break;
        case JVC:       irsend.sendJVC(address, command, 0);       break;
        case SHARP:     irsend.sendSharpRaw(
                            ((uint32_t)address << 5) | (command & 0x1F), 15);
                        break;
        default:
            // Fallback: send as NEC
            irsend.sendNEC(address, command, 0);
            break;
    }
}

// ─── Main entry ──────────────────────────────────────────────────────────────

void startIrCycle() {
    checkIrTxPin();

    IRsend irsend(bruceConfigPins.irTx);
    irsend.begin();
    setup_ir_pin(bruceConfigPins.irTx, OUTPUT);

    // ---- Phase 1: Capture a base signal ----
    decode_type_t proto = UNKNOWN;
    uint16_t      baseAddress = 0;
    uint16_t      baseCommand = 0;
    uint16_t      rawBuf[RAW_BUFFER_LENGTH];
    uint8_t       rawLen = 0;

captureAgain:
    if (!captureSignal(proto, baseAddress, baseCommand, rawBuf, rawLen)) {
        // User pressed ESC — bail out cleanly
        return;
    }

    // ---- Phase 2: Confirm ----
    drawCapturedScreen(proto, baseAddress, baseCommand);
    SelPress = false; EscPress = false;
    delay(200);

    while (true) {
        if (check(EscPress))  return;         // cancel entirely
        if (check(PrevPress)) goto captureAgain; // retry capture
        if (check(SelPress) || check(NextPress)) break; // start cycling
        delay(25);
    }

    // ---- Phase 3: Cycle ----
    uint32_t    currentCmd  = 0;
    uint32_t    delayMs     = SPEED_DEFAULT_MS;
    bool        paused      = false;
    unsigned long startMs   = millis();
    unsigned long lastDraw  = 0;
    bool        done        = false;

    SelPress = false; EscPress = false; NextPress = false; PrevPress = false;
    delay(100);

    while (!done) {
        // ── Input ──────────────────────────────────────────────────────────
        if (check(EscPress)) break;  // stop and exit

        if (check(SelPress)) {
            paused = !paused;
            // Force immediate redraw to show PAUSED badge
            lastDraw = 0;
        }

        // Dial / encoder: Next = faster, Prev = slower
        if (check(NextPress)) {
            if (delayMs > SPEED_MIN_MS) {
                delayMs = max((uint32_t)SPEED_MIN_MS, delayMs - SPEED_STEP_MS);
            }
        }
        if (check(PrevPress)) {
            if (delayMs < SPEED_MAX_MS) {
                delayMs = min((uint32_t)SPEED_MAX_MS, delayMs + SPEED_STEP_MS);
            }
        }

        // ── Redraw every 100 ms ─────────────────────────────────────────────
        unsigned long now = millis();
        if (now - lastDraw >= 100) {
            drawCycleScreen(proto, baseAddress, currentCmd,
                            TOTAL_COMMANDS, delayMs, startMs, paused);
            lastDraw = now;
        }

        // ── Send ────────────────────────────────────────────────────────────
        if (!paused) {
            sendCycleCommand(irsend, proto, baseAddress, (uint16_t)currentCmd);
            currentCmd++;

            if (currentCmd >= TOTAL_COMMANDS) {
                done = true;
                break;
            }

            // Honour the speed delay while still polling buttons
            unsigned long sendDone = millis();
            while (millis() - sendDone < delayMs) {
                if (check(SelPress) || check(EscPress) ||
                    check(NextPress) || check(PrevPress)) break;
                delay(5);
            }
        } else {
            delay(25); // idle when paused
        }
    }

    // ---- Phase 4: Result ----
    if (done) {
        drawCompletedScreen(TOTAL_COMMANDS, millis() - startMs);
        delay(200);
        while (!check(AnyKeyPress)) delay(25);
    }
    // If ESC was pressed we just fall through and return
}
