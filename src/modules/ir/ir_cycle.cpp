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
 */

#include "ir_cycle.h"
#include "TV-B-Gone.h"          // checkIrTxPin()
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/settings.h"
#include "core/utils.h"
#include "ir_read.h"
#include "ir_utils.h"
#include <globals.h>
// IRremoteESP8266 — same library Bruce uses everywhere else
#include <IRrecv.h>
#include <IRsend.h>
#include <IRutils.h>

// ─── Constants ───────────────────────────────────────────────────────────────

static const uint32_t TOTAL_COMMANDS   = 65536;  // 0x0000 – 0xFFFF
static const uint32_t SPEED_STEP_MS    = 5;
static const uint32_t SPEED_MIN_MS     = 5;
static const uint32_t SPEED_MAX_MS     = 500;
static const uint32_t SPEED_DEFAULT_MS = 35;

// ─── Helpers ─────────────────────────────────────────────────────────────────

static String fmtTime(uint32_t ms) {
    uint32_t s = ms / 1000;
    if (s < 60)   return String(s) + "s";
    if (s < 3600) return String(s / 60) + "m " + String(s % 60) + "s";
    return String(s / 3600) + "h " + String((s % 3600) / 60) + "m";
}

/**
 * Draw a horizontal progress bar using TFT primitives.
 * Outline rect + filled inner rect proportional to frac (0.0–1.0).
 */
static void drawBar(int x, int y, int w, int h, float frac) {
    tft.drawRect(x, y, w, h, bruceConfig.priColor);
    int fill = (int)((w - 2) * frac);
    if (fill > 0) tft.fillRect(x + 1, y + 1, fill, h - 2, bruceConfig.priColor);
}

// ─── Screen draw ─────────────────────────────────────────────────────────────

static void drawCycleScreen(
    decode_type_t proto, uint16_t address,
    uint32_t currentCmd, uint32_t totalCmds,
    uint32_t delayMs, unsigned long startMs,
    bool paused
) {
    // Use Bruce's standard border + title
    String title = paused ? "IR CYCLE [PAUSED]" : "IR CYCLE";
    drawMainBorderWithTitle(title);

    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FP);
    tft.setCursor(BORDER_PAD_X, BORDER_PAD_Y);

    // Proto + address line
    char protoStr[32];
    snprintf(protoStr, sizeof(protoStr), "Proto:%-4d Addr:0x%04X", (int)proto, address);
    padprintln(protoStr);

    // Current command — bigger text
    tft.setTextSize(FM);
    char cmdHex[16];
    snprintf(cmdHex, sizeof(cmdHex), "CMD: 0x%04X", (unsigned int)currentCmd);
    padprintln(cmdHex);

    // Progress numbers
    tft.setTextSize(FP);
    char progStr[32];
    int pct = (totalCmds > 0) ? (int)(((float)currentCmd / (float)totalCmds) * 100.0f) : 0;
    snprintf(progStr, sizeof(progStr), "%lu/%lu  %d%%", currentCmd, totalCmds, pct);
    padprintln(progStr);

    // Progress bar
    int barY = tft.getCursorY();
    drawBar(BORDER_PAD_X, barY, tftWidth - BORDER_PAD_X * 2, 6,
            (float)currentCmd / (float)totalCmds);
    tft.setCursor(BORDER_PAD_X, barY + 8);

    // Speed bar
    float speedFrac = 1.0f - (float)(delayMs - SPEED_MIN_MS) / (float)(SPEED_MAX_MS - SPEED_MIN_MS);
    if (speedFrac < 0.0f) speedFrac = 0.0f;
    if (speedFrac > 1.0f) speedFrac = 1.0f;

    padprint("Spd:");
    int spdBarX = tft.getCursorX();
    int spdBarY = tft.getCursorY();
    drawBar(spdBarX, spdBarY, 60, 6, speedFrac);

    char spdStr[12];
    snprintf(spdStr, sizeof(spdStr), " %lums", delayMs);
    tft.setCursor(spdBarX + 62, spdBarY);
    padprintln(spdStr);

    // Elapsed time
    String elapsed = "Time: " + fmtTime(millis() - startMs);
    padprintln(elapsed);
}

// ─── Capture screens ─────────────────────────────────────────────────────────

static void drawWaitScreen() {
    drawMainBorderWithTitle("IR CYCLE");
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FP);
    tft.setCursor(BORDER_PAD_X, BORDER_PAD_Y);
    padprintln("Point remote at");
    padprintln("IR sensor and");
    padprintln("press a button.");
    tft.println("");
    padprintln("[ESC] Cancel");
}

static void drawCapturedScreen(decode_type_t proto, uint16_t address, uint16_t command) {
    drawMainBorderWithTitle("CAPTURED!");
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FP);
    tft.setCursor(BORDER_PAD_X, BORDER_PAD_Y);

    char line[32];
    snprintf(line, sizeof(line), "Proto: %s", typeToString(proto).c_str());
    padprintln(line);
    snprintf(line, sizeof(line), "Addr : 0x%04X", address);
    padprintln(line);
    snprintf(line, sizeof(line), "Cmd  : 0x%04X", command);
    padprintln(line);
    tft.println("");
    padprintln("[OK/RIGHT] Start cycle");
    padprintln("[LEFT]  Retry");
    padprintln("[ESC]   Back");
}

static void drawCompletedScreen(uint32_t totalCmds, unsigned long elapsedMs) {
    drawMainBorderWithTitle("COMPLETE!");
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FM);
    tft.setCursor(BORDER_PAD_X, BORDER_PAD_Y);
    padprintln("All commands sent!");
    tft.setTextSize(FP);
    char line[32];
    snprintf(line, sizeof(line), "%lu commands", totalCmds);
    padprintln(line);
    String elapsed = "Time: " + fmtTime(elapsedMs);
    padprintln(elapsed);
    tft.println("");
    padprintln("Any button to exit");
}

// ─── Capture phase ───────────────────────────────────────────────────────────

/**
 * Wait for an IR signal using IRremoteESP8266's IRrecv.
 * Returns true if captured, false if user cancelled.
 */
static bool captureSignal(decode_type_t &proto, uint16_t &address, uint16_t &command) {
    IRrecv irrecv(bruceConfigPins.irRx, SAFE_STACK_BUFFER_SIZE / 2, 50);
    decode_results results;
    irrecv.enableIRIn();
    setup_ir_pin(bruceConfigPins.irRx, INPUT);

    while (true) {
        drawWaitScreen();

        if (check(EscPress)) {
            irrecv.disableIRIn();
            return false;
        }

        if (irrecv.decode(&results)) {
            if (results.decode_type != UNKNOWN && results.value != 0) {
                proto   = results.decode_type;
                address = (uint16_t)(results.address & 0xFFFF);
                command = (uint16_t)(results.command & 0xFFFF);
                irrecv.resume();
                irrecv.disableIRIn();
                return true;
            }
            irrecv.resume();
        }
        delay(10);
    }
}

// ─── Send a single command ────────────────────────────────────────────────────

/**
 * IRremoteESP8266 API: encode first, then send(encodedData, bits).
 * Protocol constants and encode/send methods match the library Bruce uses.
 */
static void sendCycleCommand(IRsend &irsend, decode_type_t proto,
                              uint16_t address, uint16_t command) {
    uint64_t data = 0;
    switch (proto) {
        case NEC:
            data = irsend.encodeNEC(address, command);
            irsend.sendNEC(data, 32);
            break;
        case SONY:
            data = irsend.encodeSony(12, command, address);
            irsend.sendSony(data, 12, 2);
            break;
        case RC5:
            data = irsend.encodeRC5(address, command);
            irsend.sendRC5(data, 13);
            break;
        case RC6:
            data = irsend.encodeRC6(address, command, 4);
            irsend.sendRC6(data, 20);
            break;
        case SAMSUNG:
            data = irsend.encodeSAMSUNG(address, command);
            irsend.sendSAMSUNG(data, 32);
            break;
        case LG:
            data = irsend.encodeLG(address, command);
            irsend.sendLG(data, 28);
            break;
        case PANASONIC:
            // encodePanasonic(manufacturer, device, subdevice, function)
            // Pack address high/low byte into device/subdevice, command into function
            data = irsend.encodePanasonic(
                address,
                (uint8_t)(address & 0xFF),
                (uint8_t)(command >> 8),
                (uint8_t)(command & 0xFF)
            );
            irsend.sendPanasonic64(data, 48);
            break;
        case JVC:
            data = irsend.encodeJVC(address, command);
            irsend.sendJVC(data, 16);
            break;
        case SHARP:
            data = irsend.encodeSharp(address, command);
            irsend.sendSharp(address, command);
            break;
        default:
            // Fallback: send as NEC
            data = irsend.encodeNEC(address, command);
            irsend.sendNEC(data, 32);
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
    decode_type_t proto       = UNKNOWN;
    uint16_t      baseAddress = 0;
    uint16_t      baseCommand = 0;

captureAgain:
    if (!captureSignal(proto, baseAddress, baseCommand)) {
        return;  // user pressed ESC
    }

    // ---- Phase 2: Confirm ----
    drawCapturedScreen(proto, baseAddress, baseCommand);
    SelPress = false; EscPress = false;
    delay(200);

    while (true) {
        if (check(EscPress))  return;
        if (check(PrevPress)) goto captureAgain;
        if (check(SelPress) || check(NextPress)) break;
        delay(25);
    }

    // ---- Phase 3: Cycle ----
    uint32_t      currentCmd = 0;
    uint32_t      delayMs    = SPEED_DEFAULT_MS;
    bool          paused     = false;
    unsigned long startMs    = millis();
    unsigned long lastDraw   = 0;
    bool          done       = false;

    SelPress = false; EscPress = false; NextPress = false; PrevPress = false;
    delay(100);

    while (!done) {
        if (check(EscPress)) break;

        if (check(SelPress)) {
            paused   = !paused;
            lastDraw = 0;
        }

        if (check(NextPress))
            delayMs = max((uint32_t)SPEED_MIN_MS, delayMs - SPEED_STEP_MS);
        if (check(PrevPress))
            delayMs = min((uint32_t)SPEED_MAX_MS, delayMs + SPEED_STEP_MS);

        unsigned long now = millis();
        if (now - lastDraw >= 100) {
            drawCycleScreen(proto, baseAddress, currentCmd,
                            TOTAL_COMMANDS, delayMs, startMs, paused);
            lastDraw = now;
        }

        if (!paused) {
            sendCycleCommand(irsend, proto, baseAddress, (uint16_t)currentCmd);
            currentCmd++;

            if (currentCmd >= TOTAL_COMMANDS) {
                done = true;
                break;
            }

            unsigned long sendDone = millis();
            while (millis() - sendDone < delayMs) {
                if (check(SelPress) || check(EscPress) ||
                    check(NextPress) || check(PrevPress)) break;
                delay(5);
            }
        } else {
            delay(25);
        }
    }

    // ---- Phase 4: Result ----
    if (done) {
        drawCompletedScreen(TOTAL_COMMANDS, millis() - startMs);
        delay(200);
        while (!check(AnyKeyPress)) delay(25);
    }
}
