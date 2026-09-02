/**
 * IRMenu.cpp
 *
 * Organized into Attacks / Sniffers submenus.
 * Includes IR Cycle (brute-force command scanner).
 *
 * Fix applied: replaced non-existent "modules/ir/otherIRcodes.h"
 * with the correct Bruce firmware header "modules/ir/custom_ir.h"
 * which is where otherIRcodes() is actually defined.
 */

#include "IRMenu.h"
#include "core/display.h"
#include "core/settings.h"
#include "core/utils.h"
#include "modules/ir/TV-B-Gone.h"   // StartTvBGone
#include "modules/ir/custom_ir.h"   // otherIRcodes  ← was wrongly "otherIRcodes.h"
#include "modules/ir/ir_cycle.h"    // startIrCycle
#include "modules/ir/ir_jammer.h"   // startIrJammer
#include "modules/ir/ir_read.h"     // IrRead

void IRMenu::optionsMenu() {
#if defined(ARDUINO_M5STICK_S3)
    bool prevPower = M5.Power.getExtOutput();
    M5.Power.setExtOutput(true);
#endif

    options.clear();

    // ── Custom IR (top level) ────────────────────────────────────────────
    options.push_back({"Custom IR", otherIRcodes});

    // ── Attacks submenu ──────────────────────────────────────────────────
    options.push_back({"Attacks", [this]() {
        std::vector<Option> atk;
        atk.push_back({"TV-B-Gone", StartTvBGone});
#if !defined(LITE_VERSION)
        atk.push_back({"IR Cycle",  startIrCycle});
        atk.push_back({"IR Jammer", startIrJammer});
#endif
        atk.push_back({"Back", [this]() { optionsMenu(); }});
        loopOptions(atk, MENU_TYPE_SUBMENU, "Attacks");
    }});

    // ── Sniffers submenu ─────────────────────────────────────────────────
    options.push_back({"Sniffers", [this]() {
        std::vector<Option> snf;
        snf.push_back({"IR Read", [this]() { IrRead(); }});
        snf.push_back({"Back",    [this]() { optionsMenu(); }});
        loopOptions(snf, MENU_TYPE_SUBMENU, "Sniffers");
    }});

    // ── Config ───────────────────────────────────────────────────────────
    options.push_back({"Config", [this]() { configMenu(); }});

    addOptionToMainMenu();

    String txt = "Infrared";
    txt += " Tx: "   + String(bruceConfigPins.irTx)
         + " Rx: "   + String(bruceConfigPins.irRx)
         + " Rpts: " + String(bruceConfigPins.irTxRepeats);

    loopOptions(options, MENU_TYPE_SUBMENU, txt.c_str());

#if defined(ARDUINO_M5STICK_S3)
    M5.Power.setExtOutput(prevPower);
#endif

    options.clear();
}

void IRMenu::configMenu() {
    options = {
        {"Ir TX Pin",     lambdaHelper(gsetIrTxPin, true)},
        {"Ir RX Pin",     lambdaHelper(gsetIrRxPin, true)},
        {"Ir TX Repeats", setIrTxRepeats},
        {"Back",          [this]() { optionsMenu(); }},
    };
    loopOptions(options, MENU_TYPE_SUBMENU, "IR Config");
}

void IRMenu::drawIcon(float scale) {
    clearIconArea();
    int iconSize    = scale * 60;
    int radius      = scale * 7;
    int deltaRadius = scale * 10;
    if (iconSize % 2 != 0) iconSize++;

    tft.fillRect(
        iconCenterX - iconSize / 2,
        iconCenterY - iconSize / 2,
        iconSize / 6, iconSize,
        bruceConfig.priColor
    );
    tft.fillRect(
        iconCenterX - iconSize / 3,
        iconCenterY - iconSize / 3,
        iconSize / 6, 2 * iconSize / 3,
        bruceConfig.priColor
    );
    tft.drawCircle(iconCenterX - iconSize / 6, iconCenterY, radius, bruceConfig.priColor);
    tft.drawArc(
        iconCenterX - iconSize / 6, iconCenterY,
        2.5 * radius, 2 * radius, 220, 320,
        bruceConfig.priColor, bruceConfig.bgColor
    );
    tft.drawArc(
        iconCenterX - iconSize / 6, iconCenterY,
        2.5 * radius + deltaRadius, 2 * radius + deltaRadius, 220, 320,
        bruceConfig.priColor, bruceConfig.bgColor
    );
    tft.drawArc(
        iconCenterX - iconSize / 6, iconCenterY,
        2.5 * radius + 2 * deltaRadius, 2 * radius + 2 * deltaRadius, 220, 320,
        bruceConfig.priColor, bruceConfig.bgColor
    );
}
