// ═══════════════════════════════════════════════════════════════════════════
//  IRMenu.cpp — organized into Attacks / Sniffers folders
//
//  Changes vs your updated version:
//   • "IR Cycle" option kept (calls startIrCycle())
//   • Reorganized into Attacks / Sniffers, same style as WiFi/BLE/RF/NRF24
// ═══════════════════════════════════════════════════════════════════════════

#include "IRMenu.h"
#include "core/display.h"
#include "core/settings.h"
#include "core/utils.h"
#include "modules/ir/ir_cycle.h"   // ← your IR Cycle addition
#include "modules/ir/ir_read.h"
#include "modules/ir/ir_jammer.h"
#include "modules/ir/otherIRcodes.h"
#include "modules/ir/tvbgone.h"
// ... keep whatever includes your original file had, plus ir_cycle.h

void IRMenu::optionsMenu() {
#if defined(ARDUINO_M5STICK_S3)
    bool prevPower = M5.Power.getExtOutput();
    M5.Power.setExtOutput(true); // ENABLE 5V OUTPUT
#endif

    options.clear();

    /*
     * Infrared main menu
     *
     *   - Custom IR
     *   - Attacks
     *   - Sniffers
     *   - Config
     */

    // =========================================================
    // CUSTOM IR (top level)
    // =========================================================
    options.push_back({"Custom IR", otherIRcodes});

    // =========================================================
    // ATTACKS
    // =========================================================
    options.push_back({"Attacks", [this]() {
                           std::vector<Option> attackOptions;

                           attackOptions.push_back({"TV-B-Gone", StartTvBGone});

#if !defined(LITE_VERSION)
                           attackOptions.push_back({"IR Cycle", startIrCycle});  // brute-force command scanner

                           attackOptions.push_back({"IR Jammer", startIrJammer});
#endif

                           attackOptions.push_back({"Back", [this]() { optionsMenu(); }});

                           loopOptions(attackOptions, MENU_TYPE_SUBMENU, "Attacks");
                       }});


    // =========================================================
    // SNIFFERS
    // =========================================================
    options.push_back({"Sniffers", [this]() {
                           std::vector<Option> snifferOptions;

                           snifferOptions.push_back({"IR Read", [=]() { IrRead(); }});

                           snifferOptions.push_back({"Back", [this]() { optionsMenu(); }});

                           loopOptions(snifferOptions, MENU_TYPE_SUBMENU, "Sniffers");
                       }});


    // =========================================================
    // CONFIG (at the very bottom)
    // =========================================================
    options.push_back({"Config", [this]() { configMenu(); }});

    addOptionToMainMenu();

    String txt = "Infrared";
    txt += " Tx: " + String(bruceConfigPins.irTx)
         + " Rx: " + String(bruceConfigPins.irRx)
         + " Rpts: " + String(bruceConfigPins.irTxRepeats);

    loopOptions(options, MENU_TYPE_SUBMENU, txt.c_str());

#if defined(ARDUINO_M5STICK_S3)
    M5.Power.setExtOutput(prevPower);
#endif

    options.clear();
}

void IRMenu::configMenu() {
    options = {
        {"Ir TX Pin", lambdaHelper(gsetIrTxPin, true)},
        {"Ir RX Pin", lambdaHelper(gsetIrRxPin, true)},
        {"Ir TX Repeats", setIrTxRepeats},
        {"Back", [this]() { optionsMenu(); }},
    };

    loopOptions(options, MENU_TYPE_SUBMENU, "IR Config");
}

void IRMenu::drawIcon(float scale) {
    clearIconArea();
    int iconSize = scale * 60;
    int radius = scale * 7;
    int deltaRadius = scale * 10;

    if (iconSize % 2 != 0) iconSize++;

    tft.fillRect(
        iconCenterX - iconSize / 2, iconCenterY - iconSize / 2, iconSize / 6, iconSize, bruceConfig.priColor
    );
    tft.fillRect(
        iconCenterX - iconSize / 3,
        iconCenterY - iconSize / 3,
        iconSize / 6,
        2 * iconSize / 3,
        bruceConfig.priColor
    );

    tft.drawCircle(iconCenterX - iconSize / 6, iconCenterY, radius, bruceConfig.priColor);

    tft.drawArc(
        iconCenterX - iconSize / 6,
        iconCenterY,
        2.5 * radius,
        2 * radius,
        220,
        320,
        bruceConfig.priColor,
        bruceConfig.bgColor
    );
    tft.drawArc(
        iconCenterX - iconSize / 6,
        iconCenterY,
        2.5 * radius + deltaRadius,
        2 * radius + deltaRadius,
        220,
        320,
        bruceConfig.priColor,
        bruceConfig.bgColor
    );
    tft.drawArc(
        iconCenterX - iconSize / 6,
        iconCenterY,
        2.5 * radius + 2 * deltaRadius,
        2 * radius + 2 * deltaRadius,
        220,
        320,
        bruceConfig.priColor,
        bruceConfig.bgColor
    );
}
