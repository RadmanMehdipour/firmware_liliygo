#include "RFMenu.h"
#include "core/display.h"
#include "core/settings.h"
#include "core/utils.h"
#include "modules/rf/record.h"
#include "modules/rf/rf_bruteforce.h"
#include "modules/rf/rf_jammer.h"
#include "modules/rf/rf_listen.h"
#include "modules/rf/rf_scan.h"
#include "modules/rf/rf_send.h"
#include "modules/rf/rf_utils.h"
#include "modules/rf/rf_spectrum.h"
#include "modules/rf/rf_waterfall.h"



void RFMenu::optionsMenu() {
    options.clear();

    /*
     * RF main menu
     *
     *   - Record Signal
     *   - Transmit
     *   - Attacks
     *   - Sniffers
     *   - Config
     */

    // =========================================================
    // RECORD SIGNAL (top level)
    // =========================================================
    options.push_back({"Record Signal", [=]() { RFScan(); }});

    // =========================================================
    // TRANSMIT (top level)
    // =========================================================
#if !defined(LITE_VERSION)
    options.push_back({"Transmit", sendCustomRF});
#endif

    // =========================================================
    // ATTACKS
    // =========================================================
    options.push_back({"Attacks", [this]() {
                           std::vector<Option> attackOptions;

#if !defined(LITE_VERSION)
                           attackOptions.push_back({"Bruteforce", rf_bruteforce}); // dev_eclipse

                           attackOptions.push_back({"Jammer", [=]() { RFJammer(true); }});
#endif

                           attackOptions.push_back({"Back", [this]() { optionsMenu(); }});

                           loopOptions(attackOptions, MENU_TYPE_SUBMENU, "Attacks");
                       }});


    // =========================================================
    // SNIFFERS
    // =========================================================
    options.push_back({"Sniffers", [this]() {
                           std::vector<Option> snifferOptions;

#if !defined(LITE_VERSION)
                           snifferOptions.push_back({"Record RAW", rf_raw_record}); // Pablo-Ortiz-Lopez

                           snifferOptions.push_back({"Spectrum", rf_spectrum});

                           snifferOptions.push_back({"RSSI Spectrum", rf_CC1101_rssi}); // @Pirata

                           snifferOptions.push_back({"SquareWave Spec", rf_SquareWave}); // @Pirata

                           snifferOptions.push_back({"Spectogram", rf_waterfall}); // dev_eclipse

#if defined(BUZZ_PIN) or defined(HAS_NS4168_SPKR) and defined(RF_LISTEN_H)
                           snifferOptions.push_back({"Listen", rf_listen}); // dev_eclipse
#endif
#else
                           snifferOptions.push_back({"Spectrum", rf_spectrum});
#endif

                           snifferOptions.push_back({"Back", [this]() { optionsMenu(); }});

                           loopOptions(snifferOptions, MENU_TYPE_SUBMENU, "Sniffers");
                       }});


    // =========================================================
    // CONFIG (at the very bottom)
    // =========================================================
    options.push_back({"Config", [this]() { configMenu(); }});

    addOptionToMainMenu();

    delay(200);
    String txt = "Radio Frequency";
    if (bruceConfigPins.rfModule == CC1101_SPI_MODULE) txt += " (CC1101)"; // Indicates if CC1101 is connected
    else txt += " Tx: " + String(bruceConfigPins.rfTx) + " Rx: " + String(bruceConfigPins.rfRx);

    loopOptions(options, MENU_TYPE_SUBMENU, txt.c_str());

    options.clear();
}



void RFMenu::configMenu() {
    options = {
        {"RF TX Pin", lambdaHelper(gsetRfTxPin, true)},
        {"RF RX Pin", lambdaHelper(gsetRfRxPin, true)},
        {"RF Module", setRFModuleMenu},
        {"RF Frequency", setRFFreqMenu},
        {"Back", [this]() { optionsMenu(); }},
    };

    loopOptions(options, MENU_TYPE_SUBMENU, "RF Config");
}

void RFMenu::drawIcon(float scale) {
    clearIconArea();
    int radius = scale * 7;
    int deltaRadius = scale * 10;
    int triangleSize = scale * 30;

    if (triangleSize % 2 != 0) triangleSize++;

    // Body
    tft.fillCircle(iconCenterX, iconCenterY - radius, radius, bruceConfig.priColor);
    tft.fillTriangle(
        iconCenterX,
        iconCenterY,
        iconCenterX - triangleSize / 2,
        iconCenterY + triangleSize,
        iconCenterX + triangleSize / 2,
        iconCenterY + triangleSize,
        bruceConfig.priColor
    );

    // Left Arcs
    tft.drawArc(
        iconCenterX,
        iconCenterY - radius,
        2.5 * radius,
        2 * radius,
        40,
        140,
        bruceConfig.priColor,
        bruceConfig.bgColor
    );
    tft.drawArc(
        iconCenterX,
        iconCenterY - radius,
        2.5 * radius + deltaRadius,
        2 * radius + deltaRadius,
        40,
        140,
        bruceConfig.priColor,
        bruceConfig.bgColor
    );
    tft.drawArc(
        iconCenterX,
        iconCenterY - radius,
        2.5 * radius + 2 * deltaRadius,
        2 * radius + 2 * deltaRadius,
        40,
        140,
        bruceConfig.priColor,
        bruceConfig.bgColor
    );

    // Right Arcs
    tft.drawArc(
        iconCenterX,
        iconCenterY - radius,
        2.5 * radius,
        2 * radius,
        220,
        320,
        bruceConfig.priColor,
        bruceConfig.bgColor
    );
    tft.drawArc(
        iconCenterX,
        iconCenterY - radius,
        2.5 * radius + deltaRadius,
        2 * radius + deltaRadius,
        220,
        320,
        bruceConfig.priColor,
        bruceConfig.bgColor
    );
    tft.drawArc(
        iconCenterX,
        iconCenterY - radius,
        2.5 * radius + 2 * deltaRadius,
        2 * radius + 2 * deltaRadius,
        220,
        320,
        bruceConfig.priColor,
        bruceConfig.bgColor
    );
}
