#include "BleMenu.h"
#include "core/display.h"
#include "core/utils.h"
#include "modules/badusb_ble/ducky_typer.h"
#include "modules/ble/ble_common.h"
#include "modules/ble/ble_ninebot.h"
#include "modules/ble/ble_spam.h"
#if !defined(LITE_VERSION)
#include "modules/ble/BLE_Suite.h"
#else
#include "modules/ble/ble_sniffer.h"
#endif
#include <globals.h>
void BleMenu::optionsMenu() {
    options.clear();

    /*
     * Bluetooth main menu
     *
     *   - Attacks
     *   - Sniffers
     *   - General
     */

    // =========================================================
    // ATTACKS
    // =========================================================
    options.push_back({"Attacks", [this]() {
                           std::vector<Option> attackOptions;

#if !defined(LITE_VERSION)
                           attackOptions.push_back({"Bad BLE", [=]() {
                                                        ducky_setup(hid_ble, true);
                                                    }});
#endif

                           attackOptions.push_back({"BLE Spam", [=]() { spamMenu(); }});

#if !defined(LITE_VERSION)
                           attackOptions.push_back({"Ninebot", [=]() { BLENinebot(); }});
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
                           snifferOptions.push_back({"BLE Scan", ble_scan});

                           snifferOptions.push_back({"BLE Suite", [=]() { BleSuiteMenu(); }});
#else
                           snifferOptions.push_back({"BLE Sniffer", [=]() { BLE_SnifferMenu(); }});
#endif

                           snifferOptions.push_back({"Back", [this]() { optionsMenu(); }});

                           loopOptions(snifferOptions, MENU_TYPE_SUBMENU, "Sniffers");
                       }});


    // =========================================================
    // GENERAL
    // =========================================================
    options.push_back({"General", [this]() {
                           std::vector<Option> generalOptions;

                           /*
                            * Connection control
                            */
#if !defined(LITE_VERSION)
                           if (BLEConnected) {
                               generalOptions.push_back({"Disconnect", [=]() {
                                                             BLEDevice::deinit();
                                                             BLEConnected = false;
                                                             delete hid_ble;
                                                             hid_ble = nullptr;
                                                         }});
                           }
#endif

                           /*
                            * HID / utility tools
                            */
#if !defined(LITE_VERSION)
                           generalOptions.push_back({"Media Cmds", [=]() {
                                                         MediaCommands(hid_ble, true);
                                                     }});

                           generalOptions.push_back({"BLE Keyboard", [=]() {
                                                         ducky_keyboard(hid_ble, true);
                                                     }});

                           generalOptions.push_back({"Presenter mode", [=]() {
                                                         PresenterMode(hid_ble, true);
                                                     }});
#endif

                           generalOptions.push_back({"iBeacon", [=]() {
                                                         ibeacon(
                                                             "Bruce",
                                                             "e4c159a0-8c82-11e6-bdf4-0800200c9a66",
                                                             0x004C
                                                         );
                                                     }});

                           generalOptions.push_back({"Back", [this]() { optionsMenu(); }});

                           loopOptions(generalOptions, MENU_TYPE_SUBMENU, "General");
                       }});


    /*
     * Keep Bruce normal return-to-main-menu behaviour
     */
    addOptionToMainMenu();

    loopOptions(options, MENU_TYPE_SUBMENU, "Bluetooth", 0, false);

    options.clear();
}
void BleMenu::drawIcon(float scale) {
    clearIconArea();

    int lineWidth = scale * 5;
    int iconW = scale * 36;
    int iconH = scale * 60;
    int radius = scale * 5;
    int deltaRadius = scale * 10;

    if (iconW % 2 != 0) iconW++;
    if (iconH % 4 != 0) iconH += 4 - (iconH % 4);

    tft.drawWideLine(
        iconCenterX,
        iconCenterY + iconH / 4,
        iconCenterX - iconW,
        iconCenterY - iconH / 4,
        lineWidth,
        bruceConfig.priColor,
        bruceConfig.priColor
    );
    tft.drawWideLine(
        iconCenterX,
        iconCenterY - iconH / 4,
        iconCenterX - iconW,
        iconCenterY + iconH / 4,
        lineWidth,
        bruceConfig.priColor,
        bruceConfig.priColor
    );
    tft.drawWideLine(
        iconCenterX,
        iconCenterY + iconH / 4,
        iconCenterX - iconW / 2,
        iconCenterY + iconH / 2,
        lineWidth,
        bruceConfig.priColor,
        bruceConfig.priColor
    );
    tft.drawWideLine(
        iconCenterX,
        iconCenterY - iconH / 4,
        iconCenterX - iconW / 2,
        iconCenterY - iconH / 2,
        lineWidth,
        bruceConfig.priColor,
        bruceConfig.priColor
    );

    tft.drawWideLine(
        iconCenterX - iconW / 2,
        iconCenterY - iconH / 2,
        iconCenterX - iconW / 2,
        iconCenterY + iconH / 2,
        lineWidth,
        bruceConfig.priColor,
        bruceConfig.priColor
    );

    tft.drawArc(
        iconCenterX,
        iconCenterY,
        2.5 * radius,
        2 * radius,
        210,
        330,
        bruceConfig.priColor,
        bruceConfig.bgColor
    );
    tft.drawArc(
        iconCenterX,
        iconCenterY,
        2.5 * radius + deltaRadius,
        2 * radius + deltaRadius,
        210,
        330,
        bruceConfig.priColor,
        bruceConfig.bgColor
    );
    tft.drawArc(
        iconCenterX,
        iconCenterY,
        2.5 * radius + 2 * deltaRadius,
        2 * radius + 2 * deltaRadius,
        210,
        330,
        bruceConfig.priColor,
        bruceConfig.bgColor
    );
}
