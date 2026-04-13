#ifndef MAIN_H
#define MAIN_H

#include <stdint.h>
#include <stdbool.h>

#define AP_SSID "ESP32_WiFi_Tool"
#define AP_PASS "12345678"

typedef struct {
    char ssid[33];
    uint8_t bssid[6];
    int8_t rssi;
    uint8_t channel;
    uint8_t auth_mode;
    bool is_wpa3;
} wifi_ap_info_t;

extern wifi_ap_info_t g_ap_list[50];
extern int g_ap_count;
extern wifi_ap_info_t g_target_ap;
extern bool g_sniffer_running;
extern int g_eapol_count;
extern bool g_got_msg1, g_got_msg2, g_got_msg3, g_got_msg4;

// Hàm bắt đầu sniffer
void start_sniffer_task(wifi_ap_info_t *target);
void stop_sniffer(void);

#endif
