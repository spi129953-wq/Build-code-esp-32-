#include "wifi_scanner.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "WIFI_SCANNER";

void wifi_scanner_init(void) {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "WiFi Scanner ready");
}

int wifi_scanner_scan_all(wifi_ap_info_t *ap_list, int max_ap) {
    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = { .active = { .min = 100, .max = 300 } }
    };
    
    ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_config, true));
    
    uint16_t ap_count = 0;
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));
    if (ap_count == 0) return 0;
    if (ap_count > max_ap) ap_count = max_ap;
    
    wifi_ap_record_t *records = malloc(sizeof(wifi_ap_record_t) * ap_count);
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&ap_count, records));
    
    for (int i = 0; i < ap_count; i++) {
        memset(ap_list[i].ssid, 0, 33);
        memcpy(ap_list[i].ssid, records[i].ssid, 32);
        memcpy(ap_list[i].bssid, records[i].bssid, 6);
        ap_list[i].rssi = records[i].rssi;
        ap_list[i].channel = records[i].primary;
        ap_list[i].auth_mode = records[i].authmode;
        ap_list[i].is_wpa3 = (records[i].authmode == WIFI_AUTH_WPA3_PSK);
    }
    
    free(records);
    
    // Sắp xếp theo RSSI
    for (int i = 0; i < ap_count - 1; i++) {
        for (int j = i + 1; j < ap_count; j++) {
            if (ap_list[i].rssi < ap_list[j].rssi) {
                wifi_ap_info_t temp = ap_list[i];
                ap_list[i] = ap_list[j];
                ap_list[j] = temp;
            }
        }
    }
    
    return ap_count;
}

bool wifi_scanner_select_target_by_index(int index, wifi_ap_info_t *target) {
    if (index < 0 || index >= g_ap_count) return false;
    memcpy(target, &g_ap_list[index], sizeof(wifi_ap_info_t));
    return true;
}
