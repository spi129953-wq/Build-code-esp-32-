#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_spiffs.h"
#include "main.h"
#include "wifi_scanner.h"
#include "webserver.h"

static const char *TAG = "MAIN";

wifi_ap_info_t g_ap_list[50];
int g_ap_count = 0;
wifi_ap_info_t g_target_ap;
bool g_sniffer_running = false;
int g_eapol_count = 0;
bool g_got_msg1 = false, g_got_msg2 = false, g_got_msg3 = false, g_got_msg4 = false;

// Mount SPIFFS để lưu web files
static void mount_spiffs(void) {
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = true
    };
    
    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount SPIFFS");
    } else {
        ESP_LOGI(TAG, "SPIFFS mounted successfully");
    }
}

void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    mount_spiffs();
    
    ESP_LOGI(TAG, "=========================================");
    ESP_LOGI(TAG, "   ESP32 WiFi Pentest Tool v2.0");
    ESP_LOGI(TAG, "   Web: http://192.168.4.1");
    ESP_LOGI(TAG, "=========================================");
    
    wifi_scanner_init();
    start_webserver();
    
    ESP_LOGI(TAG, "Connect to WiFi: %s / %s", AP_SSID, AP_PASS);
    ESP_LOGI(TAG, "Then open browser: http://192.168.4.1");
}
