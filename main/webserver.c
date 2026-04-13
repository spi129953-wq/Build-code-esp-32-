#include "webserver.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include "cJSON.h"
#include "main.h"
#include "wifi_scanner.h"
#include "handshake_sniffer.h"
#include <string.h>

static const char *TAG = "WEBSERVER";
static httpd_handle_t server = NULL;

// HTML giao diện chính
static const char *INDEX_HTML = 
"<!DOCTYPE html>"
"<html><head><title>ESP32 WiFi Tool</title>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<style>"
"body{font-family:Arial;background:#1a1a2e;color:#eee;padding:20px}"
"h1{color:#e94560}"
".container{max-width:800px;margin:0 auto}"
"button{background:#e94560;color:#fff;border:none;padding:10px 20px;margin:5px;border-radius:5px;cursor:pointer}"
"button:hover{background:#ff6b6b}"
"table{width:100%;border-collapse:collapse;margin:20px 0}"
"th,td{padding:10px;text-align:left;border-bottom:1px solid #444}"
"th{background:#16213e}"
".status{background:#0f3460;padding:15px;border-radius:10px;margin:20px 0}"
".wifi-row{cursor:pointer}"
".wifi-row:hover{background:#0f3460}"
"</style></head>"
"<body><div class='container'>"
"<h1>🔐 ESP32 WiFi Pentest Tool</h1>"
"<div class='status' id='status'>"
"<h3>Status: <span id='snifferStatus'>Idle</span></h3>"
"<p>Packets: <span id='packetCount'>0</span></p>"
"<p>Handshake: M1: <span id='msg1'>❌</span> M2: <span id='msg2'>❌</span> M3: <span id='msg3'>❌</span> M4: <span id='msg4'>❌</span></p>"
"</div>"
"<button onclick='scanWiFi()'>📡 Scan WiFi</button>"
"<button onclick='stopSniffer()'>🛑 Stop Sniffer</button>"
"<button onclick='exportPCAP()'>💾 Export PCAP</button>"
"<div id='wifiList'></div>"
"</div>"
"<script>"
"let targetSSID='';"
"function scanWiFi(){"
"fetch('/api/scan').then(r=>r.json()).then(data=>{"
"let html='<h2>WiFi Networks</h2><table><tr><th>SSID</th><th>RSSI</th><th>Channel</th><th>Security</th></tr>';"
"data.forEach((w,i)=>{"
"html+=`<tr class='wifi-row' onclick='selectTarget(${i})'><td>${w.ssid}</td><td>${w.rssi}</td><td>${w.channel}</td><td>${w.auth}</td></tr>`;"
"});"
"html+='</table>';"
"document.getElementById('wifiList').innerHTML=html;"
"});}"
"function selectTarget(i){"
"fetch('/api/select?index='+i).then(r=>r.json()).then(data=>{"
"targetSSID=data.ssid;"
"alert('Selected: '+data.ssid);"
"startSniffer();"
"});}"
"function startSniffer(){"
"fetch('/api/start').then(r=>r.json()).then(data=>{"
"updateStatus();"
"});}"
"function stopSniffer(){"
"fetch('/api/stop').then(r=>r.json()).then(data=>{"
"updateStatus();"
"});}"
"function updateStatus(){"
"fetch('/api/status').then(r=>r.json()).then(data=>{"
"document.getElementById('snifferStatus').innerText=data.running?'Running':'Stopped';"
"document.getElementById('packetCount').innerText=data.packets;"
"document.getElementById('msg1').innerHTML=data.msg1?'✅':'❌';"
"document.getElementById('msg2').innerHTML=data.msg2?'✅':'❌';"
"document.getElementById('msg3').innerHTML=data.msg3?'✅':'❌';"
"document.getElementById('msg4').innerHTML=data.msg4?'✅':'❌';"
"if(data.running)setTimeout(updateStatus,1000);"
"});}"
"function exportPCAP(){"
"fetch('/api/export').then(r=>r.blob()).then(blob=>{"
"let a=document.createElement('a');"
"a.href=URL.createObjectURL(blob);"
"a.download='handshake.pcap';"
"a.click();"
"});}"
"</script></body></html>";

// API: Scan WiFi
static esp_err_t api_scan_handler(httpd_req_t *req) {
    g_ap_count = wifi_scanner_scan_all(g_ap_list, 50);
    
    char *json = malloc(4096);
    strcpy(json, "[");
    for (int i = 0; i < g_ap_count; i++) {
        char buf[256];
        const char *auth = "OPEN";
        if (g_ap_list[i].auth_mode == WIFI_AUTH_WPA2_PSK) auth = "WPA2";
        else if (g_ap_list[i].auth_mode == WIFI_AUTH_WPA3_PSK) auth = "WPA3";
        
        snprintf(buf, sizeof(buf), 
                "{\"ssid\":\"%s\",\"rssi\":%d,\"channel\":%d,\"auth\":\"%s\"}%s",
                g_ap_list[i].ssid, g_ap_list[i].rssi, g_ap_list[i].channel, auth,
                (i < g_ap_count - 1) ? "," : "");
        strcat(json, buf);
    }
    strcat(json, "]");
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));
    free(json);
    return ESP_OK;
}

// API: Chọn mục tiêu
static esp_err_t api_select_handler(httpd_req_t *req) {
    char buf[10];
    if (httpd_req_get_url_query_str(req, buf, sizeof(buf)) == ESP_OK) {
        char index_str[5];
        if (httpd_query_key_value(buf, "index", index_str, sizeof(index_str)) == ESP_OK) {
            int index = atoi(index_str);
            if (index >= 0 && index < g_ap_count) {
                memcpy(&g_target_ap, &g_ap_list[index], sizeof(wifi_ap_info_t));
                handshake_sniffer_init(&g_target_ap);
                
                char json[128];
                snprintf(json, sizeof(json), "{\"ssid\":\"%s\",\"channel\":%d}", 
                        g_target_ap.ssid, g_target_ap.channel);
                httpd_resp_set_type(req, "application/json");
                httpd_resp_send(req, json, strlen(json));
                return ESP_OK;
            }
        }
    }
    httpd_resp_send_500(req);
    return ESP_FAIL;
}

// API: Bắt đầu sniffer
static esp_err_t api_start_handler(httpd_req_t *req) {
    handshake_sniffer_start();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"status\":\"started\"}", 18);
    return ESP_OK;
}

// API: Dừng sniffer
static esp_err_t api_stop_handler(httpd_req_t *req) {
    handshake_sniffer_stop();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"status\":\"stopped\"}", 18);
    return ESP_OK;
}

// API: Lấy trạng thái
static esp_err_t api_status_handler(httpd_req_t *req) {
    char status[512];
    handshake_sniffer_get_status(status, sizeof(status));
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, status, strlen(status));
    return ESP_OK;
}

// API: Xuất PCAP
static esp_err_t api_export_handler(httpd_req_t *req) {
    char *hex_data = malloc(65536);
    handshake_sniffer_get_hex_data(hex_data, 65536);
    
    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=handshake.json");
    httpd_resp_send(req, hex_data, strlen(hex_data));
    
    free(hex_data);
    return ESP_OK;
}

// Trang chủ
static esp_err_t index_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, INDEX_HTML, strlen(INDEX_HTML));
    return ESP_OK;
}

// Khởi động WiFi AP
static void start_wifi_ap(void) {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    
    wifi_config_t ap_config = {
        .ap = {
            .ssid = AP_SSID,
            .password = AP_PASS,
            .ssid_len = strlen(AP_SSID),
            .channel = 1,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .max_connection = 4
        }
    };
    
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());
}

void start_webserver(void) {
    start_wifi_ap();
    
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    
    httpd_uri_t uri_index = { .uri = "/", .method = HTTP_GET, .handler = index_handler };
    httpd_uri_t uri_scan = { .uri = "/api/scan", .method = HTTP_GET, .handler = api_scan_handler };
    httpd_uri_t uri_select = { .uri = "/api/select", .method = HTTP_GET, .handler = api_select_handler };
    httpd_uri_t uri_start = { .uri = "/api/start", .method = HTTP_GET, .handler = api_start_handler };
    httpd_uri_t uri_stop = { .uri = "/api/stop", .method = HTTP_GET, .handler = api_stop_handler };
    httpd_uri_t uri_status = { .uri = "/api/status", .method = HTTP_GET, .handler = api_status_handler };
    httpd_uri_t uri_export = { .uri = "/api/export", .method = HTTP_GET, .handler = api_export_handler };
    
    ESP_ERROR_CHECK(httpd_start(&server, &config));
    httpd_register_uri_handler(server, &uri_index);
    httpd_register_uri_handler(server, &uri_scan);
    httpd_register_uri_handler(server, &uri_select);
    httpd_register_uri_handler(server, &uri_start);
    httpd_register_uri_handler(server, &uri_stop);
    httpd_register_uri_handler(server, &uri_status);
    httpd_register_uri_handler(server, &uri_export);
}
