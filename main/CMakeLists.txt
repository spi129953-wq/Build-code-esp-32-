idf_component_register(SRCS "main.c" "wifi_scanner.c" "handshake_sniffer.c" "webserver.c"
                    INCLUDE_DIRS "."
                    REQUIRES nvs_flash esp_wifi esp_event esp_http_server spiffs)
