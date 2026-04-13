#ifndef WIFI_SCANNER_H
#define WIFI_SCANNER_H

#include <stdint.h>
#include <stdbool.h>
#include "main.h"

void wifi_scanner_init(void);
int wifi_scanner_scan_all(wifi_ap_info_t *ap_list, int max_ap);
bool wifi_scanner_select_target_by_index(int index, wifi_ap_info_t *target);

#endif
