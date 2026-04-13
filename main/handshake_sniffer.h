#ifndef HANDSHAKE_SNIFFER_H
#define HANDSHAKE_SNIFFER_H

#include "main.h"

void handshake_sniffer_init(wifi_ap_info_t *target);
void handshake_sniffer_start(void);
void handshake_sniffer_stop(void);
bool handshake_sniffer_is_complete(void);
void handshake_sniffer_get_status(char *buffer, int buffer_size);
void handshake_sniffer_get_hex_data(char *buffer, int buffer_size);

#endif
