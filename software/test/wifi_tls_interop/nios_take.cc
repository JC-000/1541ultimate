/*
 * nios_take.cc
 *
 * The Ultimate's own rules for a CMD_TLS_STEP reply, for nios_pump.c: what
 * wifi_tls_take_step() (software/io/wifi/wifi_tls.cc) takes from it, refuses
 * or withholds. That file is free of FreeRTOS calls, so it is linked as it is.
 */

#include "wifi_tls.h"

int wifi_tls_take_step(const uint8_t *reply, int size, uint16_t sequence, wifi_tls_step_t *step);

extern "C" int nios_take_step(const uint8_t *reply, int size, uint16_t sequence, wifi_tls_step_t *step)
{
    return wifi_tls_take_step(reply, size, sequence, step);
}
