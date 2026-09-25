/*
 * wifi_tls_json.h
 *
 * SPIKE CODE, NOT FOR RELEASE (esp-tls M2). The JSON that
 * PUT /v1/machine:tlsspike answers with, built apart from the route so that
 * the host harness renders the very same object into the golden files
 * (tests/e2e/io/wifi/golden/).
 */

#ifndef WIFI_TLS_JSON_H_
#define WIFI_TLS_JSON_H_

#ifdef TLS_SPIKE
#include "wifi_tls.h"

class JSON_Object;

// Adds the spike's result to json, by the names and types of M2 spec
// sections 7, 9 and 17.
void wifi_tls_spike_json(const wifi_tls_spike_result_t *r, JSON_Object *json);
#endif

#endif /* WIFI_TLS_JSON_H_ */
