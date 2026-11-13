/* tls_rng_gate.h: keeps the radio's entropy source on for the draws of the TLS task.
 *
 * mbedTLS 4 draws every random byte through mbedtls_psa_external_get_random() (MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG), which
 * is esp_fill_random() here. esp_fill_random() is random only while the radio runs or the ADC source is on, and a radio
 * start or stop or a read of the voltages switches the source off (radio_entropy.h). The module's link wraps that function
 * (-Wl,--wrap=mbedtls_psa_external_get_random, in the component's CMakeLists.txt) with tls_rng_gate.c:
 *  - a draw made on the TLS task holds the entropy gate shared for that one draw, which is microseconds, so a radio change
 *    never waits for ECC or RSA work; with no source, or no gate within RE_WAIT_ADC_MS (50 ms, the longest a voltage read may hold it), the draw fails with
 *    PSA_ERROR_INSUFFICIENT_ENTROPY and the engine ends the session with TLS_FAIL_NO_ENTROPY;
 *  - a draw made on any other task passes straight through, so the Wi-Fi stack's draws are never held up by it.
 */
#ifndef SOFTWARE_WIFI_TLS_TLS_RNG_GATE_H_
#define SOFTWARE_WIFI_TLS_TLS_RNG_GATE_H_

// The TLS task, once, before it serves its first command: its draws are the ones that are gated
void tls_rng_gate_bind_task(void);

// 1 once if a draw was refused since the last call (no source, or the gate not free in time), and clears it
int tls_rng_gate_take_refusal(void);

#endif /* SOFTWARE_WIFI_TLS_TLS_RNG_GATE_H_ */
