/* tls_rng_gate.c: see tls_rng_gate.h. Linked in with -Wl,--wrap=mbedtls_psa_external_get_random. */
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "psa/crypto.h"
#include "radio_entropy.h"
#include "tls_rng_gate.h"

psa_status_t __real_mbedtls_psa_external_get_random(mbedtls_psa_external_random_context_t *context, uint8_t *output,
                                                    size_t output_size, size_t *output_length);

static TaskHandle_t tls_task;      // set once by the TLS task itself
static volatile int refused;       // written and read by the TLS task only

void tls_rng_gate_bind_task(void)
{
    tls_task = xTaskGetCurrentTaskHandle();
}

int tls_rng_gate_take_refusal(void)
{
    int was = refused;
    refused = 0;
    return was;
}

psa_status_t __wrap_mbedtls_psa_external_get_random(mbedtls_psa_external_random_context_t *context, uint8_t *output,
                                                    size_t output_size, size_t *output_length)
{
    if ((tls_task == NULL) || (xTaskGetCurrentTaskHandle() != tls_task)) {
        return __real_mbedtls_psa_external_get_random(context, output, output_size, output_length);
    }
    // No lock, queue or UART is held or waited for in here: the hold is one draw. The wait covers a voltage read (the
    // ADC source is off for it, RE_WAIT_ADC_MS at most), so the read every 10 s delays a draw and does not fail it; a
    // radio change holds the gate longer and the source is off through it, so a draw then fails.
    int rc = radio_entropy_acquire_shared(RE_WAIT_ADC_MS);
    if (rc != RE_OK) {
        refused = 1;
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    }
    if (entropy_source() == ENTROPY_NONE) {
        radio_entropy_release_shared();
        refused = 1;
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    }
    psa_status_t status = __real_mbedtls_psa_external_get_random(context, output, output_size, output_length);
    radio_entropy_release_shared();
    return status;
}
