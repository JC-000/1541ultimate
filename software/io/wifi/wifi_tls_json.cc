/*
 * wifi_tls_json.cc
 *
 * SPIKE CODE, NOT FOR RELEASE (esp-tls M2). See wifi_tls_json.h.
 */

#ifdef TLS_SPIKE

#include "json.h"
#include "wifi_tls_json.h"

// heap_free, heap_min_ever, largest_block, stack_free and sessions_open;
// zeros when the STATS call failed, which detail.have_* tells.
static void add_tls_heap(JSON_Object *obj, const char *key, const wifi_tls_stats_t &s)
{
    JSON_Object *heap = JSON::Obj();
    heap->add("heap_free", (int)s.heap_free);
    heap->add("heap_min_ever", (int)s.heap_min_ever);
    heap->add("largest_block", (int)s.largest_block);
    heap->add("stack_free", (int)s.stack_free);
    heap->add("sessions_open", (int)s.sessions_open);
    obj->add(key, heap);
}

void wifi_tls_spike_json(const wifi_tls_spike_result_t *r, JSON_Object *json)
{
    static const char *const time_sources[] = { "none", "nios", "sntp" };
    json->add("ok", r->ok);
    json->add("stage", r->stage);
    json->add("error", r->error);
    json->add("handshake_ms", (int)r->handshake_ms);
    json->add("open_ms", (int)r->open_ms);
    json->add("handshake_us", (int)r->peak.handshake_us);
    add_tls_heap(json, "stats_before", r->before);
    add_tls_heap(json, "stats_peak", r->peak);
    add_tls_heap(json, "stats_after", r->after);
    json->add("tls_version", (int)r->peak.tls_version);
    json->add("ciphersuite", (int)r->peak.ciphersuite);
    json->add("group", (int)r->peak.group);
    json->add("echo_sent", r->echo_sent);
    json->add("echo_received", r->echo_received);
    json->add("echo_ok", r->echo_ok);
    json->add("steps", r->steps);
    // From the STATS right after OPEN, so that a handshake that fails still
    // says which clock the module verified with.
    bool known = r->have_opened && (r->opened.time_source < 3);
    json->add("time_source", known ? time_sources[r->opened.time_source] : "none");
    json->add("esp_time", r->have_opened ? (int)r->opened.esp_time : 0);
    json->add("step_max_ms", (int)r->step_max_ms);
    // -1 when the last STATS failed: not knowing is not zero.
    json->add("sessions_open_after", r->have_after ? (int)r->after.sessions_open : -1);

    // Everything else, for diagnosis.
    JSON_Object *detail = JSON::Obj();
    detail->add("where", r->detail ? r->detail : "");
    detail->add("code", r->code);
    detail->add("esp_err", r->esp_err);
    detail->add("state", r->state);
    detail->add("handshake_steps", r->handshake_steps);
    detail->add("resends", r->resends);
    detail->add("have_before", r->have_before);
    detail->add("have_opened", r->have_opened);
    detail->add("have_peak", r->have_peak);
    detail->add("have_after", r->have_after);
    detail->add("stats_error", r->stats_error);
    detail->add("unix_time_sent", (int)r->unix_time);
    detail->add("nios_clock", r->nios_clock ? r->nios_clock : "none");
    detail->add("tcp_out", (int)r->tcp_out);
    detail->add("tcp_in", (int)r->tcp_in);
    detail->add("early_plaintext", r->early_plaintext);
    detail->add("session_opened", r->session_opened);
    detail->add("close_result", r->close_result);
    detail->add("socket_opened", r->socket_opened);
    json->add("detail", detail);
}

#endif
