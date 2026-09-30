import os, subprocess, sys, tempfile, shutil
# Writes mutants/NAME.patch for every mutant below, against the current main/. Run it after changing main/.
RAW = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
E, D = 'main/tls_engine.c', 'main/rpc_dispatch.c'
M = {
 # name: [(file, old, new)], killer
 'no_read_ignored': [(E, '!just_established && !(flags & TLS_STEP_NO_READ) &&', '!just_established &&')],
 'no_read_only_with_pt': [(E, '!just_established && !(flags & TLS_STEP_NO_READ) &&', '!just_established && !((flags & TLS_STEP_NO_READ) && pt_in_len) &&')],
 'warning_alert_stall': [(E, '''        } else if ((n == MBEDTLS_ERR_SSL_WANT_READ) && (s->in_off > in_before) && (s->in_off < s->in_len)) {
            // A record mbedTLS skipped''', '''        } else if (0) {
            // A record mbedTLS skipped''')],
 'tag_only_on_close': [(E, '''static tls_session_t *tls_find(uint8_t slot, uint16_t tag)
{
    if (slot >= TLS_MAX_SESSIONS) {
        return NULL;
    }
    tls_session_t *s = sessions[slot];
    return (s && (s->tag == tag)) ? s : NULL;
}''', '''static tls_session_t *tls_find(uint8_t slot, uint16_t tag)
{
    if (slot >= TLS_MAX_SESSIONS) {
        return NULL;
    }
    return sessions[slot];
}
static tls_session_t *tls_find_close(uint8_t slot, uint16_t tag)
{
    if (slot >= TLS_MAX_SESSIONS) {
        return NULL;
    }
    tls_session_t *s = sessions[slot];
    return (s && (s->tag == tag)) ? s : NULL;
}'''), (E, '''    *ct_out_len = 0;
    tls_session_t *s = tls_find(slot, tag);''', '''    *ct_out_len = 0;
    tls_session_t *s = tls_find_close(slot, tag);''')],
 'no_ca_tag_check': [(E, '!(custom_ca && (p->ca_tag != 0) && (custom_ca->tag == p->ca_tag))', '!custom_ca')],
 'pin_gated_nonzero': [(E, '''        *flags = 0;
        if ((depth == 0) && (!hashed''', '''        *flags = 0;
        static const uint8_t zero[TLS_PIN_LEN];
        if ((depth == 0) && memcmp(s->pin, zero, TLS_PIN_LEN) && (!hashed''')],
 'pin_compare_stubbed': [(E, '(!hashed || memcmp(s->stats.spki_sha256, s->pin, TLS_PIN_LEN) != 0)', '!hashed')],
 'verify_on_conf_before_attach': [(E, '''        if (p->trust == TLS_TRUST_BUNDLE) {
            ret = esp_crt_bundle_attach(&s->conf);''', '''        if (p->trust == TLS_TRUST_BUNDLE) {
            mbedtls_ssl_conf_verify(&s->conf, tls_verify, s);
            ret = esp_crt_bundle_attach(&s->conf);'''), (E, '''    mbedtls_ssl_set_verify(&s->ssl, tls_verify, s);''', '''    if (p->trust != TLS_TRUST_BUNDLE) {
        mbedtls_ssl_set_verify(&s->ssl, tls_verify, s);
    }''')],
 'custom_via_bundle': [(E, '''            mbedtls_ssl_conf_ca_chain(&s->conf, &s->ca->crt, NULL);''', '''            mbedtls_ssl_conf_ca_chain(&s->conf, &s->ca->crt, NULL);
            ret = esp_crt_bundle_attach(&s->conf);''')],
 'verify_accepts_all': [(E, '''    default: // CUSTOM: mbedTLS's own chain verification against the uploaded CA
        break;
    }
    return 0;''', '''    default: // CUSTOM: mbedTLS's own chain verification against the uploaded CA
        break;
    }
    *flags = 0;
    return 0;''')],
 'no_ciphersuite_list': [(E, '        mbedtls_ssl_conf_ciphersuites(&s->conf, tls_ciphersuites);\n', '')],
 'cbc_suite_added': [(E, '    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,\n    0\n', '    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,\n    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,\n    0\n')],
 'no_group_list': [(E, '        mbedtls_ssl_conf_groups(&s->conf, tls_groups);\n', '')],
 'tickets_12_on': [(E, '        mbedtls_ssl_conf_session_tickets(&s->conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);\n', '')],
 'ems_not_required': [(E, '            if (!s->stats.ems) {\n                ESP_LOGW', '            if (0) {\n                ESP_LOGW')],
 'ems_any_extension': [(E, 's->stats.ems = (tls_sh_ext(m, len, 23, &d) == 0);', 's->stats.ems = 1;')],
 'require13_ignored': [(E, '(p->opts & TLS_OPT_REQUIRE_TLS13) ? MBEDTLS_SSL_VERSION_TLS1_3', '0 ? MBEDTLS_SSL_VERSION_TLS1_3')],
 'group_left_0': [(E, '                s->stats.group = (d[0] << 8) | d[1];', '                (void)d;'), (E, '        s->stats.group = (m[5] << 8) | m[6];', '        (void)m;')],
 'sentinel_unclassified': [(E, '            r->fail_reason = TLS_FAIL_DOWNGRADE;', '            r->fail_reason = TLS_FAIL_NONE;')],
 'sentinel_any_state': [(E, '''    } else if ((state_before == MBEDTLS_SSL_SERVER_HELLO) && (version_before == MBEDTLS_SSL_VERSION_TLS1_3) &&
               (ret == MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER)) {''', '''    } else if (ret == MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER) {''')],
 'ca_freed_on_replace': [(E, '''static void tls_ca_release(tls_ca_t *ca)
{
    if (ca && (--ca->refs == 0)) {''', '''static void tls_ca_release(tls_ca_t *ca)
{
    if (ca) {''')],
 'no_takeover': [(E, '''    if (sessions[slot]) {
        ESP_LOGW(TAG, "OPEN into slot %d frees the session held there under tag %u", slot, sessions[slot]->tag);
        tls_free(sessions[slot]);
    }''', '''    if (sessions[slot]) {
        return ESP_ERR_INVALID_STATE;
    }''')],
 'pt_on_established_step': [(E, '            just_established = (s->stats.state == TLS_STATE_ESTABLISHED);', '            (void)0;')],
 'no_close_notify': [(E, '        mbedtls_ssl_close_notify(&s->ssl);\n', '')],
 'close_all_keeps_ca': [(E, '''    tls_ca_release(custom_ca);
    custom_ca = NULL;
}

// 3.3''', '''}

// 3.3''')],
 'set_ca_keeps_old_on_error': [(E, '''    *reject = TLS_CA_REJECT_NONE;
    // The one held is dropped first: on any error none is held (a session keeps its own reference)
    tls_ca_release(custom_ca);
    custom_ca = NULL;''', '''    *reject = TLS_CA_REJECT_NONE;'''), (E, '''    custom_ca = ca;
    return ESP_OK;''', '''    tls_ca_release(custom_ca);
    custom_ca = ca;
    return ESP_OK;''')],
 'ca_no_keyusage_clause': [(E, '''    if (((crt->version >= 3) && (mbedtls_x509_crt_get_ca_istrue(crt) != 1)) ||
        (mbedtls_x509_crt_check_key_usage(crt, MBEDTLS_X509_KU_KEY_CERT_SIGN) != 0)) {''', '''    if ((crt->version >= 3) && (mbedtls_x509_crt_get_ca_istrue(crt) != 1)) {''')],
 'ca_ku_bits_without_presence': [(E, '(mbedtls_x509_crt_check_key_usage(crt, MBEDTLS_X509_KU_KEY_CERT_SIGN) != 0)', '!(crt->key_usage & MBEDTLS_X509_KU_KEY_CERT_SIGN)')],
 'ca_v1_refused': [(E, '((crt->version >= 3) && (mbedtls_x509_crt_get_ca_istrue(crt) != 1))', '(mbedtls_x509_crt_get_ca_istrue(crt) != 1)')],
 'ca_no_curve_check': [(E, '            return TLS_CA_REJECT_CURVE;', '            (void)0;')],
 'ca_precedence_notca_first': [(E, '''    psa_key_type_t type = mbedtls_pk_get_key_type(&crt->pk);''', '''    if ((crt->version >= 3) && (mbedtls_x509_crt_get_ca_istrue(crt) != 1)) {
        return TLS_CA_REJECT_NOT_CA;
    }
    psa_key_type_t type = mbedtls_pk_get_key_type(&crt->pk);''')],
 'no_entropy_gate': [(E, '''    if (entropy_source() == ENTROPY_NONE) {
        *reason = TLS_OPEN_REASON_NO_ENTROPY;''', '''    if (0) {
        *reason = TLS_OPEN_REASON_NO_ENTROPY;''')],
 'time_source_ignored': [(E, '(time_source == TLS_TIME_NIOS) && ((time_t)unix_time > floor)', '((time_t)unix_time > floor)')],
 'queue_blocks': [(D, '''        if (xQueueSend(tls_queue, &pbuffer, 0) != pdTRUE) {
            cmd_tls_busy(pbuffer);
        }''', '''        tls_serve(pbuffer);''')],
 'flags_unchecked': [(E, '    if ((flags & ~TLS_STEP_NO_READ) || (ct_in_len < 0)', '    if ((ct_in_len < 0)')],
 'no_block_timing': [(D, '''    if (ms > block_max_ms) {''', '''    if (0) {''')],
}
os.makedirs(RAW + '/test/mutants', exist_ok=True)
for name, edits in M.items():
    tmp = tempfile.mkdtemp()
    a, b = tmp + '/a', tmp + '/b'
    shutil.copytree(RAW + '/main', a + '/main'); shutil.copytree(RAW + '/main', b + '/main')
    for f, old, new in edits:
        s = open(b + '/' + f).read()
        if s.count(old) != 1:
            print('MUTANT', name, 'pattern count', s.count(old)); sys.exit(1)
        open(b + '/' + f, 'w').write(s.replace(old, new))
    d = subprocess.run(['diff', '-ru', 'a', 'b'], cwd=tmp, capture_output=True, text=True).stdout
    open(RAW + '/test/mutants/%s.patch' % name, 'w').write(d)
    shutil.rmtree(tmp)
print('wrote', len(M))
