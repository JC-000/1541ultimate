/*
 * The crypto conformance suite's view of mbedTLS: each primitive is reached through the same
 * public call the TLS 1.3 client makes for it in this configuration (mbedTLS 3.6 without
 * MBEDTLS_USE_PSA_CRYPTO, or mbedTLS 4, where the records go through PSA's AEAD and a PSS
 * signature is verified with any salt length). So the vectors check the primitives the
 * handshake and the records use; they do not check that the TLS layer calls them correctly
 * (nonces, transcript, Finished, CertificateVerify content), which only a handshake can show.
 *
 *   vectors offer      prints what a client configured like tls_engine.c offers in its
 *                      ClientHello: "suite XXXX", "group XXXX", "sigalg XXXX", "keyshare XXXX"
 *                      (the calls it copies are listed in conformance.py ENGINE_CALLS)
 *   vectors profile    prints what the default certificate profile accepts in a chain:
 *                      "md NAME", "curve NAME", "rsa-min BITS"
 *   vectors            reads one operation per line on stdin, writes one result per line:
 *                      "<rc> <output hex>", rc 0 on success, the mbedTLS or PSA error otherwise
 *
 * Operations (hex arguments, "-" for empty):
 *   hash    ALG MSG                        psa_hash_compute()
 *   hmac    ALG KEY MSG                    psa_mac_compute(PSA_ALG_HMAC)
 *   hkdf    ALG IKM SALT INFO LEN          HKDF-Extract then HKDF-Expand, as ssl_tls13_keys.c
 *   seal    AEAD KEY IV AAD PT TAGLEN      3.6: mbedtls_cipher_auth_encrypt_ext(), 4: psa_aead_encrypt(),
 *                                          output ct || tag
 *   open    AEAD KEY IV AAD CT TAG         3.6: mbedtls_cipher_auth_decrypt_ext(), 4: psa_aead_decrypt(),
 *                                          output pt
 *   ecdh    GROUP PRIV PUB                 psa_raw_key_agreement(PSA_ALG_ECDH)
 *   verify  SCHEME SPKI ALG MSG SIG SLEN   psa_hash_compute() then mbedtls_pk_verify_ext() (4: SLEN unused,
 *                                          as the 4.x TLS client passes no salt length)
 * ALG is sha1/sha224/sha256/sha384/sha512, AEAD gcm/ccm/chachapoly, GROUP x25519, x448 or
 * secp256r1/secp384r1/secp521r1, SCHEME ecdsa/pkcs1/pss (SLEN is the PSS salt length, else 0).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/ssl.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"
#if MBEDTLS_VERSION_MAJOR < 4
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/cipher.h"
#include "mbedtls/ecp.h"
#else
// The curve list and its names are private in 4.x; the profile check below needs them
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#include "mbedtls/private/ecp.h"
#endif

#define MAX_FIELDS 8

static const struct {
    const char *name;
    psa_algorithm_t psa;
    mbedtls_md_type_t md;
} hashes[] = {
    { "sha1", PSA_ALG_SHA_1, MBEDTLS_MD_SHA1 },
    { "sha224", PSA_ALG_SHA_224, MBEDTLS_MD_SHA224 },
    { "sha256", PSA_ALG_SHA_256, MBEDTLS_MD_SHA256 },
    { "sha384", PSA_ALG_SHA_384, MBEDTLS_MD_SHA384 },
    { "sha512", PSA_ALG_SHA_512, MBEDTLS_MD_SHA512 },
};

static int find_hash(const char *name)
{
    for (size_t i = 0; i < sizeof(hashes) / sizeof(hashes[0]); i++) {
        if (!strcmp(name, hashes[i].name)) {
            return (int)i;
        }
    }
    return -1;
}

typedef struct {
    unsigned char *p;
    size_t len;
} blob_t;

static int unhex(const char *s, blob_t *b)
{
    size_t n = strcmp(s, "-") ? strlen(s) : 0;
    if (n % 2) {
        return -1;
    }
    b->len = n / 2;
    // Exactly as long as the data, so that a sanitizer build sees a read past its end
    b->p = malloc(b->len ? b->len : 1);
    for (size_t i = 0; i < b->len; i++) {
        unsigned int v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) {
            return -1;
        }
        b->p[i] = (unsigned char)v;
    }
    return 0;
}

static void print_result(int rc, const unsigned char *out, size_t len)
{
    printf("%d ", rc);
    for (size_t i = 0; (rc == 0) && (i < len); i++) {
        printf("%02x", out[i]);
    }
    printf("\n");
    fflush(stdout); // the runner waits for each answer before it sends the next line
}

static int op_hkdf(psa_algorithm_t h, const blob_t *ikm, const blob_t *salt, const blob_t *info,
                   size_t len, unsigned char *out)
{
    // mbedtls_ssl_tls13_hkdf_extract() and _expand() (ssl_tls13_keys.c) take these two steps
    unsigned char prk[PSA_HASH_MAX_SIZE];
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t st = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXTRACT(h));
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt->p, salt->len);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, ikm->p, ikm->len);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_output_bytes(&op, prk, PSA_HASH_LENGTH(h));
    }
    psa_key_derivation_abort(&op);
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXPAND(h));
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, prk, PSA_HASH_LENGTH(h));
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, info->p, info->len);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_output_bytes(&op, out, len);
    }
    psa_key_derivation_abort(&op);
    return st;
}

#if MBEDTLS_VERSION_MAJOR >= 4
static int op_aead(int seal, const char *aead, const blob_t *key, const blob_t *iv, const blob_t *aad,
                   const blob_t *in, const blob_t *tag, size_t taglen, unsigned char *out, size_t *olen)
{
    // The key and algorithm a 4.x record transform uses (mbedtls_ssl_cipher_to_psa(), ssl_msg.c):
    // the tag length is part of the algorithm when it is not the full one
    psa_key_type_t type = PSA_KEY_TYPE_AES;
    psa_algorithm_t alg = !strcmp(aead, "gcm") ? PSA_ALG_GCM : !strcmp(aead, "ccm") ? PSA_ALG_CCM : 0;
    if (!strcmp(aead, "chachapoly")) {
        type = PSA_KEY_TYPE_CHACHA20;
        alg = PSA_ALG_CHACHA20_POLY1305;
    }
    size_t tlen = seal ? taglen : tag->len;
    if (alg == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (tlen != 16) {
        alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg, tlen);
    }
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, type);
    psa_set_key_bits(&attr, key->len * 8);
    psa_set_key_usage_flags(&attr, seal ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, alg);
    mbedtls_svc_key_id_t k;
    psa_status_t st = psa_import_key(&attr, key->p, key->len, &k);
    if (st != PSA_SUCCESS) {
        return st;
    }
    if (seal) {
        st = psa_aead_encrypt(k, alg, iv->p, iv->len, aad->p, aad->len, in->p, in->len, out, in->len + taglen, olen);
    } else {
        // The record layer passes ciphertext and tag as one buffer
        unsigned char *ct = malloc(in->len + tag->len + 1);
        memcpy(ct, in->p, in->len);
        memcpy(ct + in->len, tag->p, tag->len);
        st = psa_aead_decrypt(k, alg, iv->p, iv->len, aad->p, aad->len, ct, in->len + tag->len, out, in->len + 1,
                              olen);
        free(ct);
    }
    psa_destroy_key(k);
    return st;
}
#else
static int op_aead(int seal, const char *aead, const blob_t *key, const blob_t *iv, const blob_t *aad,
                   const blob_t *in, const blob_t *tag, size_t taglen, unsigned char *out, size_t *olen)
{
    // The cipher TLS 1.3 sets up for a record transform (ssl_tls13_keys.c), by key size
    mbedtls_cipher_type_t type = MBEDTLS_CIPHER_NONE;
    if (!strcmp(aead, "gcm")) {
        type = (key->len == 16) ? MBEDTLS_CIPHER_AES_128_GCM :
               (key->len == 24) ? MBEDTLS_CIPHER_AES_192_GCM :
               (key->len == 32) ? MBEDTLS_CIPHER_AES_256_GCM : MBEDTLS_CIPHER_NONE;
    } else if (!strcmp(aead, "ccm")) {
        type = (key->len == 16) ? MBEDTLS_CIPHER_AES_128_CCM :
               (key->len == 24) ? MBEDTLS_CIPHER_AES_192_CCM :
               (key->len == 32) ? MBEDTLS_CIPHER_AES_256_CCM : MBEDTLS_CIPHER_NONE;
    } else if (!strcmp(aead, "chachapoly") && (key->len == 32)) {
        type = MBEDTLS_CIPHER_CHACHA20_POLY1305;
    }
    const mbedtls_cipher_info_t *info = mbedtls_cipher_info_from_type(type);
    if (info == NULL) {
        return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);
    int rc = mbedtls_cipher_setup(&ctx, info);
    if (rc == 0) {
        rc = mbedtls_cipher_setkey(&ctx, key->p, (int)(key->len * 8), seal ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT);
    }
    if ((rc == 0) && seal) {
        rc = mbedtls_cipher_auth_encrypt_ext(&ctx, iv->p, iv->len, aad->p, aad->len, in->p, in->len,
                                             out, in->len + taglen, olen, taglen);
    } else if (rc == 0) {
        // The record layer passes ciphertext and tag as one buffer
        unsigned char *ct = malloc(in->len + tag->len + 1);
        memcpy(ct, in->p, in->len);
        memcpy(ct + in->len, tag->p, tag->len);
        rc = mbedtls_cipher_auth_decrypt_ext(&ctx, iv->p, iv->len, aad->p, aad->len, ct,
                                             in->len + tag->len, out, in->len + 1, olen, tag->len);
        free(ct);
    }
    mbedtls_cipher_free(&ctx);
    return rc;
}
#endif

static int op_ecdh(const char *group, const blob_t *priv, const blob_t *pub, unsigned char *out, size_t *olen)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    if (!strcmp(group, "x25519") || !strcmp(group, "x448")) {
        psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
        psa_set_key_bits(&attr, !strcmp(group, "x448") ? 448 : 255);
    } else {
        psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&attr, !strcmp(group, "secp256r1") ? 256 : !strcmp(group, "secp384r1") ? 384 : 521);
    }
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    mbedtls_svc_key_id_t key;
    psa_status_t st = psa_import_key(&attr, priv->p, priv->len, &key);
    if (st != PSA_SUCCESS) {
        return st;
    }
    // ssl_tls13_keys.c hands the peer's key_share bytes to psa_raw_key_agreement() as they came
    st = psa_raw_key_agreement(PSA_ALG_ECDH, key, pub->p, pub->len, out, 128, olen);
    psa_destroy_key(key);
    return st;
}

static int op_verify(const char *scheme, const blob_t *spki, int h, const blob_t *msg, const blob_t *sig, int slen)
{
    // ssl_tls13_parse_certificate_verify() (ssl_tls13_generic.c): hash with PSA, then the pk layer
    unsigned char hash[PSA_HASH_MAX_SIZE];
    size_t hlen;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int rc = mbedtls_pk_parse_public_key(&pk, spki->p, spki->len);
    if (rc == 0) {
        rc = psa_hash_compute(hashes[h].psa, msg->p, msg->len, hash, sizeof(hash), &hlen);
    }
#if MBEDTLS_VERSION_MAJOR >= 4
    if (rc == 0) {
        // PSS is PSA_ALG_RSA_PSS_ANY_SALT (pk.h); ssl_tls13_generic.c passes no salt length
        (void)slen;
        mbedtls_pk_sigalg_t type = !strcmp(scheme, "ecdsa") ? MBEDTLS_PK_SIGALG_ECDSA :
                                   !strcmp(scheme, "pss") ? MBEDTLS_PK_SIGALG_RSA_PSS : MBEDTLS_PK_SIGALG_RSA_PKCS1V15;
        rc = mbedtls_pk_verify_ext(type, &pk, hashes[h].md, hash, hlen, sig->p, sig->len);
    }
#else
    if (rc == 0) {
        mbedtls_pk_type_t type = !strcmp(scheme, "ecdsa") ? MBEDTLS_PK_ECDSA :
                                 !strcmp(scheme, "pss") ? MBEDTLS_PK_RSASSA_PSS : MBEDTLS_PK_RSA;
        mbedtls_pk_rsassa_pss_options pss = { hashes[h].md, slen };
        rc = mbedtls_pk_verify_ext(type, (type == MBEDTLS_PK_RSASSA_PSS) ? &pss : NULL, &pk, hashes[h].md,
                                   hash, hlen, sig->p, sig->len);
    }
#endif
    mbedtls_pk_free(&pk);
    return rc;
}

static void run_line(char *line)
{
    char *f[MAX_FIELDS] = { 0 };
    blob_t b[MAX_FIELDS] = { 0 };
    int n = 0;
    for (char *t = strtok(line, " \n"); t && (n < MAX_FIELDS); t = strtok(NULL, " \n")) {
        f[n++] = t;
    }
    size_t cap = 256;
    for (int i = 2; i < n; i++) {
        if (unhex(f[i], &b[i]) != 0) {
            b[i].p = (unsigned char *)strdup(f[i]); // a decimal argument
            b[i].len = strlen(f[i]);
        }
        cap += b[i].len;
    }
    unsigned char *out = malloc(cap + 8192);
    size_t olen = 0;
    int rc = -1;
    int h = (n > 1) ? find_hash(f[1]) : -1;
    const char *op = n ? f[0] : "";

    if (!strcmp(op, "hash") && (n == 3) && (h >= 0)) {
        rc = psa_hash_compute(hashes[h].psa, b[2].p, b[2].len, out, cap, &olen);
    } else if (!strcmp(op, "hmac") && (n == 4) && (h >= 0)) {
        psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
        psa_set_key_algorithm(&attr, PSA_ALG_HMAC(hashes[h].psa));
        mbedtls_svc_key_id_t key;
        rc = psa_import_key(&attr, b[2].p, b[2].len, &key);
        if (rc == 0) {
            rc = psa_mac_compute(key, PSA_ALG_HMAC(hashes[h].psa), b[3].p, b[3].len, out, cap, &olen);
            psa_destroy_key(key);
        }
    } else if (!strcmp(op, "hkdf") && (n == 6) && (h >= 0)) {
        olen = strtoul(f[5], NULL, 10);
        out = realloc(out, olen + 1);
        rc = op_hkdf(hashes[h].psa, &b[2], &b[3], &b[4], olen, out);
    } else if ((!strcmp(op, "seal") || !strcmp(op, "open")) && (n == 7)) {
        rc = op_aead(!strcmp(op, "seal"), f[1], &b[2], &b[3], &b[4], &b[5], &b[6], strtoul(f[6], NULL, 10),
                     out, &olen);
    } else if (!strcmp(op, "ecdh") && (n == 4)) {
        rc = op_ecdh(f[1], &b[2], &b[3], out, &olen);
    } else if (!strcmp(op, "verify") && (n == 7) && ((h = find_hash(f[3])) >= 0)) {
        rc = op_verify(f[1], &b[2], h, &b[4], &b[5], atoi(f[6]));
    } else {
        fprintf(stderr, "bad operation: %s\n", op);
        exit(2);
    }
    print_result(rc, out, olen);
    free(out);
    for (int i = 0; i < n; i++) {
        free(b[i].p);
    }
}

// The ClientHello of a client set up as tls_engine.c tls_create() sets one up
static unsigned char hello[4096];
static size_t hello_len;

static int bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    (void)ctx;
    if (hello_len + len <= sizeof(hello)) {
        memcpy(hello + hello_len, buf, len);
        hello_len += len;
    }
    return (int)len;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    (void)buf;
    (void)len;
    return MBEDTLS_ERR_SSL_WANT_READ;
}

static void print_list(const char *what, const unsigned char *p, size_t len)
{
    for (size_t i = 0; i + 1 < len; i += 2) {
        printf("%s %02x%02x\n", what, p[i], p[i + 1]);
    }
}

static int offer(void)
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
#if MBEDTLS_VERSION_MAJOR < 4
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_entropy_init(&entropy);
    int ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0);
#else
    int ret = 0; // 4.x takes its randomness from PSA
#endif
    if (ret == 0) {
        ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
    }
    if (ret == 0) {
        mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_3);
        mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_3);
#if MBEDTLS_VERSION_MAJOR < 4
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
#else
        // engine4's list (tls_engine.c at f0ae8ed2, run_idf6.sh's ENGINE4_COMMIT)
        static const uint16_t groups[] = { MBEDTLS_SSL_IANA_TLS_GROUP_X25519, MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1,
                                           MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1, MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1,
                                           MBEDTLS_SSL_IANA_TLS_GROUP_NONE };
        mbedtls_ssl_conf_groups(&conf, groups);
#endif
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        ret = mbedtls_ssl_setup(&ssl, &conf);
    }
    if (ret == 0) {
        ret = mbedtls_ssl_set_hostname(&ssl, "example.com");
    }
    if (ret == 0) {
        mbedtls_ssl_set_bio(&ssl, NULL, bio_send, bio_recv, NULL);
        ret = mbedtls_ssl_handshake(&ssl);
        ret = (ret == MBEDTLS_ERR_SSL_WANT_READ) ? 0 : ret;
    }
    // record header 5, handshake header 4, legacy_version 2, random 32
    const unsigned char *p = hello + 43, *end = hello + hello_len;
    if ((ret != 0) || (hello_len < 43) || (hello[0] != 22) || (hello[5] != 1)) {
        fprintf(stderr, "no ClientHello: %d\n", ret);
        return 1;
    }
    p += 1 + p[0];                                    // legacy_session_id
    size_t n = (p[0] << 8) | p[1];
    print_list("suite", p + 2, n);
    p += 2 + n;
    p += 1 + p[0];                                    // legacy_compression_methods
    p += 2;                                           // extensions length
    while (p + 4 <= end) {
        unsigned type = (p[0] << 8) | p[1], len = (p[2] << 8) | p[3];
        const unsigned char *d = p + 4;
        if (type == 10) {
            print_list("group", d + 2, (d[0] << 8) | d[1]);
        } else if (type == 13) {
            print_list("sigalg", d + 2, (d[0] << 8) | d[1]);
        } else if (type == 51) {
            for (const unsigned char *k = d + 2; k + 4 <= d + len; k += 4 + ((k[2] << 8) | k[3])) {
                print_list("keyshare", k, 2);
            }
        }
        p += 4 + len;
    }
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
#if MBEDTLS_VERSION_MAJOR < 4
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
#endif
    return 0;
}

// What a certificate chain may use: the profile ssl_config_defaults() sets (PRESET_DEFAULT), as
// far as this build has the algorithms (mbedTLS 3.6.7 added SHA-3 to the profile)
static int profile(void)
{
    static const struct {
        const char *name;
        mbedtls_md_type_t md;
    } mds[] = { { "md5", MBEDTLS_MD_MD5 }, { "sha1", MBEDTLS_MD_SHA1 }, { "sha224", MBEDTLS_MD_SHA224 },
                { "sha256", MBEDTLS_MD_SHA256 }, { "sha384", MBEDTLS_MD_SHA384 }, { "sha512", MBEDTLS_MD_SHA512 },
                { "sha3_224", MBEDTLS_MD_SHA3_224 }, { "sha3_256", MBEDTLS_MD_SHA3_256 },
                { "sha3_384", MBEDTLS_MD_SHA3_384 }, { "sha3_512", MBEDTLS_MD_SHA3_512 },
                { "ripemd160", MBEDTLS_MD_RIPEMD160 } };
    const mbedtls_x509_crt_profile *p = &mbedtls_x509_crt_profile_default;
    for (size_t i = 0; i < sizeof(mds) / sizeof(mds[0]); i++) {
        // A hash the profile allows but this build does not have cannot be used in a chain
        if ((p->allowed_mds & MBEDTLS_X509_ID_FLAG(mds[i].md)) && mbedtls_md_info_from_type(mds[i].md)) {
            printf("md %s\n", mds[i].name);
        }
    }
    // Curve names as Wycheproof spells them
    for (const mbedtls_ecp_curve_info *c = mbedtls_ecp_curve_list(); c->grp_id != MBEDTLS_ECP_DP_NONE; c++) {
        if (p->allowed_curves & MBEDTLS_X509_ID_FLAG(c->grp_id)) {
            printf("curve %s\n", c->name);
        }
    }
    printf("rsa-min %u\n", (unsigned)p->rsa_min_bitlen);
    return 0;
}

int main(int argc, char **argv)
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        fprintf(stderr, "psa_crypto_init failed\n");
        return 1;
    }
    if ((argc == 2) && !strcmp(argv[1], "offer")) {
        return offer();
    }
    if ((argc == 2) && !strcmp(argv[1], "profile")) {
        return profile();
    }
    char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, stdin) > 0) {
        run_line(line);
    }
    free(line);
    return 0;
}
