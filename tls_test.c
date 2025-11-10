#include "tls_test.h"
#include "keypair.h"
#include "ca.h"
#include "util.h"
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <string.h>
#include <stdio.h>

// #define MBEDTLS_SSL_TRANSPORT MBEDTLS_SSL_TRANSPORT_STREAM
#define MBEDTLS_SSL_TRANSPORT MBEDTLS_SSL_TRANSPORT_DATAGRAM

#if MBEDTLS_SSL_TRANSPORT == MBEDTLS_SSL_TRANSPORT_DATAGRAM
#include "mbedtls/timing.h"
#include <mbedtls/ssl_cookie.h>
#endif

// In-memory BIO buffers
#define MEMBIO_SIZE 4096
typedef struct {
    unsigned char buf[MEMBIO_SIZE];
    size_t len;
    size_t pos;
} membio_t;

static mbedtls_ssl_context client_ssl;
static mbedtls_ssl_context server_ssl;
static membio_t client_io = {0};
static membio_t server_io = {0};

static const char* nss_keylog_file = "nss_keylog_file";

// Print in a format that text2pcap.exe understands
static void print_bytes(const unsigned char *buf, size_t len)
{
    printf("000000 ");
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

static int membio_send(void *ctx, const unsigned char *buf, size_t len)
{
    membio_t *bio = (membio_t *)ctx;
    // Client must write to server IO and vice versa
    if (bio == &client_io) {
        printf("[TLS SEND] Client: %zu bytes\n", len);
        bio = &server_io;
    } else {
        printf("[TLS SEND] Server: %zu bytes\n", len);
        bio = &client_io;
    }

    if (bio->len + len > MEMBIO_SIZE) return MBEDTLS_ERR_SSL_WANT_WRITE;

    memcpy(bio->buf + bio->len, buf, len);
    bio->len += len;

    print_bytes(buf, len);

    return (int)len;
}

static int membio_recv(void *ctx, unsigned char *buf, size_t len)
{
    membio_t *bio = (membio_t *)ctx;
    size_t avail = bio->len - bio->pos;
    if (avail == 0) return MBEDTLS_ERR_SSL_WANT_READ;
    if (len > avail) len = avail;

    memcpy(buf, bio->buf + bio->pos, len);
    bio->pos += len;

    return (int)len;
}

static void nss_keylog_export(void *p_expkey,
                              mbedtls_ssl_key_export_type secret_type,
                              const unsigned char *secret,
                              size_t secret_len,
                              const unsigned char client_random[32],
                              const unsigned char server_random[32],
                              mbedtls_tls_prf_types tls_prf_type)
{
    char nss_keylog_line[200];
    size_t const client_random_len = 32;
    size_t len = 0;
    size_t j;

    /* We're only interested in the TLS 1.2 master secret */
    if (secret_type != MBEDTLS_SSL_KEY_EXPORT_TLS12_MASTER_SECRET) {
        return;
    }

    ((void) p_expkey);
    ((void) server_random);
    ((void) tls_prf_type);

    len += sprintf(nss_keylog_line + len,
                   "%s", "CLIENT_RANDOM ");

    for (j = 0; j < client_random_len; j++) {
        len += sprintf(nss_keylog_line + len,
                       "%02x", client_random[j]);
    }

    len += sprintf(nss_keylog_line + len, " ");

    for (j = 0; j < secret_len; j++) {
        len += sprintf(nss_keylog_line + len,
                       "%02x", secret[j]);
    }

    len += sprintf(nss_keylog_line + len, "\n");
    nss_keylog_line[len] = '\0';

    if (nss_keylog_file != NULL) {
        FILE *f;

        if ((f = fopen(nss_keylog_file, "a")) == NULL) {
            goto exit;
        }

        if (fwrite(nss_keylog_line, 1, len, f) != len) {
            fclose(f);
            goto exit;
        }

        fclose(f);
    }

exit:
    mbedtls_platform_zeroize(nss_keylog_line,
                             sizeof(nss_keylog_line));
}

void run_tls_handshake_test(void)
{
    printf("[TLS TEST] Starting simplified in-memory handshake...\n");
    mbedtls_ssl_config client_conf, server_conf;
    mbedtls_x509_crt client_cert, server_cert;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    int ret, client_done = 0, server_done = 0;
    const char *pers = "tls_handshake";

    mbedtls_ssl_init(&client_ssl);
    mbedtls_ssl_init(&server_ssl);
    mbedtls_ssl_config_init(&client_conf);
    mbedtls_ssl_config_init(&server_conf);
    mbedtls_x509_crt_init(&client_cert);
    mbedtls_x509_crt_init(&server_cert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Seed RNG
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
        printf("[TLS TEST] Failed to seed ctr_drbg: -0x%04x\n", -ret);
        goto cleanup;
    }

    // Use CA to sign client and server certs
    if ((ret = sign_client_cert(&ctr_drbg, &client_cert, &ca_cert, &ca_pk)) != 0) {
        printf("[TLS TEST] Failed to sign client cert: -0x%04x\n", -ret);
        goto cleanup;
    }
    print_certificate("Client Certificate", &client_cert);
    if ((ret = sign_server_cert(&ctr_drbg, &server_cert, &ca_cert, &ca_pk)) != 0) {
        printf("[TLS TEST] Failed to sign server cert: -0x%04x\n", -ret);
        goto cleanup;
    }
    print_certificate("Server Certificate", &server_cert);

    // Configure server
    const int ciphersuites[] = { MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0 };
    if ((ret = mbedtls_ssl_config_defaults(&server_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        printf("[TLS TEST] Server config failed: -0x%04x\n", -ret);
        goto cleanup;
    }
    mbedtls_ssl_conf_ciphersuites(&server_conf, ciphersuites);
    mbedtls_ssl_conf_min_version(&server_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version(&server_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_ca_chain(&server_conf, &ca_cert, NULL);
    mbedtls_ssl_conf_own_cert(&server_conf, &server_cert, keypair_get_server_pk());
    mbedtls_ssl_conf_rng(&server_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_authmode(&server_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
#if MBEDTLS_SSL_TRANSPORT == MBEDTLS_SSL_TRANSPORT_DATAGRAM
    mbedtls_ssl_cookie_ctx cookie_ctx;
    mbedtls_ssl_cookie_init(&cookie_ctx);
    mbedtls_ssl_cookie_setup(&cookie_ctx, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dtls_cookies(&server_conf,
                                  mbedtls_ssl_cookie_write,
                                  mbedtls_ssl_cookie_check,
                                  &cookie_ctx);

    mbedtls_ssl_conf_handshake_timeout(&server_conf, 10000, 60000);
#endif

    // Configure client
    if ((ret = mbedtls_ssl_config_defaults(&client_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        printf("[TLS TEST] Client config failed: -0x%04x\n", -ret);
        goto cleanup;
    }
    mbedtls_ssl_conf_ciphersuites(&client_conf, ciphersuites);
    mbedtls_ssl_conf_min_version(&client_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version(&client_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_ca_chain(&client_conf, &ca_cert, NULL);
    mbedtls_ssl_conf_own_cert(&client_conf, &client_cert, keypair_get_client_pk());
    mbedtls_ssl_conf_rng(&client_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_authmode(&client_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
#if MBEDTLS_SSL_TRANSPORT == MBEDTLS_SSL_TRANSPORT_DATAGRAM
    mbedtls_ssl_conf_handshake_timeout(&client_conf, 10000, 60000);
#endif


    if ((ret = mbedtls_ssl_setup(&server_ssl, &server_conf)) != 0 ||
        (ret = mbedtls_ssl_setup(&client_ssl, &client_conf)) != 0) {
        printf("[TLS TEST] ssl_setup failed: -0x%04x\n", -ret);
        goto cleanup;
    }

    mbedtls_ssl_set_hostname(&client_ssl, NULL);
    mbedtls_ssl_set_bio(&client_ssl, &client_io, membio_send, membio_recv, NULL);
    mbedtls_ssl_set_bio(&server_ssl, &server_io, membio_send, membio_recv, NULL);
    mbedtls_ssl_set_export_keys_cb(&client_ssl, nss_keylog_export, NULL);

#if MBEDTLS_SSL_TRANSPORT == MBEDTLS_SSL_TRANSPORT_DATAGRAM
    mbedtls_timing_delay_context timer_client;
    mbedtls_timing_delay_context timer_server;
    mbedtls_ssl_set_timer_cb(&client_ssl, &timer_client, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
    mbedtls_ssl_set_timer_cb(&server_ssl, &timer_server, mbedtls_timing_set_delay, mbedtls_timing_get_delay);

    mbedtls_ssl_set_client_transport_id(&server_ssl,
                                        (const unsigned char *)"client_id",
                                        strlen("client_id"));
#endif

    // Handshake loop
    while (!client_done || !server_done) {
        if (!client_done) {
            ret = mbedtls_ssl_handshake(&client_ssl);
            if (ret == 0 && mbedtls_ssl_is_handshake_over(&client_ssl)) client_done = 1;
            else if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                printf("[TLS TEST] Client handshake error: -0x%04x\n", -ret);
                break;
            }
        }
        if (!server_done) {
            ret = mbedtls_ssl_handshake(&server_ssl);
            if (ret == 0 && mbedtls_ssl_is_handshake_over(&server_ssl)) server_done = 1;
#if MBEDTLS_SSL_TRANSPORT == MBEDTLS_SSL_TRANSPORT_DATAGRAM
            else if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
                printf("[TLS TEST] Server requested HelloVerify\n");
                // Reset session and set client ID again. Done because server expects a new ClientHello.
                // See dtls_server.c in the mbedTLS examples for reference.
                mbedtls_ssl_session_reset(&server_ssl);
                mbedtls_ssl_set_client_transport_id(&server_ssl,
                                                    (const unsigned char *)"client_id",
                                                    strlen("client_id"));
            }
#endif
            else if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                printf("[TLS TEST] Server handshake error: -0x%04x\n", -ret);
                break;
            }
        }
    }

    if (client_done && server_done) {
        printf("[TLS TEST] Handshake completed successfully!\n");
    } else {
        printf("[TLS TEST] Handshake failed.\n");
    }

    if (client_done && server_done) {
        // Send dummy data from client
        const char* str = "Hello World";
        mbedtls_ssl_write(&client_ssl, str, strlen(str));
    }

cleanup:
    mbedtls_ssl_free(&client_ssl);
    mbedtls_ssl_free(&server_ssl);
    mbedtls_ssl_config_free(&client_conf);
    mbedtls_ssl_config_free(&server_conf);
    mbedtls_x509_crt_free(&client_cert);
    mbedtls_x509_crt_free(&server_cert);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}
