#include "tls_test.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include "keypair.h"
#include "ca.h"

//#define VERBOSE_OUTPUT

static void generate_test_keys(void)
{
    int ret;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "keygen";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
        printf("Failed to seed ctr_drbg: -0x%04x\n", -ret);
        return;
    }

    printf("--- Generating CA Key Pair and Certificate ---\n");
    if (create_ca(&ctr_drbg) != 0) return;
    print_ca();

    printf("--- Generating Client Key Pair ---\n");
    if (create_client_keypair(&ctr_drbg) != 0) return;
#if defined(VERBOSE_OUTPUT)
    print_client_keypair();
#endif

    printf("--- Generating Server Key Pair ---\n");
    if (create_server_keypair(&ctr_drbg) != 0) return;
#if defined(VERBOSE_OUTPUT)
    print_server_keypair();
#endif

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

int main() 
{
    generate_test_keys();

    // Run a stub TLS handshake test
    printf("\n");
    run_tls_handshake_test();

    // Cleanup keypair contexts
    keypair_cleanup();
    free_ca();
    return 0;
}