#include "ca.h"
#include "util.h"
#include <mbedtls/x509_csr.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <stdio.h>
#include <string.h>

mbedtls_pk_context ca_pk;
mbedtls_x509_crt ca_cert;

int create_ca(mbedtls_ctr_drbg_context *ctr_drbg) {
    int ret;
    mbedtls_pk_init(&ca_pk);
    mbedtls_x509_crt_init(&ca_cert);
    if ((ret = mbedtls_pk_setup(&ca_pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0) {
        printf("Failed to setup CA pk: -0x%04x\n", -ret);
        return ret;
    }
    if ((ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(ca_pk), mbedtls_ctr_drbg_random, ctr_drbg)) != 0) {
        printf("Failed to generate CA key: -0x%04x\n", -ret);
        return ret;
    }

    mbedtls_x509write_cert crt_writer;
    mbedtls_x509write_crt_init(&crt_writer);
    mbedtls_x509write_crt_set_md_alg(&crt_writer, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt_writer, &ca_pk);
    mbedtls_x509write_crt_set_issuer_key(&crt_writer, &ca_pk);
    mbedtls_x509write_crt_set_subject_name(&crt_writer, "CN=Test CA");
    mbedtls_x509write_crt_set_issuer_name(&crt_writer, "CN=Test CA");
    mbedtls_x509write_crt_set_version(&crt_writer, 2);
    mbedtls_x509write_crt_set_key_usage(&crt_writer, MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN);
    mbedtls_x509write_crt_set_basic_constraints(&crt_writer, 1, -1);

    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);
    mbedtls_mpi_lset(&serial, 100);
    mbedtls_x509write_crt_set_serial(&crt_writer, &serial);
    mbedtls_x509write_crt_set_validity(&crt_writer, "20250101000000", "20300101000000");
    unsigned char ca_cert_buf[1024];
    ret = mbedtls_x509write_crt_pem(&crt_writer, ca_cert_buf, sizeof(ca_cert_buf), mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret < 0) {
        printf("Failed to write CA cert: -0x%04x\n", -ret);
        mbedtls_mpi_free(&serial);
        mbedtls_x509write_crt_free(&crt_writer);
        return ret;
    }
    mbedtls_x509_crt_parse(&ca_cert, ca_cert_buf, strlen((char*)ca_cert_buf)+1);
    mbedtls_mpi_free(&serial);
    mbedtls_x509write_crt_free(&crt_writer);
    return 0;
}

void print_ca() {
    unsigned char buf[4096];
    int ret = mbedtls_pk_write_key_pem(&ca_pk, buf, sizeof(buf));
    if (ret == 0) {
        printf("CA Private Key:\n%s\n", buf);
    } else {
        printf("Failed to write CA private key: -0x%04x\n", -ret);
    }

    print_certificate("CA Certificate", &ca_cert);
}

void free_ca() {
    mbedtls_pk_free(&ca_pk);
    mbedtls_x509_crt_free(&ca_cert);
}
