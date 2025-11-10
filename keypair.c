#include "keypair.h"
#include <mbedtls/x509_csr.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/md.h>
#include <stdio.h>
#include <string.h>

static mbedtls_pk_context client_pk;
static mbedtls_pk_context server_pk;

// Helper to sign a keypair with the CA
static int sign_cert(const char *subject, mbedtls_pk_context *subject_key, mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_x509_crt *out_cert, mbedtls_x509_crt *ca_cert, mbedtls_pk_context *ca_pk, int serial_val) {
    int ret;
    mbedtls_x509write_cert crt_writer;
    mbedtls_x509write_crt_init(&crt_writer);
    mbedtls_x509write_crt_set_md_alg(&crt_writer, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt_writer, subject_key);
    mbedtls_x509write_crt_set_issuer_key(&crt_writer, ca_pk);
    mbedtls_x509write_crt_set_subject_name(&crt_writer, subject);
    mbedtls_x509write_crt_set_issuer_name(&crt_writer, "CN=Test CA");
    mbedtls_x509write_crt_set_version(&crt_writer, 2);
    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);
    mbedtls_mpi_lset(&serial, serial_val);
    mbedtls_x509write_crt_set_serial(&crt_writer, &serial);
    mbedtls_x509write_crt_set_validity(&crt_writer, "20250101000000", "20300101000000");
    unsigned char cert_buf[2048];
    ret = mbedtls_x509write_crt_pem(&crt_writer, cert_buf, sizeof(cert_buf), mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret < 0) {
        printf("Failed to write %s cert: -0x%04x\n", subject, -ret);
        mbedtls_mpi_free(&serial);
        mbedtls_x509write_crt_free(&crt_writer);
        return ret;
    }
    ret = mbedtls_x509_crt_parse(out_cert, cert_buf, strlen((char*)cert_buf)+1);
    mbedtls_mpi_free(&serial);
    mbedtls_x509write_crt_free(&crt_writer);
    return ret;
}

int sign_client_cert(mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_x509_crt *out_cert, mbedtls_x509_crt *ca_cert, mbedtls_pk_context *ca_pk) {
    mbedtls_x509_crt_init(out_cert);
    return sign_cert("CN=Client", keypair_get_client_pk(), ctr_drbg, out_cert, ca_cert, ca_pk, 101);
}

int sign_server_cert(mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_x509_crt *out_cert, mbedtls_x509_crt *ca_cert, mbedtls_pk_context *ca_pk) {
    mbedtls_x509_crt_init(out_cert);
    return sign_cert("CN=Server", keypair_get_server_pk(), ctr_drbg, out_cert, ca_cert, ca_pk, 102);
}

static int generate_ecc_keypair(mbedtls_pk_context *pk, mbedtls_ctr_drbg_context *ctr_drbg) {
    int ret;
    mbedtls_pk_init(pk);
    if ((ret = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0) {
        printf("Failed to setup pk context: -0x%04x\n", -ret);
        return ret;
    }
    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(*pk), mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0) {
        printf("Failed to generate ECC key: -0x%04x\n", -ret);
        return ret;
    }
    return 0;
}

int create_client_keypair(mbedtls_ctr_drbg_context *ctr_drbg) {
    return generate_ecc_keypair(&client_pk, ctr_drbg);
}

int create_server_keypair(mbedtls_ctr_drbg_context *ctr_drbg) {
    return generate_ecc_keypair(&server_pk, ctr_drbg);
}

mbedtls_pk_context* keypair_get_client_pk()
{
    return &client_pk;
}

mbedtls_pk_context* keypair_get_server_pk()
{
    return &server_pk;
}

static void print_keypair(const char *who, mbedtls_pk_context *pk) {
    unsigned char priv_buf[1600];
    unsigned char pub_buf[800];
    int ret;
    ret = mbedtls_pk_write_key_pem(pk, priv_buf, sizeof(priv_buf));
    if (ret == 0)
        printf("%s Private Key (PEM):\n%s\n", who, priv_buf);
    else
        printf("Failed to write %s private key: -0x%04x\n", who, -ret);
    ret = mbedtls_pk_write_pubkey_pem(pk, pub_buf, sizeof(pub_buf));
    if (ret == 0)
        printf("%s Public Key (PEM):\n%s\n", who, pub_buf);
    else
        printf("Failed to write %s public key: -0x%04x\n", who, -ret);
}

void print_client_keypair() {
    print_keypair("Client", &client_pk);
}

void print_server_keypair() {
    print_keypair("Server", &server_pk);
}

void keypair_cleanup() {
    mbedtls_pk_free(&client_pk);
    mbedtls_pk_free(&server_pk);
}