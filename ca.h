#ifndef CA_H
#define CA_H

#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ctr_drbg.h>

// CA key and certificate
extern mbedtls_pk_context ca_pk;
extern mbedtls_x509_crt ca_cert;

// Functions to create CA key and self-signed cert
int create_ca(mbedtls_ctr_drbg_context *ctr_drbg);
void print_ca();
void free_ca();

#endif // CA_H
