#ifndef KEYPAIR_H
#define KEYPAIR_H

#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/x509.h>

// Keypair creation
int create_client_keypair(mbedtls_ctr_drbg_context *ctr_drbg);
int create_server_keypair(mbedtls_ctr_drbg_context *ctr_drbg);

// Certificate signing
int sign_client_cert(mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_x509_crt *out_cert, mbedtls_x509_crt *ca_cert, mbedtls_pk_context *ca_pk);
int sign_server_cert(mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_x509_crt *out_cert, mbedtls_x509_crt *ca_cert, mbedtls_pk_context *ca_pk);

// Getters
mbedtls_pk_context* keypair_get_client_pk();
mbedtls_pk_context* keypair_get_server_pk();

// Utility to print PEM keys
void print_client_keypair();
void print_server_keypair();

// Cleanup function to free key-pair contexts
void keypair_cleanup();

#endif // KEYPAIR_H
