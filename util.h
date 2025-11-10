#ifndef UTIL_H
#define UTIL_H

#include <mbedtls/x509_crt.h>

// Print a certificate in PEM format with a label
void print_certificate(const char *label, const mbedtls_x509_crt *crt);

#endif // UTIL_H
