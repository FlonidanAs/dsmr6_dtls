#include "util.h"
#include <stdio.h>

void print_certificate(const char *label, const mbedtls_x509_crt *crt) {
    unsigned char buf[4096];
    int ret = mbedtls_x509_crt_info((char*)buf, sizeof(buf)-1, "", crt);
    if (ret > 0) {
        printf("%s\n%s\n", label, buf);
    } else {
        printf("Failed to write cert info: -0x%04x\n", -ret);
    }
}
