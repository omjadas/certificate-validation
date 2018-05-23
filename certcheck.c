#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int validate(char *, char *);

int main(int argc, char *argv[]) {
    FILE *file = fopen(argv[1], "r");

    // initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    char line[256];

    while (fgets(line, sizeof(line), file)) {
        strtok(line, "\n");
        char *certificate, *url;
        certificate = strtok(line, ",");
        url = strtok(NULL, ",");
        validate(certificate, url);
    }

    fclose(file);
    return 0;
}

int validate(char *certificate, char *url) {
    return 0;
}