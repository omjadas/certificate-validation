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
    FILE *in = fopen(argv[1], "r");
    FILE *out = fopen("output.csv", "w");

    // initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    char line[256];

    while (fgets(line, sizeof(line), in)) {
        strtok(line, "\n");
        char *certificate, *url;
        certificate = strtok(line, ",");
        url = strtok(NULL, ",");
        fprintf(out, "%s,%s,%d\n", certificate, url,
                validate(certificate, url));
    }

    fclose(in);
    fclose(out);
    return 0;
}

int validate(char *certificate, char *url) {
    return 0;
}