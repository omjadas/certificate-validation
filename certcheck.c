#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int validate(char *, char *);
int validate_dates(X509 *);

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
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;

    // create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    // Read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, certificate))) {
        fprintf(stderr, "Error in reading cert BIO filename");
        exit(EXIT_FAILURE);
    }
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL))) {
        fprintf(stderr, "Error in loading certificate");
        exit(EXIT_FAILURE);
    }

    // cert contains the x509 certificate and can be used to analyse the
    // certificate

    if (validate_dates(cert) == 0) {
        return 0;
    }

    X509_free(cert);
    BIO_free_all(certificate_bio);
    return 1;
}

int validate_dates(X509 *cert) {
    ASN1_TIME *from, *to;
    int pday1, psec1, pday2, psec2;
    from = X509_get_notBefore(cert);
    to = X509_get_notAfter(cert);
    ASN1_TIME_diff(&pday1, &psec1, from, NULL);
    ASN1_TIME_diff(&pday2, &psec2, NULL, to);

    if (pday1 < 0 || psec1 < 0 || pday2 < 0 || psec2 < 0) {
        return 0;
    }
    return 1;
}