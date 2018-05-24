#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int validate(char *, char *);
int validate_dates(X509 *);
int validate_domain(X509 *, char *);
int validate_cn(X509 *, char *);
int validate_san(X509 *, char *);
int validate_key_length(X509 *);
int validate_key_usage(X509 *);
int validate_ca(X509 *);
int validate_tls(X509 *);
char *get_common_name(X509 *);
int match(char *, char *);

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
    int valid = 1;

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

    if (validate_dates(cert) == 0 || validate_domain(cert, url) == 0 ||
        validate_key_length(cert) == 0 || validate_key_usage(cert) == 0) {
        valid = 0;
    }

    X509_free(cert);
    BIO_free_all(certificate_bio);
    return valid;
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

int validate_domain(X509 *cert, char *url) {
    return (validate_cn(cert, url) && validate_san(cert, url));
}

int validate_cn(X509 *cert, char *url) {
    return match(get_common_name(cert), url);
}

int validate_san(X509 *cert, char *url) {
    int alt_name = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    X509_EXTENSION *ex = X509_get_ext(cert, alt_name);
    if (alt_name > 0) {
        BUF_MEM *bptr = NULL;
        char *buf = NULL;

        BIO *bio = BIO_new(BIO_s_mem());
        if (!X509V3_EXT_print(bio, ex, 0, 0)) {
            fprintf(stderr, "Error in reading extensions");
        }
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bptr);

        // bptr->data is not NULL terminated - add null character
        buf = (char *)malloc((bptr->length + 1) * sizeof(char));
        memcpy(buf, bptr->data, bptr->length);
        buf[bptr->length] = '\0';

        // Can print or parse value
        char *token = strtok(buf, ", DNS:");
        while (token) {
            if (match(token, url) == 1) {
                free(buf);
                return 1;
            }
            token = strtok(NULL, ", DNS:");
        }
        free(buf);
        return 0;
    } else {
        return 1;
    }
}

int validate_key_length(X509 *cert) {
    int valid = 1;
    EVP_PKEY *key = X509_get_pubkey(cert);
    RSA *rsa_key = EVP_PKEY_get1_RSA(key);

    if ((RSA_size(rsa_key) * 8) < 2048) {
        valid = 0;
    }
    RSA_free(rsa_key);
    EVP_PKEY_free(key);
    return valid;
}

int validate_key_usage(X509 *cert) {
    int valid = 1;
    return valid;
}

int validate_ca(X509 *cert) {
}

int validate_tls(X509 *cert) {
}

int match(char *str1, char *str2) {
    if (str1[0] == '*') {
        char *str1_cpy, *str2_cpy;
        char *save_ptr1, *save_ptr2;
        char *token1, *token2;

        str1_cpy = strdup(str1);
        str2_cpy = strdup(str2);

        token1 = strtok_r(str1_cpy, ".", &save_ptr1);
        token2 = strtok_r(str2_cpy, ".", &save_ptr2);
        token1 = strtok_r(NULL, ".", &save_ptr1);
        token2 = strtok_r(NULL, ".", &save_ptr2);
        while (token1 && token2) {
            if (strcmp(token1, token2) != 0) {
                return 0;
            } else {
                token1 = strtok_r(NULL, ".", &save_ptr1);
                token2 = strtok_r(NULL, ".", &save_ptr2);
            }
        }
        if (token1 || token2) {
            return 0;
        }
    } else {
        if (strcmp(str1, str2) != 0) {
            return 0;
        }
    }
    return 1;
}

char *get_common_name(X509 *cert) {
    X509_NAME *subj = X509_get_subject_name(cert);
    X509_NAME_ENTRY *entry =
        X509_NAME_get_entry(subj, X509_NAME_entry_count(subj) - 1);
    ASN1_STRING *domain = X509_NAME_ENTRY_get_data(entry);
    return ASN1_STRING_data(domain);
}
