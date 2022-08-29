#ifndef NC_TLS_HEADER
#define NC_TLS_HEADER

#include <stdbool.h>
#include <stdlib.h>         /* EXIT_FAILURE etc */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>   /* X509_get_default_cert_{file,dir} */
#include <openssl/bio.h>

/* Type of certificate: always use PEM */
#define OPENSSL_CERT_TYPE SSL_FILETYPE_PEM

/* 256 bytes seems to be the longest PSK in any supported cypher */
#define MAX_PSK_LEN 2048

/*
 * authentication mode:
 * 1) no authentication i.e. authentication disabled
 * 2) certificate-based authentication
 * 3) authentication based on pre-shared key */
enum auth_mode { CERT_AUTH=1, PSK_AUTH=2 };

/* for certificate-based auth */
extern char *CERT_PATH;
extern char *PRIV_KEY_PATH;

/* for PSK-based auth */
extern char *PSKEY;

/* get new ssl context; the session ssl object will inherit its attributes */
SSL_CTX *get_ssl_ctx(void);

/* configure SSL context either for server (srv=true) or client (!src) */
void configure_ssl_ctx(bool srv, enum auth_mode auth, bool skip_cert_verify, SSL_CTX *ctx);

#endif
