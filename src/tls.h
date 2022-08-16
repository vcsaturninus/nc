#ifndef NC_TLS_HEADER
#define NC_TLS_HEADER

#include <stdbool.h> 
#include <stdlib.h>  /* EXIT_FAILURE etc */
#include <openssl/ssl.h>
#include <openssl/err.h>

/*
#define OPENSSL_CERT      "/etc/openssl/cert.pem"
#define OPENSSL_CERT_TYPE SSL_FILETYPE_PEM
#define OPENSSL_PRIV_KEY  "/etc/openssl/key.pem"
*/

#define OPENSSL_CERT      "/home/vcsaturninus/common/docs/software_apis/openssl/scert.pem"
#define OPENSSL_CERT_TYPE SSL_FILETYPE_PEM
#define OPENSSL_PRIV_KEY  "/home/vcsaturninus/common/docs/software_apis/openssl/skey.pem"


SSL_CTX *get_ssl_ctx(bool srv);
void configure_ssl_ctx(bool srv, SSL_CTX *ctx);

#endif
