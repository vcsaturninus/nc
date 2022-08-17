#ifndef NC_TLS_HEADER
#define NC_TLS_HEADER

#include <stdbool.h> 
#include <stdlib.h>  /* EXIT_FAILURE etc */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>   /* X509_get_default_cert_{file,dir} */


#define OPENSSL_CERT_TYPE SSL_FILETYPE_PEM

/* authentication can happen either through certificate exchange
 * or via pre-shared key (PSK) */
extern char *CERT_PATH;    
extern char *PRIV_KEY_PATH;
extern char *PSK_PATH;     

SSL_CTX *get_ssl_ctx(bool srv);
void configure_ssl_ctx(bool srv, SSL_CTX *ctx);

#endif
