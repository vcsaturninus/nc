#include "tls.h"

#ifdef USE_TLS /* empty if TLS not used */

/* Create new SSL context for server
 * (if srv=true), else for client */
SSL_CTX *get_ssl_ctx(bool srv){
    (void) srv;
    //const SSL_METHOD *meth = srv ? TLS_server_method() : TLS_client_method();
    const SSL_METHOD *meth = TLS_method();
    SSL_CTX *ctx = SSL_CTX_new(meth);
    if (!ctx){
        perror("Failed to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_ssl_ctx(bool srv, SSL_CTX *ctx){
    if (srv){
        /* specify private key and certificate to use */
        //if (SSL_CTX_use_certificate_file(ctx, OPENSSL_CERT, OPENSSL_CERT_TYPE) != 1){
        if (SSL_CTX_use_certificate_chain_file(ctx, OPENSSL_CERT) != 1){
            fprintf(stderr, "Failed to configure ssl context\n");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, OPENSSL_PRIV_KEY, OPENSSL_CERT_TYPE) != 1){
            fprintf(stderr, "Failed to configure ssl context");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }

    else{ // client
        /* abort if cert verification fails */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); // no diagnostics provided
        //SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); // no diagnostics provided
        
        SSL_CTX_set_default_verify_paths(ctx);
#if 0
        if (SSL_CTX_load_verify_locations(ctx, OPENSSL_CERT, NULL) != 1){
            fprintf(stderr, "Failed to verify locations\n");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
#endif
    }
}

#endif
