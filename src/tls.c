#include "nc.h"
#include "tls.h"

#ifdef USE_TLS     /* empty if TLS not used */

extern int DEBUG_;               /* defined in nc.c */

char *CERT_PATH     = NULL;
char *PRIV_KEY_PATH = NULL;
char *PSKEY         = NULL;

/*
 * For clients and servers that have different keys with several different parties,
 * a PSK identity might be used as part of the session setup. The client indicates
 * to the server which key to use by specifying a PSK identity; the server can help
 * the client figure out which identity is needed by providing an identity 'hint'.
 *
 * For our purposes this will always be the same and is not really needed, but
 * is kept here as an example; the identity in our case is always the string below.
 * This string is hardcoded in both the client and the server so validating the psk
 * will never fail (so, again, it's not really needed/used here). However, more complex
 * validation could be implemented, such as looking up the identity in a database. */
static const char *PSK_IDENTITY  = "static_ident";

/*
 * Validate PSK shared by the client; this callback works with TLS
 * 1.{1,2,3}, but TLS1.3 prefers another function (psk_find_session_cb)
 * be used and only falls back to this as a second option.
 * See https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_psk_server_callback.html
 */
static unsigned int psk_srv_cb(SSL *ssl, const char *identity,
                                  unsigned char *psk,
                                  unsigned int max_psk_len)
{
    say(DEBUG_, " ~ running psk_server_cb()\n");
    long klen = 0;
    unsigned char *key = NULL;

    if (identity == NULL) {
        exit_print("Fatal: no PSK identity received from client\n");
    }
    say(DEBUG_, " ~ PSK identity received from the client with length %zu: '%s'\n", strlen(identity), identity);

    if (!matches(identity, PSK_IDENTITY)) {
        exit_print("PSK identity mismatch. Got '%s', expected '%s'\n", identity, PSK_IDENTITY);
    }
    say(DEBUG_, " ~ PSK client identity successfully validated.\n");

    /* convert the PSK key to buffer */
    key = OPENSSL_hexstr2buf(PSKEY, &klen);
    if (!key) {
        exit_print("Fatal: failed to convert PSK key '%s' to buffer\n", PSKEY);
    }

    if (klen > (int)max_psk_len) {
        OPENSSL_free(key);
        exit_print("Fatal: psk buffer in psk callback too small (%u) to fit the pre-shared key(%ld)\n", max_psk_len, klen);
    }

    memcpy(psk, key, klen);
    OPENSSL_free(key);

    say(DEBUG_, " ~ Returning PSK length=%ld\n", klen);
    return klen;
}

/*
 * See comments for psk_srv_cb().
 * This is much the same but does the client side of things. From the man:
 *  > The purpose of the callback function is to select the PSK identity
 *  > and the pre-shared key to use during the connection setup phase.
 *
 *  In more complex setup, this callback could have a way to determine the
 *  correct PSK identity to send the server based on the identity hint
 *  received (if any). For our purposes though the psk identity is hardcoded
 *  and no hint is used.
 */
static unsigned int psk_client_cb(SSL *ssl, const char *hint, char identity[],
                                  unsigned int max_identity_len,
                                  unsigned char *psk,
                                  unsigned int max_psk_len)
{
    int  rc            = 0;
    long klen          = 0;
    unsigned char *key = NULL;

    say(DEBUG_, " ~ running psk_client_cb()\n");
    if (!hint) {
        say(DEBUG_, " ~ no PSK identity hint provided by the server (none expected)\n");
    }else{
        say(DEBUG_, " ~ PSK identity hint received from the server: '%s'\n", hint);
    }

    /*
     * lookup PSK identity and PSK key based on the given identity hint here
     */
    rc = BIO_snprintf(identity, max_identity_len, "%s", PSK_IDENTITY);
    if (rc < 0 || (unsigned int)rc > max_identity_len){
        exit_print("Failed to write PSK identity '%s' to variable\n", PSK_IDENTITY);
    }
    say(DEBUG_, " ~ successfully set PSK identity: '%s' of length %d\n", identity, rc);

    /* convert PSK to buffer */
    key = OPENSSL_hexstr2buf(PSKEY, &klen);
    if (!key) {
        exit_print("Fatal: failed to convert PSK key '%s' to buffer\n", PSKEY);
    }

    if (max_psk_len > INT_MAX || klen > (long)max_psk_len) {
        OPENSSL_free(key);
        exit_print("Fatal: psk buffer in psk callback too small (%u) to fit the pre-shared key(%ld)\n", max_psk_len, klen);
    }

    memcpy(psk, key, klen);
    OPENSSL_free(key);

    say(DEBUG_, " ~ Returning PSK length=%ld\n", klen);
    return klen;
}

/*
 * Callback openssl calls for every certificate in the cert chain during verification.
 *
 * if preverify is 1, certificate verification has succeeded; Otherwise
 * if 0, it's failed.
 * x509_ctx stores any errors found during the certificate validation process.
 *
 * Note this callback does NOT DECIDE whether validation succeeds or fails. There is
 * another similar callback hook that can be used for that. This callback merely
 * allows printing out diagnostics -- e.g. the level in the chain where verification
 * failed.
 */
int verify_callback(int preverify, X509_STORE_CTX *x509_ctx)
{
    if (preverify > 0) return preverify;   /* no errors */

    /* 0 would be the end certificate, 1 its CA signer cert etc */
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int errc  = X509_STORE_CTX_get_error(x509_ctx);
    printf("TLS cert verification error (%d) at level %d: '%s'\n", errc, depth, X509_verify_cert_error_string(errc));

    /* cert that caused the error or NULL if no relevant cert */
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;

    fprintf(stdout, "Issuer (cn): ");
    X509_NAME_print_ex_fp(stdout, iname, 0, 0);
    fprintf(stdout, "Subject (cn): ");
    X509_NAME_print_ex_fp(stdout, sname, 0, 0);

    /* if end-entity certificate, print it all out */
    if(depth == 0) {
        X509_print_ex_fp(stdout, cert, 0, 0);
    }

    return preverify;
}

SSL_CTX *get_ssl_ctx(void){
    // const SSL_METHOD *meth = srv ? TLS_server_method() : TLS_client_method();  // older openssl??
    const SSL_METHOD *meth = TLS_method();
    SSL_CTX *ctx = SSL_CTX_new(meth);
    if (!ctx){
        ERR_print_errors_fp(stderr);
        exit_print("Failed to create SSL context");
    }
    return ctx;
}

void configure_ssl_ctx(bool srv, enum auth_mode auth, bool skip_cert_verify, SSL_CTX *ctx)
{
    if (auth == PSK_AUTH){
        say(DEBUG_, " ~ using PSK authentication\n");
        if (srv){
            SSL_CTX_set_psk_server_callback(ctx, psk_srv_cb);
        }else{
            SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);
        }
    }

    else if (auth == CERT_AUTH){
        say(DEBUG_, " ~ using certificate-based authentication\n");
        /* specify private key and certificate to use */
        if (SSL_CTX_use_certificate_file(ctx, CERT_PATH, OPENSSL_CERT_TYPE) != 1){
            ERR_print_errors_fp(stderr);
            exit_print("Failed to configure ssl context\n");
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, PRIV_KEY_PATH, OPENSSL_CERT_TYPE) != 1){
            ERR_print_errors_fp(stderr);
            exit_print("Failed to configure ssl context\n");
        }

        if (skip_cert_verify){
            say(DEBUG_, " ~ certificate verification will be skipped (insecure!)\n");
            /* forgo certificate verification: 1) client will NOT send a certificate
             * (server will not ask it to) and 2) server sends a certificate but the TLS
             * handshake continues regardless of the verification outcome for the server's
             * certificate. Note that even though the client need not present a
             * certificate anymore, it's simpler to keep the `nc` cli consistent so a
             * certificate and key still need to be specified even for the client even if
             * --noverify is specified; that means these functions still get called and
             *  therefore the client cert, just like the server cert, although it does not
             *  get 'verified' for trustworthiness, it still gets checked for format correctness
             *  and therefore it must still be valid format-wise. */
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        }else{
            /* unconditionally set SSL_VERIFY_PEER: both client and server will verify each other */
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback); // no diagnostics provided
        }

        /* find CA cert anchor in system trust store */
        if (SSL_CTX_set_default_verify_paths(ctx) != 1){
            ERR_print_errors_fp(stderr);
            exit_print("Failed to verify locations\n");
        }
    }
}

#endif
