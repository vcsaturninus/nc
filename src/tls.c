#include "tls.h"

#ifdef USE_TLS /* empty if TLS not used */

char *CERT_PATH     = NULL;
char *PRIV_KEY_PATH = NULL;
char *PSK_PATH      = NULL;


int verify_callback(int preverify, X509_STORE_CTX *x509_ctx)
{
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
	printf("err = %d\n", err);
	fprintf(stderr, "%s\n", X509_verify_cert_error_string(err));
    
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
    
    //print_cn_name("Issuer (cn)", iname);
    //print_cn_name("Subject (cn)", sname);
	X509_NAME_print_ex_fp(stdout, iname, 0, 0);
	puts("");
	X509_NAME_print_ex_fp(stdout, sname, 0, 0);
	puts("");
    
    if(depth == 0) {
        /* If depth is 0, its the server's certificate. Print the SANs too */
		printf("depth 0\n");
		X509_print_ex_fp(stdout, cert, 0, 0);
    }

    return preverify;
}


/* Create new SSL context for server
 * (if srv=true), else for client */
SSL_CTX *get_ssl_ctx(bool srv){
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
	const char * path = X509_get_default_cert_dir();
	const char * file = X509_get_default_cert_file();
	const char * fenv = X509_get_default_cert_file_env();
	const char * penv = X509_get_default_cert_dir_env();
	puts(path);
	puts(file);
	puts(penv);
	puts(fenv);
	//printf("%s\n", getenv("SSL_CERT_FILE"));
	int rc = 0;
    //if (srv){
        /* specify private key and certificate to use */
        if (SSL_CTX_use_certificate_file(ctx, CERT_PATH, OPENSSL_CERT_TYPE) != 1){
        //if (SSL_CTX_use_certificate_chain_file(ctx, OPENSSL_CERT) != 1){
            fprintf(stderr, "Failed to configure ssl context\n");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, PRIV_KEY_PATH, OPENSSL_CERT_TYPE) != 1){
            fprintf(stderr, "Failed to configure ssl context");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    //}

    //else{ // client
        /* abort if cert verification fails */
        //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); // no diagnostics provided
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback); // no diagnostics provided
        //SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); // no diagnostics provided
		printf("returned = %d\n", rc);
        
        //SSL_CTX_set_default_verify_paths(ctx);
#if 1
        //if (SSL_CTX_load_verify_locations(ctx, OPENSSL_ROOTCA, NULL) != 1){
        //if (SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/certs") != 1){
        //if (SSL_CTX_load_verify_locations(ctx, "/usr/lib/ssl/certs/cert.pem", "/usr/lib/ssl/certs") != 1){
		if (SSL_CTX_set_default_verify_paths(ctx) != 1){  /* assumes cert anchor is installed in truststore */
            fprintf(stderr, "Failed to verify locations\n");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
#endif
    //}
}

#endif
