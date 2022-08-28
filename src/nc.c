#include <assert.h>
#include <errno.h>
#include <limits.h>      /* SSIZE_MAX */
#include <getopt.h>      /* getopt_long() */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>      /* exit() */
#include <stdarg.h>      /* va_list etc */
#include <netdb.h>       /* getaddrinfo() */
#include <sys/socket.h>  /* struct socket */
#include <string.h>      /* memset() */
#include <unistd.h>
#include <fcntl.h>       /* open() */
#include <sys/stat.h>    /* mode_t constants */
#include <arpa/inet.h>   /* inet_pton */
#include <sys/un.h>      /* struct sockaddr_un */

#include "nc.h"

#ifdef USE_TLS           /* encrypt internet sockets with TLS */
#include <signal.h>      /* to ignore SIGPIPE */
#include "tls.h"
#endif


/*============
  -- Macros --
  ===========*/

/* Size of accept() backlog */
#define BACKLOG_SIZE 1

/* buffer size for connect utility function */
#define BUFFER_SIZE 8192  /* 2^13; large buffer to speed up byte transfer */

/* silence unused variable warning */
#define UNUSED(x) (void)(x)


/*===================
  -- Declarations --
  ==================*/

int DEBUG_ = 0;      /* flag to toggle debug prints and verbosity */

/* IO failure return codes */
enum {READ_FAIL=-1, WRITE_FAIL=-2};

/* print to stdout iff flag is true */
void say(int flag, const char *fmt, ...);

/* Show help message for [-h] */
void show_usage(char **argv);

/* read buffsz bytes at a time from src until EOF or error and write to dst */
int transfer(int src, int dst, int buffsz);

/* reliably write nbytes from the src buffer to the dst descriptor */
int full_write(int dst, char *src, int nbytes);

#ifdef USE_TLS
/*
 * read buffsz bytes at a time until EOF or error from src and write
 * to ssl or or from ssl and write to dst. dir indicates which of the
 * two it is (see the enum below). */
int ssl_transfer(int src, int dst, int buffsz, SSL *ssl, int dir);

/* SSL read-write direction - used in ssl_transfer(). */
enum {FROM_SSL=0, TO_SSL=1};
#endif


/*==========
  -- MAIN --
  =========*/

int main(int argc, char *argv[]){
    setbuf(stdout, NULL);/* make stdout unbuffered */
    int rc = 0;          /* used to store the return code of various functions */
    int sd = 0;          /* socket descriptor */

    int LISTENER = 0;    /* flag for running in receiver/server mode */
    int UNIX_DOMAIN = 0; /* flag to use unix domain sockets rather than INET ones */

    char *file = NULL;   /* optionally specified input/output file */
    UNUSED(file);        /* silence unused warning (if unspecified) */

#ifdef USE_TLS
    enum auth_mode auth = 0;
    int TLS_ENCRYPT     = 0;            /* flag to enable TLS encryption */
    int PSK_MODE        = 0;            /* auth modes are mutually exclusive */
    int CERT_MODE       = 0;
    int NO_TLS_AUTH     = 0;
    int PSK_FROM_FILE   = 0;
    char psk__[MAX_PSK_LEN+1] = {0};  /* to store the PSK IFF PSK_FROM_FILE is true */

    SSL_CTX *ssl_ctx = NULL;
    SSL     *ssl     = NULL;
    say(DEBUG_, "openssl version = %lx\n", OPENSSL_VERSION_NUMBER);
#endif

    /*~~~~~~~~~~~~~~~~~
      -- CLI parsing --
     *~~~~~~~~~~~~~~~~~*/

#ifdef USE_TLS
    const char *optstring = "dec:k:p:f:hlu";
#else
    const char *optstring = "df:hlu";
#endif

    struct option longopts[] = {
#ifdef USE_TLS
    {"encrypt", no_argument, NULL, 'e'},
    {"cert", required_argument, NULL, 'c'},
    {"key", required_argument, NULL, 'k'},
    {"psk", required_argument, NULL, 'p'},
    {"psk-from-file", no_argument, &PSK_FROM_FILE, 1},
    {"noauth", no_argument, &NO_TLS_AUTH, 1},
#endif
    {"debug", no_argument, NULL, 'd'},
    {"file", required_argument, NULL, 'f'},
    {"listen", no_argument, &LISTENER, 1},
    {"help", no_argument, NULL, 'h'},
    {"unix", no_argument, &UNIX_DOMAIN, 1},
    {0,0,0,0}
    };

    char opt   = 0;
    extern int optind;
    extern char *optarg;
    extern int   optopt;

    while ((opt = getopt_long(argc, argv, optstring, longopts, &optind)) != -1){
        switch(opt){
#ifdef USE_TLS
            case 'e':
                TLS_ENCRYPT = 1;
                break;

            case 'c':
                CERT_PATH = optarg;
                CERT_MODE = 1;
                break;

            case 'k':
                PRIV_KEY_PATH = optarg;
                CERT_MODE = 1;
                break;

            case 'p':
                PSKEY = optarg;
                PSK_MODE = 1;
                break;
#endif
            case 'd':
                DEBUG_ = 1;
                break;

            case 'f':
                file = optarg;
                break;

            case 'l':
                LISTENER=1;
                break;

            case 'u':
                UNIX_DOMAIN = 1;
                break;

            case 'h':
                show_usage(argv);
                exit(EXIT_SUCCESS);
                break;

            case '?':
            case ':':
                exit(EXIT_FAILURE);
                break;
        }
    }

    /* validate cli */
#ifdef USE_TLS
    if (UNIX_DOMAIN && TLS_ENCRYPT){
        exit_print("Invalid cli configuration: encryption can only be used with Internet sockets\n");
    }

    if (PSK_MODE + CERT_MODE + NO_TLS_AUTH > 1){
        exit_print("Invalid cli configuration: certificate, PSK, and noauth modes are mutually exclusive\n");
    }

    if (CERT_MODE && (!PRIV_KEY_PATH || !CERT_PATH)){
        exit_print("Invalid cli configuration: certificate mode requires certificate and private key\n");
    }

    if (TLS_ENCRYPT && !(CERT_MODE || PSK_MODE || NO_TLS_AUTH)){
        exit_print("Invalid cli configuration: TLS mode (-e) requires either certificate, PSK, or noauth mode\n");
    }

    if (TLS_ENCRYPT){
        /* set authentication mode */
        auth = NO_TLS_AUTH ? NO_AUTH : PSK_MODE ? PSK_AUTH : CERT_AUTH;

        /* if PSK_FROM_FILE is true, then PSKEY is not a key,
         * but a path to read the key from */
        if (PSK_FROM_FILE){
            int fd = 0;
            if ( (fd = open(PSKEY, O_RDONLY)) == -1){
                exit_perror("Failed to open PSK file");
            }
            if (read(fd, psk__, MAX_PSK_LEN) == -1){
                exit_perror("Failed to read PSK file");
            }

            close(fd);
            PSKEY = &(psk__[0]);

            /* strip trailing newline, if any */
            char *nl = strchr(PSKEY, '\n');
            if (nl) *nl = '\0';
            say(DEBUG_, "READ PSK from file: '%s'", PSKEY);
        }

        /* initialize openssl lib internals */
        SSL_library_init();
    }
#endif

    /* where to read and write from:
       1) client reads from stdin or file and sends to server via socket
       2) server reads from socket what the client sent and writes to stdout or file */
    int input  = 0; /* stdin */
    int output = 1; /* stdout */
    if (file && LISTENER){
        mode_t perms = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;
        if ((output = open(file, O_CREAT|O_WRONLY|O_APPEND, perms)) == -1){
            exit_perror("Failed to open file for writing");
        }
    } else if (file && !LISTENER){
        if ((input = open(file, O_RDONLY)) == -1){
            exit_perror("Failed to open file for reading");
        }
    }

    /*~~~~~~~~~~~~~~~~~~
      -- Socket logic --
     *~~~~~~~~~~~~~~~~~~*/
    if (UNIX_DOMAIN){
        /* 1 positional param expected: path to unix domain socket */
        if (argc != optind+1){
            exit_print("Invalid cli specification; see help message\n");
        }
        char *SOCK_PATH = argv[optind];

        if (( sd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1){
            exit_perror("Failed to create Unix Domain socket");
        }

        struct sockaddr_un unaddr;
        memset(&unaddr, 0, sizeof(struct sockaddr_un));
        unaddr.sun_family = AF_UNIX;
        strncpy(unaddr.sun_path, SOCK_PATH, sizeof(unaddr.sun_path)-1);

        if (LISTENER){
            if (unlink(SOCK_PATH) == -1 && errno != ENOENT){
                say(DEBUG_, "Failed to delete %s : '%s'\n", SOCK_PATH, strerror(errno));
            }

            if (bind(sd, (struct sockaddr *)&unaddr, sizeof(struct sockaddr_un)) == -1){
                exit_perror("Failed to bind to socket");
            }

            if (listen(sd, BACKLOG_SIZE) == -1){
                exit_perror("Failed to listen");
            }

            int connsock = accept(sd, NULL, NULL);
            if (connsock == -1){
                exit_perror("accept() error");
            }

            rc = transfer(connsock, output, BUFFER_SIZE);
            close(connsock);
        }
        else{
            // connect so we can use write() instead of send()
            if (connect(sd, (struct sockaddr *)&unaddr, sizeof(struct sockaddr_un)) == -1){
                exit_perror("Failed to connect");
            }
            rc = transfer(input, sd, BUFFER_SIZE);
        }

        if (rc == READ_FAIL){
            exit_perror("Read failure");
        }else if (rc == WRITE_FAIL){
            exit_perror("Write failure");
        }

        if (LISTENER) unlink(SOCK_PATH);
    } /* Unix Domain */

    else{ /* Internet Domain (IPv4/v6) */

        /* 2 positional params expected : ADDRESS and PORT */
        if (argc != optind+2){
            exit_print("Invalid cli specification; see help message\n");
        }
        const char *HOST_ADDR = argv[optind];
        const char *PORT_NUM = argv[++optind];

        struct addrinfo hints;
        struct addrinfo *res = NULL;
        memset(&hints, 0, sizeof(struct addrinfo));

        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = AF_UNSPEC;  /* ipv4 OR ipv6 */
        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV; /* args expected to be numeric specs */

        if ( (rc = getaddrinfo(HOST_ADDR, PORT_NUM, &hints, &res)) != 0 ){
            exit_print("getaddrinfo failure: %s\n", gai_strerror(rc));
        }

        bool found_sock = false;
        for (struct addrinfo *i = res; i; i = i->ai_next){
            sd = socket(i->ai_family, i->ai_socktype, i->ai_protocol);

            if (sd == -1) continue;   /* try another from the list */

            if (!LISTENER){
                found_sock = true;
                break;
            }

            if (bind(sd, i->ai_addr, i->ai_addrlen) == 0){  /* listener */
                found_sock = true;
                break;
            }

            close(sd); /* bind failure */
        }

        freeaddrinfo(res); // no longer needed

        if (!found_sock){
            exit_print("Failed to set up socket. FATAL.\n");
        }

        if (LISTENER){ /* server/receiver */
            if (listen(sd, BACKLOG_SIZE) == -1){
                exit_print("Failed to listen on socket. FATAL.\n");
            }

            /* could be ipv4 OR ipv6; sockaddr_storage is big enough to accommodate either */
            socklen_t addrlen = sizeof(struct sockaddr_storage);
            struct sockaddr_storage peer_addr = {0};
            int connsock = accept(sd, (struct sockaddr *)&peer_addr, &addrlen);
            if (connsock == -1){
                exit_perror("accept() error");
            }
#ifdef USE_TLS
            if (TLS_ENCRYPT){
                say(DEBUG_, " ~ Setting up TLS encryption \n");
                ssl_ctx = get_ssl_ctx();

                /* If the client sends some data over the TLS connection and then immediately
                 * closes its socket, it's very likely the program will be terminated with
                 * SIGPIPE. This is because the server in certain TLS versions or MOs
                 * also sends the client some data -- which leads to the generation of the
                 * aforementioned signal if the client's end of the socket is already
                 * closed. One could either force the server not to send any data or
                 * - better and safer - simply ignore the signal as the client is not
                 *  interested. */
                if (signal(SIGPIPE,SIG_IGN) == SIG_ERR){
                    perror("Failed to change signal disposition");
                    exit(EXIT_FAILURE);
                }
                configure_ssl_ctx(true, auth, ssl_ctx);
                ssl = SSL_new(ssl_ctx);   /* SSL session object */
                SSL_set_fd(ssl, connsock);

                say(DEBUG_, " ~ Looking to accept() incoming TLS connection request\n");
                if (SSL_accept(ssl) != 1){
                    fprintf(stderr, "Failed to accept() TLS conection request\n");
                    ERR_print_errors_fp(stderr);
                    exit(EXIT_FAILURE);
                }

                say(DEBUG_, " ~ Transferring data over TLS\n");
                rc = ssl_transfer(connsock, output, BUFFER_SIZE, ssl, FROM_SSL);

                SSL_shutdown(ssl);
                SSL_free(ssl);
                SSL_CTX_free(ssl_ctx);

                if (rc < 0){
                    ERR_print_errors_fp(stderr);
                    exit_print("failed to read ssl msg\n");
                }
            } /* TLS_ENCRYPT */
            else
            {
#endif /* USE_TLS */
            say(DEBUG_, " ~ Running without TLS encryption\n");
            rc = transfer(connsock, output, BUFFER_SIZE);
#ifdef USE_TLS
            } /* ! TLS_ENCRYPT */
#endif
            close(connsock);
        } /* server/receiver */

        else {  /* client, sender */
            struct sockaddr_storage peer;
            socklen_t addrlen = sizeof(struct sockaddr_storage);
            struct sockaddr_in in;
            struct sockaddr_in6 in6;
            memset(&peer, 0, sizeof(struct sockaddr_storage));
            memset(&in,   0, sizeof(in));
            memset(&in6,  0, sizeof(in6));

            // figure out if cmdline specified ipv4 or ipv6 address
            if (inet_pton(AF_INET, HOST_ADDR, &in.sin_addr) == 1){
                in.sin_port   = htons(strtol(PORT_NUM, NULL, 10));
                in.sin_family = AF_INET;
                memcpy(&peer, &in, sizeof(struct sockaddr_in));
            }
            else if (inet_pton(AF_INET6, HOST_ADDR, &in6.sin6_addr) == 1){
                in6.sin6_family = AF_INET6;
                in6.sin6_port = htons(strtol(PORT_NUM, NULL, 10));
                memcpy(&peer, &in6, sizeof(struct sockaddr_in));
            }else{
                exit_perror("Failed to form peer socket in either AF_INET or AF_INET6");
            }

            if (connect(sd, (struct sockaddr *)&peer, addrlen) == -1){
                exit_perror("Failed to establish connection with peer");
            }

#ifdef USE_TLS
            if (TLS_ENCRYPT){
                say(DEBUG_, " ~ Setting up TLS encryption \n");
                ssl_ctx = get_ssl_ctx();
                configure_ssl_ctx(false, auth, ssl_ctx);
                ssl = SSL_new(ssl_ctx);
                SSL_set_fd(ssl, sd);

                if (SSL_connect(ssl) != 1){
                    ERR_print_errors_fp(stderr);
                    exit_print("Failure when initiating TLS handshake\n");
                }

                rc = ssl_transfer(input, sd, BUFFER_SIZE, ssl, TO_SSL);

                SSL_shutdown(ssl);
                SSL_free(ssl);
                SSL_CTX_free(ssl_ctx);

                if (rc < 0){
                    ERR_print_errors_fp(stderr);
                    exit_print("failed to write ssl msg\n");
                }
            } /* TLS_ENCRYPT */
            else{
#endif /* USE_TLS */
            rc = transfer(input, sd, BUFFER_SIZE);
#ifdef USE_TLS
            } /* !TLS_ENCRYPT */
#endif
        } /* client/sender */

#ifndef USE_TLS
        if (rc == READ_FAIL){
            exit_perror("Read failure");
        }else if (rc == WRITE_FAIL){
            exit_perror("Write failure");
        }
#endif
    } /* Internet Domain (IPv4/v6) */

    if (file && LISTENER)  close(output);  /* server */
    if (file && !LISTENER) close(input);   /* client */
    close(sd);
} /* main() */



/*===========================
  -- Function definitions  --
  ===========================*/
/*
 * Print debug string to stdout IFF flag is true */
void say(int flag, const char *fmt, ...){
    if (!flag) return;

    va_list vargs;
    va_start(vargs, fmt);
    vfprintf(stdout, fmt, vargs);
    va_end(vargs);
}

/*
 * Print cli to stdout */
void show_usage(char **argv){
    printf(
" %s\n"

"SYNOPSYS:\n"
"  IPv4/IPv6:           "
#ifdef USE_TLS
"[-hdel][-f FILE][[--noauth]|[-c CERT][-k KEY]|[-p PSK][--psk-from-file]] <ADDRESS> <PORT>\n"
#else
"[-hdl][-f FILE] <ADDRESS> <PORT>\n"
#endif
"  Unix Domain Sockets: "
"-u [-hdl][-f FILE] <UDS PATH> \n"

"\nOPTIONS:\n"
" -h|--help             show help usage and exit\n"
" -d|--debug            enable debug prints and verbosity\n"
" -f|--file FILE        read contents from file instead of stdin (client) or write contents to file instead of stdout (server)\n"
" -l|--listen           run in listening/server/receiver mode.\n"
" -u|--unix             use Unix Domain Sockets instead of Internet (Ipv4/Ipv6) sockets\n"
#ifdef USE_TLS
" -e|--encrypt          TLS-encrypt communication using the openssl library\n"
" -c|--cert CERT_PATH   use specified TRUSTED certificate for TLS authentication.\n"
" -k|--key KEY_PATH     indicate private key associated with the certificate specified\n"
" -p|--psk PSK          use specified PSK for TLS authentication\n"
"    --psk-from-file    the PSK argument to -p is not the psk itself but a file containing the psk\n"
"    --noauth           use TLS encryption but do NOT authenticate via certificate or PSK\n"
#endif

"\n\n See https://github.com/vcsaturninus/nc FMI.\n",
    argv[0]);
}

/*
 * Reliably write nbytes from the src buffer to the dst descriptor.
 *
 * This function deals with partial writes which may occur due to
 * e.g. signal interrupts. Unless WRITE_FAIL is returned, then the whole
 * nbytes have been written to dst.
 *
 * It also reattempts the write 5 times in a row when the write fails
 * with one of EINTR, EAGAIN or EWOULDBLOCK. If one of those reattempts
 * actually succeeds, the reattempt counter is reset to 0 (meaning if
 * another error like this were to occur, another 5 reattempts would be
 * carried out). These 3 errors may be considered temporary nonfatal
 * conditions so reattempting a write makes sense.
 *
 * Other errors however are likely fatal so reattempting the write in
 * that case is not advisable. The function in that case returns WRITE_FAIL,
 * as it's unlikely write() will succeed and there are probably more
 * significant issues with the system anyway.
 *
 * <-- return
 *     0 on success. Else WRITE_FAIL if write() has failed with an error
 *     considered to be FATAL or if the maximum number of write reattempts
 *     has been reached without success.
 */
int full_write(int dst, char *src, int nbytes){
    int tries         = 0;
    int max_tries     = 5;
    int to_write      = nbytes;
    int bytes_written = 0;

    while(to_write){ /* writing 0 bytes is implementation defined, so do not */
        bytes_written = write(dst, src, to_write);
        if (tries == max_tries) return WRITE_FAIL;
        if (bytes_written == -1){
            if (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK){
                ++tries; continue;
            } else return WRITE_FAIL;
        };
        src      += bytes_written;
        to_write -= bytes_written;
        tries = 0;  /* reset tries */
    } /* while write */

    return 0;
}

/*
 * Read buffsz bytes at a time from src until EOF or error and write to dst
 *
 * An internal buffer will be created of size buffsz which read() will read
 * into and write() will write from.
 *
 * If read() returns:
 * a) -1: transfer() considers it to have failed
 * b) 0 : transfer() considers it to have succeeded but
 *    the internal loop never enters; this is when read
 *    returns EOF. In other words, there is nothing to transfer.
 * c) a certain numbers of bytes that have been read;
 *    In this case the internal loop is entered and write()
 *    will attempt to write that number of bytes to dst.
 *
 * The number of bytes read by `read()` will be written
 * by `write()` in an internal loop, as described above.
 *
 * The full_write() wrapper is used rather than the plain write()
 * in order to attempt recovery from partial writes.
 */
int transfer(int src, int dst, int buffsz){
    char buff[buffsz];
    int16_t bytes_read = 0;
    assert(buffsz <= SSIZE_MAX); /* else udefined behavior */

    while ( (bytes_read = read(src, buff, buffsz)) ){
        if (bytes_read == -1) return READ_FAIL;
        if (full_write(dst, buff, bytes_read) == WRITE_FAIL){
            return WRITE_FAIL;
        }
    } /* while read */

    return 0;
}

#ifdef USE_TLS
/*
 * Like transfer() but either the source or destination is a TLS socket.
 *
 * If dir == FROM_SSL then the source is ssl; if dir == TO_SSL then the
 * destination is ssl.
 *
 * Note that when writing to ssl SSL_write() must be used. Like full_write()
 * this also handled partial writes so SSL_write() either succeeds and writes
 * the number of bytes specified, or it fails.
 *
 * <-- return
 *     0 = success.
 *     READ_FAIL if SSL_read() failed when reading from TLS socket or if
 *     read() failed when reading from src.
 *     WRITE_FAIL if full_write() failed when writing to dst or if SSL_write()
 *     failed when writing to TLS socket.
 */
int ssl_transfer(int src, int dst, int buffsz, SSL *ssl, int dir){
    char buff[buffsz];
    int16_t bytes_read    = 0;
    assert(buffsz <= SSIZE_MAX); /* else implementation-defined */

    if (dir == FROM_SSL){
        while ( (bytes_read = SSL_read(ssl, buff, buffsz)) ){
            if (bytes_read == -1) return READ_FAIL;
            if (full_write(dst, buff, bytes_read)){
                return WRITE_FAIL;
            }
        } /* while read */
    }
    else if(dir == TO_SSL){
        while ( (bytes_read = read(src, buff, BUFFER_SIZE)) ){
            if (bytes_read == -1) return READ_FAIL;
            if (SSL_write(ssl, buff, bytes_read) <= 0){
                return WRITE_FAIL;
            }
        } /* while read */
    }

    return 0;
}

#endif

