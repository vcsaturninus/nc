#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>      /* exit() */
#include <netdb.h>       /* getaddrinfo() */
#include <sys/socket.h>  /* struct socket */
#include <string.h>      /* memset() */
#include <unistd.h>
#include <fcntl.h>       /* open() */
#include <sys/stat.h>    /* mode_t constants */
#include <arpa/inet.h>   /* inet_pton */
#include <sys/un.h>      /* struct sockaddr_un */
#include <errno.h>

/*============
  -- Macros --
  ===========*/

/* silence unused variable warning */
#define UNUSED(x) (void)(x)

/* call perror() to print msg and then exit with error */
#define exit_perror(msg) do{ perror(msg); exit(EXIT_FAILURE); } while(0);

/* print msg to stderr and then exit with error */
#define exit_print(...) do{ fprintf(stderr, __VA_ARGS__); exit(EXIT_FAILURE); } while(0);

/* Size of accept() backlog */
#define BACKLOG_SIZE 10

/* buffer size for connect utility function */
#define BUFFER_SIZE 8192  /* 2^13; large buffer to speed up transfer */


/*===================
  -- Declarations --
  ==================*/

/* IO failure return codes */
enum {READ_FAIL=-1, WRITE_FAIL=-2};

/* Show help message for [-h] */
void show_usage(char **argv);

/* read bytes from src and write to dst until EOF or error */
int transfer(int src, int dst);




int main(int argc, char *argv[]){
    int rc = 0;          /* used to store the return code of various functions */
    int sd = 0;          /* socket descriptor */

    int LISTENER = 0;    /* flag for running in receiver/server mode */
    int UNIX_DOMAIN = 0; /* flag to use unix domain sockets */

    char *file = NULL;   /* optionally specified input/output file */
    UNUSED(file);

    /*==================
     * -- CLI parsing --
     *=================*/
    const char *optstring = "f:hlu";
    char opt = 0;

    extern int optind;
    extern char *optarg;

    while ((opt = getopt(argc, argv, optstring)) != -1){
        switch(opt){
            case 'l':
                LISTENER=1;
                break;

            case 'f':
                file = optarg;
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

    /* where to read and write from:
       1) client reads from stdin or file and sends to server via socket
       2) server reads from socket and writes to stdout or file */
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

    /*====================
     * -- Socket logic --
     *===================*/
    if (UNIX_DOMAIN){
        /* 1 positional param expected: path to unix domain socket */
        if (argc != optind+1){
            exit_print("Invalid cli specification; see help message\n");
        }
        char *SOCK_PATH = argv[optind];

        if (( sd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1){
            exit_perror("Failed to create Unix Domain socket");
        }

        struct sockaddr_un unaddr;
        memset(&unaddr, 0, sizeof(struct sockaddr_un));
        unaddr.sun_family = AF_UNIX;
        strncpy(unaddr.sun_path, SOCK_PATH, sizeof(unaddr.sun_path)-1);

        if (LISTENER){
            if (unlink(SOCK_PATH) == -1 && errno != ENOENT){
                fprintf(stderr, "Failed to delete %s : '%s'\n", SOCK_PATH, strerror(errno));
            }

            if (bind(sd, (struct sockaddr *)&unaddr, sizeof(struct sockaddr_un)) == -1){
                exit_perror("Failed to bind to socket");
            }
            rc = transfer(sd, output);
        }
        else{
            // connect so we can use write instead of send
            if (connect(sd, (struct sockaddr *)&unaddr, sizeof(struct sockaddr_un)) == -1){
                exit_perror("Failed to connect");
            }
            rc = transfer(input, sd);
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
        const char *PORT_NUM = argv[optind+1];

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

            if (bind(sd, i->ai_addr, i->ai_addrlen) == 0){
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

            socklen_t addrlen = sizeof(struct sockaddr_storage);
            struct sockaddr_storage peer_addr = {0};
            int connsock = accept(sd, (struct sockaddr *)&peer_addr, &addrlen);

            if (connsock == -1){
                exit_perror("accept() error");
            }

            rc = transfer(connsock, output);
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
                in.sin_port = htons(strtol(PORT_NUM, NULL, 10));
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

            rc = transfer(input, sd);
        } /* client/sender */

        if (rc == READ_FAIL){
            exit_perror("Read failure");
        }else if (rc == WRITE_FAIL){
            exit_perror("Write failure");
        }
    } /* Internet Domain (IPv4/v6) */

    if (file && LISTENER)  close(output);  /* server */
    if (file && !LISTENER) close(input);   /* client */
    close(sd);
} /* main() */



/*===========================
  -- Function definitions  --
  ===========================*/
void show_usage(char **argv){
    printf(
" %s\n"
"   [-h]\n"
" \nIPv4/IPv6:\n"
"   [-f FILE] [-l] <ADDRESS> <PORT>\n"
" Unix Domain Sockets:\n"
"   [-f FILE] [-l] <UDS PATH> \n",
    argv[0]);

    fflush(stdout);
}

int transfer(int src, int dst){
    int16_t bytes_read = 0;
    char buff[BUFFER_SIZE] = {0};

    while ( (bytes_read = read(src, buff, BUFFER_SIZE)) ){
        if (bytes_read == -1) return READ_FAIL;

        if (write(dst, buff, bytes_read) != bytes_read){
            // todo: deal with case where errno is simply EINT for partial writes
            return WRITE_FAIL;
        } /* write */
    } /* while loop */

    return 0;
}


