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

#include <errno.h>


#define UNUSED(x) (void)(x)

/* call perror() to print msg and then exit with error */
#define perror_exit(msg) do{ perror(msg); exit(EXIT_FAILURE); } while(0);

#define BACKLOG_SIZE 10

/* Show help message for [-h] */
void show_usage(char **argv){
    printf(
" %s\n"
"   [-h]\n"
"   [-f FILE] [-l] ADDRESS PORT\n",
    argv[0]);

    fflush(stdout);
}



int main(int argc, char *argv[]){
    int rc = 0;  /* used to store the return code of various functions */
    int sd = 0;  /* socket descriptor */
    char buff[8192] = {0};  /* 2^13; large buffer to speed up transfer */

    /* flag for running in receiver/server mode */
    int LISTENER = 0;
    char *file = NULL;
    UNUSED(file);       /* only optionally used */

    /*===================
     * -- CLI parsing ---
     *==================*/
    const char *optstring = "lhf:";
    char opt = 0;

    extern int optind;

    while ((opt = getopt(argc, argv, optstring)) != -1){
        switch(opt){
            case 'l':
                LISTENER=1;
                break;

            case 'f':
                file = optarg;
                break;

            case 'h':
                show_usage(argv);
                exit(EXIT_SUCCESS);
                break;

            case '?':
                exit(EXIT_FAILURE);
        }
    }

    /* 2 positional params expected: ADDRESS and PORT */
    if (optind != argc-2){
        fprintf(stderr, "Invalid cli specification; see help message\n");
        exit(EXIT_FAILURE);
    }
    const char *HOST_ADDR = argv[optind];
    const char *PORT_NUM = argv[optind+1];


    /*=====================
     * -- Socket setup ---
     *====================*/
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;  /* ipv4 OR ipv6 */
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV; /* args expected to be numeric specs */
    
    if ( (rc = getaddrinfo(HOST_ADDR, PORT_NUM, &hints, &res)) != 0 ){
        fprintf(stderr, "getaddrinfo failure: %s\n", gai_strerror(rc));
        exit(EXIT_FAILURE);
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
        fprintf(stderr, "Failed to set up socket. FATAL.\n");
        exit(EXIT_FAILURE);
    }
     
    if (LISTENER){ /* server/receiver */
        if (listen(sd, BACKLOG_SIZE) == -1){
            fprintf(stderr, "Failed to listen on socket. FATAL.\n");
            exit(EXIT_FAILURE);
        }
        
        socklen_t addrlen = sizeof(struct sockaddr_storage);
        struct sockaddr_storage peer_addr = {0};
        int connsock = accept(sd, (struct sockaddr *)&peer_addr, &addrlen);

        if (connsock == -1){
            perror_exit("accept() error");
        }
        
        /* where the write the sender's message */
        int outstream = 1; /* stdout */
        if (file){
            mode_t perms = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;
            if ((outstream = open(file, O_CREAT|O_WRONLY|O_APPEND, perms)) == -1){
                perror_exit("Failed to open file for writing");
            }
        }

        int bytes_read = 0;
        while ( (bytes_read = read(connsock, buff, sizeof(buff))) ){
            if (bytes_read == -1){
                perror_exit("Failed to read from socket");
            }
            
            if (write(outstream, buff, bytes_read) != bytes_read){
                // todo: deal with case where errno is simply EINT for partial writes
                perror_exit("write failure");
            } /* write */
        } /* while loop */

        if (file) close(outstream);
        close(sd);
    } /* server/receiver */

    else {  /* client, sender */
        int instream = 0;  
        if (file){
            if ((instream = open(file, O_RDONLY)) == -1){
                perror_exit("Failed to open file for reading");
            }
        }

        struct sockaddr_storage peer;
        memset(&peer, 0, sizeof(struct sockaddr_storage));
        socklen_t addrlen = sizeof(struct sockaddr_storage);

        printf("host is %s\n", HOST_ADDR);
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
        memset(&in, 0, sizeof(in));
        memset(&in6, 0, sizeof(in6));

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
            perror_exit("Failed to form peer socket in either AF_INET or AF_INET6");
        }

        //if (connect(sd, (struct sockaddr *)&peer_addr, addrlen) == -1){
        if (connect(sd, (struct sockaddr *)&peer, addrlen) == -1){
            perror_exit("Failed to establish connection with peer");
        }

        int bytes_read = 0;
        while ( (bytes_read = read(instream, buff, sizeof(buff))) ){
            if (bytes_read == -1){
                perror_exit("Failed to read from stream");
            }
            
            if (write(sd, buff, bytes_read) != bytes_read){
                puts("two");
                // todo: deal with case where errno is simply EINT for partial writes
                perror_exit("write failure");
            } /* write */
        } /* while loop */

        if (file) close(instream);
        close(sd);
    } /* client/sender */

} /* main */



