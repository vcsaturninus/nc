#ifndef NC_H__
#define NC_H__

/* call perror() to print msg and then exit with error */
#define exit_perror(msg) do{ perror(msg); exit(EXIT_FAILURE); } while(0);

/* print msg to stderr and then exit with error */
#define exit_print(...) do{ fprintf(stderr, __VA_ARGS__); exit(EXIT_FAILURE); } while(0);

/* true if strings a and b are the same, else false */
#define matches(a,b) (!strcmp(a,b))

void say(int flag, const char *fmt, ...);


#endif
