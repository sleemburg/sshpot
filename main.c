#include "config.h"
#include "auth.h"

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>

#define MINPORT 0
#define MAXPORT 65535


/* for keeping track of the maximum number of forks (connections) */

#define MINCONN 1

#ifndef MAXCONN
#define MAXCONN 20
#endif

#define STATE_FREE  0
#define STATE_CONN  1

typedef struct conntab {
    int state;
    pid_t pid;
} TPconntab;

static TPconntab *conntab = NULL;
static int maxconn = DEF_CONNECTIONS;
static int curconn = 0;

/* Global so they can be cleaned up at SIGINT. */
static ssh_session session;
static ssh_bind sshbind;

/* Print usage information to `stream', exit with `exit_code'. */
static void usage(FILE *stream, int exit_code) {
    fprintf(stream, "Usage: sshpot [-h] [-p <port>] [-m <connections>]\n");
    fprintf(stream,
            "   -h  --help              Display this usage information.\n"
            "   -p  --port <port>       Port to listen on; defaults to 22.\n"
            "   -m  --max <connections> Maximum number of connections;"
                                       " defaults to %d.\n", DEF_CONNECTIONS);
    exit(exit_code);
}

/* Return the c-string `p' as an int if it is a valid value 
 * in the range of minval - maxval, or -1 if invalid. */
static int valid_intval(char *p, int minval, int maxval) {
    int intval;
    char *endptr;

    intval = strtol(p, &endptr, 10);
    if (intval >= minval && intval <= maxval && !*endptr && errno == 0) 
        return intval;

    return -1;
}

/* Return the c-string `p' as an int if it is a valid port 
 * in the range of MINPORT - MAXPORT, or -1 if invalid. */
static int valid_port(char *p) {
    return valid_intval(p, MINPORT, MAXPORT);
}

/* Signal handler for cleaning up after children. We want to do cleanup
 * at SIGCHILD instead of waiting in main so we can accept multiple
 * simultaneous connections. */
static int cleanup(void) {
    int i;
    int status;
    pid_t pid;
    pid_t wait3(int *statusp, int options, struct rusage *rusage);

    while ((pid=wait3(&status, WNOHANG, NULL)) > 0) {
        for (i = 0; i < maxconn; i++)
        {
            if (conntab[i].pid == pid)
            {
                    conntab[i].pid = 0;
                    conntab[i].state = STATE_FREE;
                    curconn--;
            }
        }
        if (DEBUG) { printf("process %d reaped\n", pid); }
    }

    /* Re-install myself for the next child. */
    signal(SIGCHLD, (void (*)())cleanup);

    return 0;
}


/* SIGINT handler. Cleanup the ssh* objects and exit. */
static void wrapup(void) {
    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_finalize();
    exit(0);
}


int main(int argc, char *argv[]) {
    register int i;
    int port = DEFAULTPORT;

    /* Handle command line options. */
    int next_opt = 0;
    const char *short_opts = "hp:m:";
    const struct option long_opts[] = {
        { "help",   0, NULL, 'h' },
        { "port",   1, NULL, 'p' },
        { "max",    1, NULL, 'm' },
        { NULL,     0, NULL, 0   }
    };

    while (next_opt != -1) {
        next_opt = getopt_long(argc, argv, short_opts, long_opts, NULL);
        switch (next_opt) {
            case 'h':
                usage(stdout, 0);
                break;

            case 'p':
                if ((port = valid_port(optarg)) < 0) {
                    fprintf(stderr, "Port must range from %d - %d\n\n", MINPORT, MAXPORT);
                    usage(stderr, 1);
                }
                break;

            case 'm':
                if ((maxconn = valid_intval(optarg, MINCONN, MAXCONN)) < 0) {
                    fprintf(stderr, "Max must range from %d - %d\n\n", MINCONN, MAXCONN);
                    usage(stderr, 1);
                }

                break;

            case '?':
                usage(stderr, 1);
                break;

            case -1:
                break;

            default:
                fprintf(stderr, "Fatal error, aborting...\n");
                exit(1);
        }
    }

    /* There shouldn't be any other parameters. */
    if (argv[optind]) {
        fprintf(stderr, "Invalid parameter `%s'\n\n", argv[optind]);
        usage(stderr, 1);
    }

    if ((conntab = (TPconntab *) malloc(maxconn * sizeof(TPconntab))) == NULL) {
        fprintf(stderr, "Cannot allocate a connection table for %d slots\n\n", maxconn);
        usage(stderr, 1);
    }

    for (i = 0; i < maxconn; i++)
        conntab[i].state = STATE_FREE;

    /* Install the signal handlers to cleanup after children and at exit. */
    signal(SIGCHLD, (void (*)())cleanup);
    signal(SIGINT, (void(*)())wrapup);

    /* Create and configure the ssh session. */
    sshbind=ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, LISTENADDRESS);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, "ssh-rsa");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY,RSA_KEYFILE);

    /* Listen on `port' for connections. */
    if (ssh_bind_listen(sshbind) < 0) {
        printf("Error listening to socket: %s\n",ssh_get_error(sshbind));
        return -1;
    }
    if (DEBUG) { printf("Listening on port %d.\n", port); }

    /* Loop forever, waiting for and handling connection attempts. */
    while (1) {
        int i;
        pid_t pid;

        if (curconn == maxconn)
        {
            (void) usleep(500000);
            continue;
        }
        session=ssh_new();

        if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
            fprintf(stderr, "Error accepting a connection: `%s'.\n",ssh_get_error(sshbind));
            return -1;
        }
        if (DEBUG) { printf("Accepted a connection.\n"); }

        switch ((pid = fork()))  {
            case -1:
                fprintf(stderr,"Fork returned error: `%d'.\n",-1);
                exit(-1);

            case 0:
                exit(handle_auth(session));

            default:
                for (i = 0; i < maxconn; i++)
                    if (conntab[i].state == STATE_FREE)
                    {
                        conntab[i].state = STATE_CONN;
                        conntab[i].pid = pid;
                        curconn++;
                        break;
                    }
                ssh_free(session);
                break;
        }
    }

    return 0;
}
