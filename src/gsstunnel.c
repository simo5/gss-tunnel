/* Copyright (C) 2015 Gsstunnel Contributors, for licensee see COPYING */

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "popt.h"

#ifdef HAVE_NLS
#include <libintl.h>
#define _(s) dgettext(PACKAGE, (s))
#else
#define _(s) (s)
#endif
#define N_(s) s

#include "gsstunnel.h"

static const char *err_strs[] = {
                        N_("Unknown Error"),
    /* ERR_BADOPT */    N_("Invalid option"),
    /* ERR_BADCONF */   N_("Invalid configuration"),
};

static const char *err_string(int err)
{
    if (err < ERR_UNKNOWN || err >= ERR_LAST) {
        return strerror(err);
    }
    return err_strs[err - ERR_UNKNOWN];
}

static void autofreestr(char **memaddr)
{
    free(*memaddr);
}

static int string_to_addrinfo(char *str,
                              struct addrinfo **addr)
{
    struct addrinfo hints = {0};
    AUTOCLEAN(char *address, autofreestr) = NULL;
    char *port;
    int ret;

    address = strdup(str);
    if (!address) return ENOMEM;

    port = strchr(address, ']');
    if (port) {
        /* assume ipv6 */
        port[0] = '\0';
        memmove(address, address + 1, port - address - 1);
        if (port[1] != ':' || port[2] == '\0') {
            fprintf(stderr, "Invalid IPV6 address or port for '%s'\n", str);
            return EINVAL;
        }
        port += 2;
    } else {
        port = strchr(address, ':');
        if (port) {
            /* assume ipv4 or dns name */
            port[0] = '\0';
            if (port[1] == '\0') {
                fprintf(stderr, "Invalid address or port for '%s'\n", str);
                return EINVAL;
            }
            port += 1;
        } else {
            /* port undefined */
            fprintf(stderr, "Missing port for '%s'\n", str);
            return EINVAL;
        }
    }

    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    ret = getaddrinfo(address, port, &hints, addr);
    if (ret) {
        fprintf(stderr, "Failed to resolve address '%s': %s\n",
                str, gai_strerror(ret));
        return EINVAL;
    }

    return 0;
}

static void autofreeaddrinfo(struct addrinfo **addr)
{
    freeaddrinfo(*addr);
}

static void autofreesocket(int *sd)
{
    if (*sd != -1) close(*sd);
    *sd = -1;
}

static int tunnel(struct gt_service *svc, int fd, struct sockaddr *peer)
{
    return 0;
}

static int runsvc(struct gt_service *svc)
{
    AUTOCLEAN(struct addrinfo *addr, autofreeaddrinfo) = NULL;
    AUTOCLEAN(int sd, autofreesocket) = -1;
    struct sockaddr_storage peer;
    socklen_t peerlen;
    pid_t pid;
    int opt;
    int ret;

    if (!svc->accept ||
        (!svc->connect &&
         !svc->exec)) {
        return ERR_BADCONF;
    }

    errno = 0;
    pid = fork();

    if (pid) {
        /* parent */
        if (pid == -1) {
            return errno;
        }
        svc->pid = pid;
        return 0;
    }

    ret = string_to_addrinfo(svc->accept, &addr);
    if (ret) return ret;

    errno = 0;
    sd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (sd == -1) return errno;

    opt = 1;
    ret = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "[%s] Failed to set SO_REUSEADDR on socket: %s\n",
                        svc->name, strerror(ret));
    }

    ret = bind(sd, addr->ai_addr, addr->ai_addrlen);
    if (ret == -1) return errno;

    ret = listen(sd, 5);
    if (ret == -1) return errno;

    while (1) {
        int fd;

        errno = 0;
        peerlen = sizeof(struct sockaddr_storage);
        fd = accept(sd, (struct sockaddr *)(&peer), &peerlen);
        if (fd == -1) {
            ret = errno;
            if (ret == ECONNABORTED || ret == EINTR) continue;
            fprintf(stderr, "Service '%s' aborting, on accpet() error: %s\n",
                            svc->name, strerror(ret));
            return ret;
        }

        /* recycle children, if any terminated */
        (void)waitpid(-1, NULL, WNOHANG);

        errno = 0;
        pid = fork();
        if (pid) {
            /* parent */
            close(fd);

            if (pid == -1) {
                fprintf(stderr, "Failed to fork() for service '%s': %s\n",
                                svc->name, strerror(errno));
            }
        } else {
            /* child */
            return tunnel(svc, fd, (struct sockaddr *)(&peer));
        }
    }

    return 0;
}

static void waitchildren(int *werr)
{
    int w;
    do {
        w = waitpid(-1, werr, 0);
    } while ((w != -1) || (*werr == EINTR));
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int opt_version = 0;
    char *opt_config_file = NULL;
    int opt_debug = 0;
    struct gt_config cfg = {0};
    int ret;
    AUTOCLEAN(int werr, waitchildren) = 0;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        {"config", 'c', POPT_ARG_STRING, &opt_config_file, 0, \
         _("Specify a non-default config file"), NULL}, \
        {"debug", 'd', POPT_ARG_NONE, &opt_debug, 0, \
         _("Enable debugging"), NULL}, \
         {"version", '\0', POPT_ARG_NONE, &opt_version, 0, \
          _("Print version number and exit"), NULL }, \
        POPT_TABLEEND
    };

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\n%s %s: %s\n\n", err_string(ERR_BADOPT),
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }

    if (opt_version) {
        puts(VERSION""DISTRO_VERSION""PRERELEASE_VERSION);
        return 0;
    }

    ret = load_config(opt_config_file, &cfg);
    if (ret) {
        fprintf(stderr, "Failed to load config file '%s': %s\n",
                opt_config_file, err_string(ret));
        return 2;
    }

    for (int i = 0; i < cfg.num_svcs; i++) {
        ret = runsvc(&cfg.svcs[i]);
        if (ret) {
            fprintf(stderr, "Failed to start service: %s\n", err_string(ret));
            return 3;
        }
    }

    return 0;
}
