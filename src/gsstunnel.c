/* Copyright (C) 2015 Gsstunnel Contributors, for licensee see COPYING */

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/epoll.h>
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
#include <gssapi/gssapi.h>

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

struct gss_err {
    gss_buffer_desc buf;
    OM_uint32 maj;
    OM_uint32 min;
};

static void autofreegsserr(struct gss_err *err)
{
    if (err->maj) {
        fprintf(stderr, "--- {ERROR IN PROCESSING GSS ERROR}\n");
    }
    (void)gss_release_buffer(&err->min, &err->buf);
}

static void gt_gss_error(char *name, gss_OID mech, uint32_t maj, uint32_t min)
{
    AUTOCLEAN(struct gss_err err, autofreegsserr) = { {0}, 0, 0};
    OM_uint32 msgctx;

    fprintf(stderr, "[%s] Failed with:", name);

    if (mech != GSS_C_NO_OID) {
        err.maj = gss_oid_to_str(&err.min, mech, &err.buf);
        if (err.maj != GSS_S_COMPLETE) return;
        fprintf(stderr, " (OID: %s)", (char *)err.buf.value);
        (void)gss_release_buffer(&err.min, &err.buf);
    }

    msgctx = 0;
    err.maj = gss_display_status(&err.min, maj, GSS_C_GSS_CODE,
                                 mech, &msgctx, &err.buf);
    if (err.maj != GSS_S_COMPLETE) return;
    fprintf(stderr, " %s,", (char *)err.buf.value);
    (void)gss_release_buffer(&err.min, &err.buf);

    msgctx = 0;
    err.maj = gss_display_status(&err.min, min, GSS_C_MECH_CODE,
                                 mech, &msgctx, &err.buf);
    if (err.maj != GSS_S_COMPLETE) return;
    fprintf(stderr, " %s\n", (char *)err.buf.value);
    (void)gss_release_buffer(&err.min, &err.buf);
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

static void autofreegssname(gss_name_t *name)
{
    OM_uint32 ignore;
    (void)gss_release_name(&ignore, name);
}

static void autofreegsscred(gss_cred_id_t *cred)
{
    OM_uint32 ignore;
    (void)gss_release_cred(&ignore, cred);
}

static void autofreegssctx(gss_ctx_id_t *ctx)
{
    OM_uint32 ignore;
    gss_buffer_desc out;
    (void)gss_delete_sec_context(&ignore, ctx, &out);
}

static void autofreegssbuf(gss_buffer_t buf)
{
    OM_uint32 ignore;
    (void)gss_release_buffer(&ignore, buf);
}

#define MAX_EVENTS 4
static int tunnel(struct gt_service *svc, int fd, struct sockaddr *cliaddr)
{
    AUTOCLEAN(char *tmbuf, autofreestr) = NULL;
    AUTOCLEAN(struct addrinfo *addr, autofreeaddrinfo) = NULL;
    AUTOCLEAN(int sd, autofreesocket) = -1;
    AUTOCLEAN(int efd, autofreesocket) = -1;
    AUTOCLEAN(gss_name_t name, autofreegssname) = GSS_C_NO_NAME;
    AUTOCLEAN(gss_name_t srcname, autofreegssname) = GSS_C_NO_NAME;
    AUTOCLEAN(gss_cred_id_t cred, autofreegsscred) = GSS_C_NO_CREDENTIAL;
    AUTOCLEAN(gss_ctx_id_t ctx, autofreegssctx) = GSS_C_NO_CONTEXT;
    AUTOCLEAN(gss_buffer_desc output, autofreegssbuf) = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc input = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc  namebuf;
    OM_uint32 maj, min;
    OM_uint32 ignore;
    struct epoll_event events[MAX_EVENTS];
    size_t tmlen;
    int pfd; /* plain text fd */
    int cfd; /* cipher text fd */
    int ret;
    int do_once = 0;
    char answer[1];

    /* We allocate a 16 KiB buffer for messages, that's also the maximum msg
     * size */
    tmbuf = malloc(MAX_MSG_SIZE);
    if (!tmbuf) return ENOMEM;

    if (svc->exec) {
        fprintf(stderr, "[%s] EXEC option not supported yet, sorry!\n",
                        svc->name);
        return ENOTSUP;
    }

    ret = string_to_addrinfo(svc->connect, &addr);
    if (ret) return ret;

    errno = 0;
    sd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (sd == -1) return errno;

    ret = connect(sd, addr->ai_addr, addr->ai_addrlen);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "[%s] Failed to connect to server '%s': %s\n",
                        svc->name, svc->connect, strerror(ret));
        return ret;
    }

    if (svc->target_name) {
        namebuf.length = strlen(svc->target_name);
        namebuf.value = svc->target_name;
        maj = gss_import_name(&min, &namebuf,
                              GSS_C_NT_HOSTBASED_SERVICE, &name);
        if (maj != GSS_S_COMPLETE) {
            fprintf(stderr, "[%s] Failed to import name: '%s' (%d/%d)\n",
                            svc->name, svc->target_name,
                            (int)maj, (int)min);
            return EINVAL;
        }
    }

    if (svc->client) {
        pfd = fd;
        cfd = sd;

        do {
            if (do_once == 0) {
                char gssencrequest[] = { 0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x30 };
                ret = send(cfd, gssencrequest, 8, 0);
                fprintf(stderr, "postgres send gssencrequest return: %d\n", ret);
                ret = recv(cfd, answer, 1, 0);
                fprintf(stderr, "postgres recv gssencrequest answer: %s\n", answer);
                fprintf(stderr, "postgres recv gssencrequest return: %d\n", ret);
                if (answer[0] != 'G') {
                    fprintf(stderr, "did not get a GSS 'G' response");
                    return 1;
                }
                do_once = 1;
            }

            maj = gss_init_sec_context(&min, cred, &ctx, name, GSS_C_NO_OID,
                                       GSS_C_MUTUAL_FLAG
                                        | GSS_C_REPLAY_FLAG
                                        | GSS_C_SEQUENCE_FLAG
                                        | GSS_C_CONF_FLAG
                                        | GSS_C_INTEG_FLAG, 0,
                                       GSS_C_NO_CHANNEL_BINDINGS,
                                       &input, NULL, &output, NULL, NULL);

            if (maj != GSS_S_COMPLETE && maj != GSS_S_CONTINUE_NEEDED) {
                gt_gss_error(svc->name, GSS_C_NO_OID, maj, min);
                return EBADE;
            }

            if (output.length > MAX_MSG_SIZE) return ENOSPC;
            if (output.length > 0) {
                memcpy(tmbuf, output.value, output.length);
                tmlen = output.length;
                (void)gss_release_buffer(&ignore, &output);

                ret = send_msg(cfd, tmbuf, tmlen, true);
                if (ret) return ret;
            }

            if (maj == GSS_S_CONTINUE_NEEDED) {
                tmlen = MAX_MSG_SIZE;
                ret = recv_msg(cfd, tmbuf, &tmlen, true);
                if (ret) return ret;

                input.value = tmbuf;
                input.length = tmlen;
            }

        } while (maj == GSS_S_CONTINUE_NEEDED);

    } else {
        pfd = sd;
        cfd = fd;

        if (name != GSS_C_NO_NAME) {
            maj = gss_acquire_cred(&min, name, GSS_C_INDEFINITE,
                                   GSS_C_NO_OID_SET, GSS_C_ACCEPT,
                                   &cred, NULL, NULL);
            if (maj != GSS_S_COMPLETE) {
                fprintf(stderr,
                        "[%s] Failed to acquire creds for '%s' (%d/%d)\n",
                        svc->name, svc->target_name?svc->target_name:"",
                        (int)maj, (int)min);
                return EIO;
            }
        }

        do {
            tmlen = MAX_MSG_SIZE;
            ret = recv_msg(cfd, tmbuf, &tmlen, true);
            if (ret) return ret;

            input.value = tmbuf;
            input.length = tmlen;

            maj = gss_accept_sec_context(&min, &ctx, cred, &input,
                                         GSS_C_NO_CHANNEL_BINDINGS, &srcname,
                                         NULL, &output, NULL, NULL, NULL);

            if (maj != GSS_S_COMPLETE && maj != GSS_S_CONTINUE_NEEDED) {
                gt_gss_error(svc->name, GSS_C_NO_OID, maj, min);
                return EBADE;
            }

            if (output.length > MAX_MSG_SIZE) return ENOSPC;
            if (output.length > 0) {
                memcpy(tmbuf, output.value, output.length);
                tmlen = output.length;
                (void)gss_release_buffer(&ignore, &output);

                ret = send_msg(cfd, tmbuf, tmlen, true);
                if (ret) return ret;
            }

        } while (maj == GSS_S_CONTINUE_NEEDED);
    }

    /* negotiation completed, now handle traffic */

    ret = init_epoll(cfd, pfd, &efd);
    if (ret) return ret;

    while (efd != -1) {
        struct epoll_event *ev;
        int n;
        n = epoll_wait(efd, events, MAX_EVENTS, -1);
        if (n == -1) {
            ret = errno;
            if (ret == EINTR) continue;
            return ret;
        }
        for (int i = 0; i < n; i++) {
            ev = &events[i];
            if (ev->events & (EPOLLERR|EPOLLHUP)) {
                /* one of the peers gave up */
                return ENOLINK;
            }

            /* RECEIVE */

            tmlen = MAX_MSG_SIZE;
            ret = recv_msg(ev->data.fd, tmbuf, &tmlen, (ev->data.fd == cfd));
            if (ret) return ret;

            if (ev->data.fd == cfd) {
                /* sender encrypts */
                input.value = tmbuf;
                input.length = tmlen;
                maj = gss_unwrap(&min, ctx, &input, &output, NULL, NULL);
                if (maj != GSS_S_COMPLETE) {
                    gt_gss_error(svc->name, GSS_C_NO_OID, maj, min);
                    return EIO;
                }
                if (output.length > MAX_MSG_SIZE) return ENOSPC;
                memcpy(tmbuf, output.value, output.length);
                tmlen = output.length;
                (void)gss_release_buffer(&ignore, &output);
            }

            /* RESEND */
            if (ev->data.fd == pfd) {
                /* receiver encrypts */
                input.value = tmbuf;
                input.length = tmlen;
                maj = gss_wrap(&min, ctx, 1, 0, &input, NULL, &output);
                if (maj != GSS_S_COMPLETE) {
                    gt_gss_error(svc->name, GSS_C_NO_OID, maj, min);
                    return EIO;
                }
                if (output.length > MAX_MSG_SIZE) return ENOSPC;
                memcpy(tmbuf, output.value, output.length);
                tmlen = output.length;
                (void)gss_release_buffer(&ignore, &output);
            }

            /* send to the other fd, add header only if we encrypted */
            ret = send_msg((ev->data.fd == pfd)?cfd:pfd,
                           tmbuf, tmlen, (ev->data.fd == pfd));
            if (ret) return ret;
        }
    }

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
            fprintf(stderr, "Service terminated: %s\n", err_string(ret));
            return 3;
        }
    }

    return 0;
}
