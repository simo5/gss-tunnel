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

static int runsvc(struct gt_service *svc)
{
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
