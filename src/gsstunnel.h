/* Copyright (C) 2015 Gsstunnel Contributors, for licensee see COPYING */

#include <stdbool.h>
#include <ini_configobj.h>

#define MAX_MSG_SIZE 1024*1024 /* 1 Mib */
#define AUTOCLEAN(def, fn) def __attribute__ ((__cleanup__(fn)))

enum gterr {
    ERR_UNKNOWN = 0x97110000,
    ERR_BADOPT,
    ERR_BADCONF,
    ERR_LAST
};

struct gt_service {
    char *name;
    bool client;
    char *target_name;
    char *accept;
    char *connect;
    char *exec;
    char **mechs;
    const char **cred_store;
    int cred_count;

    pid_t pid;
};

struct gt_config {
    struct ini_cfgobj *ini_config;

    int num_svcs;
    struct gt_service *svcs;
};

int load_config(const char *cfg_file, struct gt_config *cfg);
int recv_msg(int sd, char *buf, size_t *buflen, bool header);
int send_msg(int sd, char *buf, size_t buflen, bool header);
int init_epoll(int fd1, int fd2, int *efd);
