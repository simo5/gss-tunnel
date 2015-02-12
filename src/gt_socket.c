/* Copyright (C) 2015 Gsstunnel Contributors, for licensee see COPYING */

#include "config.h"
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "gsstunnel.h"

int recv_msg(int sd, char *buf, size_t *buflen, bool header)
{
    size_t recvlen = *buflen;
    size_t count = 0;
    size_t total = 0;
    int flags = 0;
    uint32_t tmp;
    ssize_t len;

    if (header) {
        flags = MSG_WAITALL;

        len = recv(sd, &tmp, sizeof(uint32_t), flags);
        if (len != sizeof(uint32_t)) {
            if (len == 0) return ENOLINK;
            return EBADE;
        }
        total = ntohl(tmp);

        if (total > *buflen) {
            return EMSGSIZE;
        }

        recvlen = total;
    }

    do {
        errno = 0;
        len = recv(sd, &buf[count], recvlen, flags);
        switch (len) {
        case -1:
            if (errno == EAGAIN || errno == EINTR) continue;
            return errno;
        case 0:
            return ENOLINK;
        default:
            recvlen -= len;
            count += len;
            break;
        }
        /* we continue only if total was set (we had a header)
         * and count is not there yet */
    } while (count < total);

    (*buflen) = count;
    return 0;
}

int send_msg(int sd, char *buf, size_t buflen, bool header)
{
    size_t count = 0;
    size_t total = 0;
    uint32_t tmp;
    ssize_t len;
    int ret;

    if (header) {
        tmp = htonl(buflen);

        ret = 0;
        do {
            errno = 0;
            len = send(sd, &tmp, sizeof(uint32_t), MSG_MORE);
            if (len != sizeof(uint32_t)) {
                if (len == -1) {
                    if (errno == EINTR || errno == EAGAIN) continue;
                    return errno;
                }
                return EIO;
            }
        } while (ret != 0);
    }

    total = buflen;

    while (count < total) {
        errno = 0;
        len = send(sd, &buf[count], total - count, 0);
        switch (len) {
        case -1:
            if (errno == EAGAIN || errno == EINTR) continue;
            return errno;
        default:
            count += len;
            break;
        }
    }

    return 0;
}

static int init_epoll_addfd(int efd, int fd)
{
    struct epoll_event ev;
    int ret;

    ev.events = EPOLLIN;
    ev.data.fd = fd;
    ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
    if (ret == -1) {
        ret = errno;
        fprintf(stderr, "Failed to ADD epoll FD: %s\n", strerror(ret));
        return ret;
    }

    return 0;
}

int init_epoll(int fd1, int fd2, int *efd)
{
    int ret;

    *efd = epoll_create(1);
    if (*efd == -1) {
        ret = errno;
        fprintf(stderr, "Failed to create epoll FD: %s\n", strerror(ret));
        return ret;
    }

    ret = init_epoll_addfd(*efd, fd1);
    if (ret) return ret;

    ret = init_epoll_addfd(*efd, fd2);
    if (ret) return ret;

    return 0;
}
