/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <asm/unistd.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>
#include <linux/mount.h>
#include <fcntl.h>
#include <sys/mount.h>

#include "bpfilter/helper.h"
#include "bpfilter/logger.h"

#define CMD_LEN 64
static char cmd[CMD_LEN];

struct st_opts
{
    const char *socket_path;
    const char *bpffs_mount_path;
};

static error_t st_opts_parser(int key, const char *arg, struct argp_state *state)
{
    struct st_opts *opts = state->input;

    switch (key) {
    case 's':
        opts->socket_path = arg;
        break;
    case 'b':
        opts->bpffs_mount_path = arg;
        break;
    case ARGP_KEY_END:
        if (!opts->socket_path)
            return bf_err_r(-EINVAL, "--socket argument required");
        if (!opts->bpffs_mount_path)
            opts->bpffs_mount_path = "/sys/fs/bpf";
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static inline void usage(void)
{
    bf_err("usage: setup_token_bin COMMAND [OPTIONS...]");
}

int send_fd(int sock_fd, int fd)
{
    struct msghdr msg = {};
    struct cmsghdr *cmsg;
    int fds[1] = { fd };
    char iobuf[1];
    struct iovec io = {
        .iov_base = iobuf,
        .iov_len = sizeof(iobuf),
    };
    union {
        char buf[CMSG_SPACE(sizeof(fds))];
        struct cmsghdr align;
    } u;
    int r;

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = u.buf;
    msg.msg_controllen = sizeof(u.buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fds));
    memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));

    r = sendmsg(sock_fd, &msg, 0);
    if (r < 0)
        return bf_err_r(errno, "send_fd: failed to send message");
    if (r != 1)
        return bf_err_r(-EINVAL, "send_fd: unexpected amount of data sent (%d)", r);

    return 0;
}

int recv_fd(int sock_fd)
{
    struct msghdr msg = {};
    struct cmsghdr *cmsg;
    int fds[1];
    char iobuf[1];
    struct iovec io = {
        .iov_base = iobuf,
        .iov_len = sizeof(iobuf),
    };
    union {
        char buf[CMSG_SPACE(sizeof(fds))];
        struct cmsghdr align;
    } u;
    int r;

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = u.buf;
    msg.msg_controllen = sizeof(u.buf);

    r = recvmsg(sock_fd, &msg, 0);
    if (r < 0)
        return bf_err_r(errno, "recv_fd: failed to receive message");
    if (r != 1)
        return bf_err_r(r, "recv_fd: unexpected amount of data received (%d)", r);

    cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg)
        return bf_err_r(-EINVAL, "recv_fd: cmsg is NULL");
    if (cmsg->cmsg_len != CMSG_LEN(sizeof(fds)))
        return bf_err_r(-EINVAL, "recv_fd: cmsg has unexpected length");
    if (cmsg->cmsg_level != SOL_SOCKET)
        return bf_err_r(-EINVAL, "recv_fd: cmsg has unexpected level");
    if (cmsg->cmsg_type != SCM_RIGHTS)
        return bf_err_r(-EINVAL, "recv_fd: cmsg has unexpected type");

    memcpy(fds, CMSG_DATA(cmsg), sizeof(fds));

    return fds[0];
}

int do_in(const struct st_opts *opts)
{
    _cleanup_close_ int sock_fd = -1;
    _cleanup_close_ int bpffs_fd = -1;
    _cleanup_close_ int mount_fd = -1;
    struct sockaddr_un addr = {};
    int r;

    /**
     * Get socket
     */
    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0)
        return bf_err_r(errno, "do_in: can't create socket");

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, opts->socket_path, sizeof(addr.sun_path) - 1);

    r = connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (r < 0)
        return bf_err_r(errno, "do_in: failed to connect to socket at %s", opts->socket_path);

    /**
     * Configure bpffs to allow for BPF tokens
     */
    bpffs_fd = fsopen("bpf", 0);
    if (bpffs_fd < 0)
        return bf_err_r(errno, "do_in: failed to open BPF filesystem");

    r = send_fd(sock_fd, bpffs_fd);
    if (r)
        return bf_err_r(r, "do_in: failed to send file descriptor");

    mount_fd = recv_fd(sock_fd);
    if (mount_fd < 0)
        return bf_err_r(mount_fd, "do_in: failed to receive mount fd");

    r = move_mount(mount_fd, "", AT_FDCWD, opts->bpffs_mount_path, MOVE_MOUNT_F_EMPTY_PATH);
    if (r)
        return bf_err_r(errno, "failed to move mount");

    return 0;
}

int do_out(const struct st_opts *opts)
{
    _cleanup_close_ int sock_fd = -1;
    _cleanup_close_ int client_fd = -1;
    _cleanup_close_ int bpffs_fd = -1;
    _cleanup_close_ int mnt_fd = -1;
    struct sockaddr_un addr = {};
    int r;

    /**
     * Configure a socket
     */
    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0)
        return bf_err_r(errno, "do_out: failed to create socket");

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, opts->socket_path, sizeof(addr.sun_path) - 1);

    r = bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (r < 0)
        return bf_err_r(errno, "do_out: failed to bind socket to %s", opts->socket_path);

    r = listen(sock_fd, 1);
    if (r)
        return bf_err_r(errno, "do_out: failed to listen to connections");

    client_fd = accept(sock_fd, NULL, NULL);
    if (client_fd < 0)
        return bf_err_r(errno, "do_out: failed to accept connection");

    /**
     * Receive a bpffs FD
     */
    bpffs_fd = recv_fd(client_fd);
    if (bpffs_fd < 0)
        return bf_err_r(bpffs_fd, "do_out: failed to receive file descriptor");

    r = fsconfig(bpffs_fd, FSCONFIG_SET_STRING, "delegate_cmds", "any", 0);
    if (r)
        return bf_err_r(r, "do_out: failed to set 'delegate_cmds'");

    r = fsconfig(bpffs_fd, FSCONFIG_SET_STRING, "delegate_maps", "any", 0);
    if (r)
        return bf_err_r(r, "do_out: failed to set 'delegate_maps'");

    r = fsconfig(bpffs_fd, FSCONFIG_SET_STRING, "delegate_progs", "any", 0);
    if (r)
        return bf_err_r(r, "do_out: failed to set 'delegate_progs'");

    r = fsconfig(bpffs_fd, FSCONFIG_SET_STRING, "delegate_attachs", "any", 0);
    if (r)
        return bf_err_r(r, "do_out: failed to set 'delegate_attachs'");

    r = fsconfig(bpffs_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
    if (r)
        return bf_err_r(r, "do_out: failed to create fsconfig");

    mnt_fd = fsmount(bpffs_fd, 0, 0);
    if (mnt_fd < 0)
        return bf_err_r(mnt_fd, "do_out: failed to fsmount bpffs");

    /**
     * Send the FD back
     */
    r = send_fd(client_fd, mnt_fd);
    if (r)
        return bf_err_r(r, "do_out: failed to send file descriptor");

    return 0;
}

int main(int argc, char *argv[])
{
    static struct argp_option options[] = {
        {"socket", 's', "SOCKET_PATH", 0, "Path to the socket to use to communicate", 0},
        {"bpffs-mount-path", 'b', "BPFFS_MOUNT_PATH", 0, "Path to mount the bpffs with delegated attributes. Defaults to /sys/fs/bpf.", 0},
        {0},
    };

    const char *command;
    struct st_opts opts = {};
    struct argp argp = {
        options, (argp_parser_t)st_opts_parser,
        NULL,    NULL,
        0,       NULL,
        NULL,
    };
    int r;

    if (argc < 2 || argv[1][0] == '-') {
        usage();
        return EXIT_FAILURE;
    }

    command = argv[1];

    snprintf(cmd, CMD_LEN, "%s %s", argv[0], argv[1]);
    argv[1] = cmd;
    argv++;
    argc--;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r)
        return bf_err_r(r, "failed to parse arguments");

    if (bf_streq(command, "in")) {
        r = do_in(&opts);
    } else if (bf_streq(command, "out")) {
        r = do_out(&opts);
    } else {
        usage();
        return EXIT_FAILURE;
    }

    return r;

    return 0;
}
