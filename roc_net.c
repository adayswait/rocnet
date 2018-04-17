#include "roc_net.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>

int roc_set_fd_nonblock(int fd, int non_block)
{
    int flags;

    /* Set the socket blocking (if non_block is zero) or non-blocking.
     * Note that fcntl(2) for F_GETFL and F_SETFL can't be
     * interrupted by a signal. */
    if ((flags = fcntl(fd, F_GETFL)) == -1)
    {
        return -1;
    }

    if (non_block)
    {
        flags |= O_NONBLOCK;
    }
    else
    {
        flags &= ~O_NONBLOCK;
    }
    if (fcntl(fd, F_SETFL, flags) == -1)
    {
        return -1;
    }
    return 0;
}

/* Set TCP keep alive option to detect dead peers. The interval option
 * is only used for Linux as we are using Linux-specific APIs to set
 * the probe send time, interval, and count. */
int roc_set_tcp_keepalive(int sockfd, int interval)
{
    int val = 1;

    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) == -1)
    {
        return -1;
    }

#ifdef __linux__
    /* Default settings are more or less garbage, with the keepalive time
     * set to 7200 by default on Linux. Modify settings to make the feature
     * actually useful. */

    /* Send first probe after interval. */
    val = interval;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val)) < 0)
    {
        return -1;
    }

    /* Send next probes after the specified interval. Note that we set the
     * delay as interval / 3, as we send three probes before detecting
     * an error (see the next setsockopt call). */
    val = interval / 3;
    if (val == 0)
    {
        val = 1;
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val)) < 0)
    {
        return -1;
    }

    /* Consider the socket in error state after three we send three ACK
     * probes without getting a reply. */
    val = 3;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val)) < 0)
    {
        return -1;
    }
#else
    ((void)interval); /* Avoid unused var warning for non Linux systems. */
#endif

    return 0;
}

/* roc_net_resolve() resolves the hostname "host" and set the string
 * representation of the IP address into the buffer pointed by "ipbuf".
 *
 * If (flags & 1) the function only resolves hostnames
 * that are actually already IPv4 or IPv6 addresses. This turns the function
 * into a validating / normalizing function. */
int roc_net_resolve(char *host, char *ipbuf, size_t ipbuf_len, int flags)
{
    struct addrinfo hints, *info;
    int rv;

    memset(&hints, 0, sizeof(hints));
    if (flags & 1)
    {
        hints.ai_flags = AI_NUMERICHOST;
    }
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM; /* specify socktype to avoid dups */

    if ((rv = getaddrinfo(host, NULL, &hints, &info)) != 0)
    {
        return -1;
    }
    if (info->ai_family == AF_INET)
    {
        struct sockaddr_in *sa = (struct sockaddr_in *)info->ai_addr;
        inet_ntop(AF_INET, &(sa->sin_addr), ipbuf, ipbuf_len);
    }
    else
    {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)info->ai_addr;
        inet_ntop(AF_INET6, &(sa->sin6_addr), ipbuf, ipbuf_len);
    }

    freeaddrinfo(info);
    return 0;
}

static int roc_create_sock(int domain, int type)
{
    if (type != SOCK_STREAM || type != SOCK_DGRAM)
    {
        return -1;
    }
    int sockfd;
    if ((sockfd = socket(domain, type, 0)) == -1)
    {
        return -1;
    }
    return sockfd;
}

/**
 * (flags & (1 << 0)) 创建非阻塞模式socket
 * (flags & (1 << 1)) 尝试绑定到source_addr
 */
int roc_connect(char *addr, int port, char *source_addr, int flags)
{
    int sockfd = -1, rv;
    char portstr[6]; /* strlen("65535") + 1; */
    struct addrinfo hints, *servinfo, *bservinfo, *p, *b;

    snprintf(portstr, sizeof(portstr), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(addr, portstr, &hints, &servinfo)) != 0)
    {
        return -1;
    }
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        /* Try to create the socket and to connect it.
         * If we fail in the socket() call, or on connect(), we retry with
         * the next entry in servinfo. */
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
            continue;
        if (roc_set_sock_reuseaddr(sockfd) == -1)
            goto error;
        if (flags & (1 << 0) && roc_set_fd_nonblock(sockfd, 1) != 0)
            goto error;
        if (source_addr)
        {
            int bound = 0;
            /* Using getaddrinfo saves us from self-determining IPv4 vs IPv6 */
            if ((rv = getaddrinfo(source_addr, NULL, &hints, &bservinfo)) != 0)
            {
                goto error;
            }
            for (b = bservinfo; b != NULL; b = b->ai_next)
            {
                if (bind(sockfd, b->ai_addr, b->ai_addrlen) != -1)
                {
                    bound = 1;
                    break;
                }
            }
            freeaddrinfo(bservinfo);
            if (!bound)
            {
                goto error;
            }
        }
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            /* If the socket is non-blocking, it is ok for connect() to
             * return an EINPROGRESS error here. */
            if (errno == EINPROGRESS && flags & (1 << 0))
                goto end;
            close(sockfd);
            sockfd = -1;
            continue;
        }

        /* If we ended an iteration of the for loop without errors, we
         * have a connected socket. Let's return to the caller. */
        goto end;
    }

error:
    if (sockfd != -1)
    {
        close(sockfd);
        sockfd = -1;
    }

end:
    freeaddrinfo(servinfo);

    /* Handle best effort binding: if a binding address was used, but it is
     * not possible to create a socket, try again without a binding address. */
    if (sockfd == -1 && source_addr && (flags & (1 << 1)))
    {
        return roc_connect(addr, port, NULL, flags);
    }
    else
    {
        return sockfd;
    }
}

/**
 * (flags & (1 << 0)) 创建非阻塞模式socket
 * (flags & (1 << 1)) 尝试绑定到source_addr
 */
int roc_local_connect(char *path, int flags)
{
    int sockfd;
    struct sockaddr_un sa;

    if ((sockfd = roc_create_sock(AF_LOCAL, SOCK_STREAM)) == -1)
    {
        return -1;
    }
    if (roc_set_sock_reuseaddr(sockfd) == -1)
    {
        return -1;
    }

    sa.sun_family = AF_LOCAL;
    strncpy(sa.sun_path, path, sizeof(sa.sun_path) - 1);
    if (flags & (1 << 0))
    {
        if (roc_set_fd_nonblock(sockfd, 1) != 0)
        {
            close(sockfd);
            return -1;
        }
    }
    if (connect(sockfd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
    {
        if (errno == EINPROGRESS && flags & (1 << 0))
            return sockfd;

        close(sockfd);
        return -1;
    }
    return sockfd;
}

static int roc_listen(int sockfd, struct sockaddr *sa,
                      socklen_t len, int backlog)
{
    if (bind(sockfd, sa, len) == -1)
    {
        close(sockfd);
        return -1;
    }

    if (listen(sockfd, backlog) == -1)
    {
        close(sockfd);
        return -1;
    }
    return 0;
}

static int roc_set_sock_ipv6only(int sockfd)
{
    int yes = 1;
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes)) == -1)
    {
        close(sockfd);
        return -1;
    }
    return 0;
}

int roc_tcp_svr(int port, char *bindaddr, int af, int backlog)
{
    int sockfd = -1, rv;
    char _port[6]; /* strlen("65535") */
    struct addrinfo hints, *servinfo, *p;

    snprintf(_port, 6, "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; /* No effect if bindaddr != NULL */

    if ((rv = getaddrinfo(bindaddr, _port, &hints, &servinfo)) != 0)
    {
        return -1;
    }
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            continue;
        }
        if (af == AF_INET6 && roc_set_sock_ipv6only(sockfd) == -1)
        {
            goto error;
        }

        if (roc_set_sock_reuseaddr(sockfd) == -1)
        {
            goto error;
        }
        if (roc_listen(sockfd, p->ai_addr, p->ai_addrlen, backlog) == -1)
        {
            sockfd = -1;
        }

        goto end;
    }
    if (p == NULL)
    {
        goto error;
    }

error:
    if (sockfd != -1)
    {
        close(sockfd);
    }
    sockfd = -1;
end:
    freeaddrinfo(servinfo);
    return sockfd;
}

/**
 * AF_LOCAL || AF_UNIX
 */
int roc_local_tcp_svr(char *path, mode_t perm, int backlog)
{
    int sockfd;
    struct sockaddr_un sa;

    if ((sockfd = roc_create_sock(AF_LOCAL, SOCK_STREAM)) == -1)
    {
        return -1;
    }
    if (roc_set_sock_reuseaddr(sockfd) == -1)
    {
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_LOCAL;
    strncpy(sa.sun_path, path, sizeof(sa.sun_path) - 1);
    if (roc_listen(sockfd, (struct sockaddr *)&sa, sizeof(sa), backlog) == -1)
    {
        return -1;
    }
    if (perm)
    {
        chmod(sa.sun_path, perm);
    }
    return sockfd;
}

static int _roc_accept(int sockfd, struct sockaddr *sa, socklen_t *len)
{
    int fd;
    while (1)
    {
        fd = accept(sockfd, sa, len);
        if (fd == -1)
        {
            if (errno == EINTR)
                continue;
            else
            {
                return -1;
            }
        }
        break;
    }
    return fd;
}

int roc_accept(int sockfd, char *ip, size_t ip_len, int *port)
{
    int fd;
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    if ((fd = _roc_accept(sockfd, (struct sockaddr *)&sa, &salen)) == -1)
    {
        return -1;
    }

    if (sa.ss_family == AF_INET)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
        if (ip)
        {
            inet_ntop(AF_INET, (void *)&(sin->sin_addr), ip, ip_len);
        }
        if (port)
        {
            *port = ntohs(sin->sin_port);
        }
    }
    else
    {
        struct sockaddr_in6 *sin = (struct sockaddr_in6 *)&sa;
        if (ip)
        {
            inet_ntop(AF_INET6, (void *)&(sin->sin6_addr), ip, ip_len);
        }
        if (port)
        {
            *port = ntohs(sin->sin6_port);
        }
    }
    return fd;
}

/**
 * AF_UNIX || AF_LOCAL
 */
int roc_local_accpet(int sockfd)
{
    int fd;
    struct sockaddr_un sa;
    socklen_t salen = sizeof(sa);
    if ((fd = _roc_accept(sockfd, (struct sockaddr *)&sa, &salen)) == -1)
        return -1;

    return fd;
}

int roc_get_peer_ip_port(int fd, char *ip, size_t ip_len, int *port)
{
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);

    if (getpeername(fd, (struct sockaddr *)&sa, &salen) == -1)
    {
        goto error;
    }
    if (ip_len == 0)
    {
        goto error;
    }

    if (sa.ss_family == AF_INET)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
        if (ip)
        {
            inet_ntop(AF_INET, (void *)&(sin->sin_addr), ip, ip_len);
        }
        if (port)
        {
            *port = ntohs(sin->sin_port);
        }
    }
    else if (sa.ss_family == AF_INET6)
    {
        struct sockaddr_in6 *sin = (struct sockaddr_in6 *)&sa;
        if (ip)
        {
            inet_ntop(AF_INET6, (void *)&(sin->sin6_addr), ip, ip_len);
        }
        if (port)
        {
            *port = ntohs(sin->sin6_port);
        }
    }
    else if (sa.ss_family == AF_LOCAL)
    {
        if (ip)
        {
            strncpy(ip, "/localsocket", ip_len);
        }
        if (port)
        {
            *port = 0;
        }
    }
    else
    {
        goto error;
    }
    return 0;

error:
    if (ip)
    {
        if (ip_len >= 2)
        {
            ip[0] = '?';
            ip[1] = '\0';
        }
        else if (ip_len == 1)
        {
            ip[0] = '\0';
        }
    }
    if (port)
    {
        *port = 0;
    }
    return -1;
}

/* Format an IP,port pair into something easy to parse. If IP is IPv6
 * (matches for ":"), the ip is surrounded by []. IP and port are just
 * separated by colons.  */
int roc_fmt_addr(char *buf, size_t buf_len, char *ip, int port)
{
    return snprintf(buf, buf_len,
                    strchr(ip, ':') ? "[%s]:%d" : "%s:%d", ip, port);
}

/* Like roc_fmt_addr() but extract ip and port from the socket's peer. */
int roc_fmt_peer(int sockfd, char *buf, size_t buf_len)
{
    char ip[INET6_ADDRSTRLEN];
    int port;

    roc_get_peer_ip_port(sockfd, ip, sizeof(ip), &port);
    return roc_fmt_addr(buf, buf_len, ip, port);
}

/**
 * 在一个没有调用bind的TCP客户上,connect成功返回后
 * roc_getsockname用于返回由内核赋予该连接的本地IP地址和本地端口号。
 */
int roc_getsockname(int fd, char *ip, size_t ip_len, int *port)
{
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);

    if (getsockname(fd, (struct sockaddr *)&sa, &salen) == -1)
    {
        if (port)
        {
            *port = 0;
        }
        ip[0] = '?';
        ip[1] = '\0';
        return -1;
    }
    if (sa.ss_family == AF_INET)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
        if (ip)
        {
            inet_ntop(AF_INET, (void *)&(sin->sin_addr), ip, ip_len);
        }
        if (port)
        {
            *port = ntohs(sin->sin_port);
        }
    }
    else
    {
        struct sockaddr_in6 *sin = (struct sockaddr_in6 *)&sa;
        if (ip)
        {
            inet_ntop(AF_INET6, (void *)&(sin->sin6_addr), ip, ip_len);
        }
        if (port)
        {
            *port = ntohs(sin->sin6_port);
        }
    }
    return 0;
}

int roc_fmt_sock(int fd, char *fmt, size_t fmt_len)
{
    char ip[INET6_ADDRSTRLEN];
    int port;

    roc_getsockname(fd, ip, sizeof(ip), &port);
    return roc_fmt_addr(fmt, fmt_len, ip, port);
}

int roc_recv(int sockfd, void *buf, int len, int nonblock)
{
    int recvd_bytes, ret_len;

    for (recvd_bytes = 0; recvd_bytes < len; recvd_bytes += ret_len)
    {
        ret_len = recv(sockfd, buf + recvd_bytes, len - recvd_bytes, 0);

        if (ret_len == 0) /*connection closed by client*/
        {
            return 0;
        }
        if (ret_len == -1)
        {
            if (errno == EINTR)
            {
                ret_len = 0;
                continue;
            }
            else if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return recvd_bytes;
            }
            else
            {
                return -1;
            }
        }
        if (nonblock == 0)
        {
            return ret_len;
        }
    }

    return recvd_bytes;
}

int roc_send(int sockfd, const void *buf, int len, int nonblock)
{
    int sent_bytes, ret_len;

    for (sent_bytes = 0; sent_bytes < len; sent_bytes += ret_len)
    {
        ret_len = send(sockfd, buf + sent_bytes, len - sent_bytes, 0);
        if (ret_len == -1)
        {
            if (errno == EINTR)
            {
                ret_len = 0;
                continue;
            }
            else if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return sent_bytes;
            }
            else
            {
                return -1;
            }
        }
        if (nonblock == 0)
        {
            return ret_len;
        }
    }

    return sent_bytes;
}