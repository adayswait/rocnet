#ifndef ROC_NET_H
#define ROC_NET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>

int roc_set_fd_nonblock(int fd, int nonblock);
int roc_set_tcp_keepalive(int sockfd, int interval);
int roc_tcp_svr(int port, char *bindaddr, int domain, int backlog);
int roc_connect(char *addr, int port, char *source_addr, int flags);
int roc_local_connect(char *path, int flags);
int roc_accept(int sockfd, char *ip, size_t ip_len, int *port);
int roc_local_tcp_svr(char *path, mode_t perm, int backlog);
int roc_local_accpet(int sockfd);
int roc_net_resolve(char *host, char *ipbuf, size_t ipbuf_len, int flags);
int roc_getsockname(int fd, char *ip, size_t ip_len, int *port);
int roc_get_peer_ip_port(int fd, char *ip, size_t ip_len, int *port);
int roc_fmt_addr(char *buf, size_t buf_len, char *ip, int port);
int roc_fmt_peer(int sockfd, char *buf, size_t buf_len);
int roc_fmt_sock(int fd, char *fmt, size_t fmt_len);
int roc_recv(int sockfd, void *buf, int len, int nonblock);
int roc_send(int sockfd, const void *buf, int len, int nonblock);

/**
 * flag = 1 open nodelay
 * flag = 0 close nodelay
 */
static inline int roc_set_tcp_nodelay(int sockfd, int flag)
{
    return setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
}

static inline int roc_set_sock_sndbuf(int sockfd, int size)
{
    return setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
}

/* Set the socket send timeout (SO_SNDTIMEO socket option) to the specified
 * number of milliseconds, or disable it if the 'ms' argument is zero. */
static inline int roc_set_sock_sndtimeo(int sockfd, int64_t ms)
{
    struct timeval tv;

    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* Set the socket receive timeout (SO_RCVTIMEO socket option) to the specified
 * number of milliseconds, or disable it if the 'ms' argument is zero. */
static inline int roc_set_sock_rcvtimeo(int sockfd, int64_t ms)
{
    struct timeval tv;

    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static inline int roc_set_sock_reuseaddr(int sockfd)
{
    int yes = 1;
    /* Make sure connection-intensive things 
     * will be able to close/open sockets a zillion of times */
    return setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
}

#endif /* ROC_NET_H */
