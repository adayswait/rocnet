#ifndef ROC_SVR_H
#define ROC_SVR_H
#include "roc_evt.h"
#include "roc_ringbuf.h"

struct roc_svr_s;
struct roc_link_s;
typedef struct roc_svr_s roc_svr;
typedef struct roc_link_s roc_link;

typedef void roc_handle_func(roc_link *link);

struct roc_svr_s
{
    int fd;
    int port;
    int domain;
    int type;
    int backlog;
    int maxlink;
    int nonblock;
    roc_evt_loop *evt_loop;
    roc_handle_func *handler[ROC_SOCK_EVTEND];
};

struct roc_link_s
{
    int fd;
    int port;
    char *ip;
    roc_ringbuf *ibuf;
    roc_ringbuf *obuf;
    roc_evt_loop *evt_loop;
    roc_handle_func *handler[ROC_SOCK_EVTEND];
};
int roc_init();
int roc_run();
roc_link *roc_link_new(int fd, char *ip, int port);
roc_svr *roc_svr_new(int port);
static inline void roc_link_del(roc_link *link);
int roc_svr_start(roc_svr *svr);
int roc_svr_stop(roc_svr *svr);
static int roc_dispatch_ioevt(roc_link *link, int mask);
static void roc_pretreat_data(roc_evt_loop *el, int fd,
                              void *custom_data, int mask);
int roc_smart_send(roc_link *link);

#endif /* ROC_SVR_H */
