#ifndef ROC_SVR_H
#define ROC_SVR_H
#include "roc_evt.h"
#include "roc_log.h"
#include "roc_ringbuf.h"

struct roc_svr_s;
struct roc_link_s;
typedef struct roc_svr_s roc_svr;
typedef struct roc_link_s roc_link;

typedef void roc_handle_func_link(roc_link *link);
typedef void roc_handle_func_svr(roc_svr *svr);
typedef int roc_send_func(roc_link *link, void *buf, int len);
typedef void roc_log_func(int level, const char *format, ...);

typedef struct
{
    void *so_handle;
    void *data_so_handle;
    roc_handle_func_link *connect_handler;
    roc_handle_func_link *recv_handler;
    roc_handle_func_link *close_handler;

    roc_handle_func_svr *init_handler;
    roc_handle_func_svr *fini_handler;
} roc_plugin;

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
    roc_handle_func_link *handler[ROC_SOCK_EVTEND];
    roc_plugin *plugin;
    roc_send_func *send;
    roc_log_func *log;
};

struct roc_link_s
{
    int fd;
    int port;
    char *ip;
    roc_ringbuf *ibuf;
    roc_ringbuf *obuf;
    roc_evt_loop *evt_loop;
    roc_handle_func_link *handler[ROC_SOCK_EVTEND];
    roc_svr *svr;
};
roc_svr *roc_svr_new(int port, char *plugin_path);
int roc_init(const char *log_path, int log_level);
int roc_run();
int roc_svr_start(roc_svr *svr);
int roc_svr_stop(roc_svr *svr);
int roc_smart_send(roc_link *link, void *buf, int len);
void roc_svr_on(roc_svr *svr, int evt_type, roc_handle_func_link *handler);
void roc_link_on(roc_link *link, int evt_type, roc_handle_func_link *handler);

#endif /* ROC_SVR_H */
