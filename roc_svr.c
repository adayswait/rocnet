#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <sys/socket.h>
#include "roc_svr.h"
#include "roc_net.h"
#include "roc_evt.h"
#include "roc_log.h"
#include "roc_daemon.h"
#include "roc_plugin.h"
#include "roc_ringbuf.h"
#include "roc_threadpool.h"

#define MAX_LINK_PER_SVR 65535
#define ROC_THREAD_MAX_NUM 1024

int flush_log_interval = 3000;
int svr_thread_num = 4; /* default 4 threads */

roc_work work_arr[ROC_THREAD_MAX_NUM];
roc_evt_loop *default_loop;

uint32_t curr_loop_offset = 0;

static void roc_work_func(roc_work *w)
{
    roc_evt_loop *thread_loop = (roc_evt_loop *)(w->data);
    roc_evt_loop_start(thread_loop);
}

static int roc_flush_log_func(roc_evt_loop *evt_loop,
                              int64_t id, void *intptr_interval)
{

    roc_log_flush();
    return *((int *)intptr_interval);
}

int roc_init(const char *log_path, int log_level)
{
    //roc_daemon_start(); /* 测试时暂时屏蔽,正式环境建议开启 */
    if (roc_log_init(log_path, log_level) == -1)
    {
        return -1;
    }
    ROC_LOG_STDERR("log inited\n");
    default_loop = roc_create_evt_loop(MAX_LINK_PER_SVR);

    if (!default_loop)
    {
        return -1;
    }
    if (roc_add_time_evt(default_loop, flush_log_interval,
                         roc_flush_log_func, &flush_log_interval) == -1)
    {
        return -1;
    }

    char *val = getenv("ROC_THREADPOOL_SIZE");
    if (val != NULL)
    {
        svr_thread_num = atoi(val);
    }
    int i;
    for (i = 0; i < svr_thread_num; i++)
    {
        roc_evt_loop *thread_loop = roc_create_evt_loop(MAX_LINK_PER_SVR);
        roc_work w;
        work_arr[i] = w;
        roc_tpwork_submit(&work_arr[i], roc_work_func, thread_loop);
    }
    signal(SIGPIPE, SIG_IGN);
    ROC_LOG_STDERR("roc inited\n");
    return 0;
}

int roc_run()
{
    roc_evt_loop_start(default_loop);
    return 0;
}

static inline void roc_link_del(roc_link *link, void *custom_data)
{
    roc_del_io_evt(link->evt_loop, link->fd, ROC_EVENT_IOET);
    if (link->handler[ROC_SOCK_CLOSE])
    {
        link->handler[ROC_SOCK_CLOSE](link, NULL);
    }
    close(link->fd);
    roc_ringbuf_del(link->ibuf);
    roc_ringbuf_del(link->obuf);
    free(link->ip);
    free(link);
}

roc_svr *roc_svr_new(int port)
{
    roc_svr *svr = (roc_svr *)malloc(sizeof(roc_svr));
    if (!svr)
    {
        return NULL;
    }
    if (!default_loop)
    {
        free(svr);
        return NULL;
    }
    svr->port = port;
    svr->domain = AF_INET;
    svr->type = SOCK_STREAM;
    svr->backlog = 65535;
    svr->maxlink = 65535;
    svr->nonblock = 1;
    svr->next_plugin_level = 0;
    svr->evt_loop = default_loop;
    int i;
    for (i = 0; i < ROC_PLUGIN_MAX; i++)
    {
        svr->plugin[i].level = -1;
    }
    for (i = 0; i < ROC_SOCK_EVTEND; i++)
    {
        svr->handler[i] = NULL;
    }
    svr->close_link = roc_link_del;
    svr->send = roc_smart_send;
    svr->log = roc_log_write;

    return svr;
}

void roc_svr_on(roc_svr *svr, int evt_type, roc_handle_func_link *handler)
{
    if (evt_type < ROC_SOCK_EVTEND)
    {
        svr->handler[evt_type] = handler;
    }
}
int roc_svr_use(roc_svr *svr, char *plugin_path)
{
    int i;
    for (i = 0; i < ROC_PLUGIN_MAX; i++)
    {
        if (svr->plugin[i].level != -1)
        {
            continue;
        }
        svr->plugin[i].level = i;
        if (register_plugin(&svr->plugin[i], plugin_path, 0) == -1)
        {
            free(svr);
            return -1;
        }
        return 0;
    }
    return -1;
}

static roc_link *roc_link_new(int fd, char *ip, int port, roc_svr *svr)
{
    roc_link *link = (roc_link *)malloc(sizeof(roc_link));
    if (!link)
    {
        return NULL;
    }
    link->ip = malloc(16);
    if (!link->ip)
    {
        free(link);
        return NULL;
    }
    memcpy(link->ip, ip, 16);
    link->ibuf = roc_ringbuf_new(1024);
    if (!link->ibuf)
    {
        free(link->ip);
        free(link);
        return NULL;
    }
    link->obuf = roc_ringbuf_new(1024);
    if (!link->obuf)
    {
        free(link->ip);
        roc_ringbuf_del(link->ibuf);
        free(link);
        return NULL;
    }
    int i;
    for (i = 0; i < ROC_SOCK_EVTEND; i++)
    {
        link->handler[i] = NULL;
    }
    link->port = port;
    link->fd = fd;
    link->svr = svr;
    link->next_plugin_level = 0;
    return link;
}

void roc_link_on(roc_link *link, int evt_type, roc_handle_func_link *handler)
{
    if (evt_type < ROC_SOCK_EVTEND)
    {
        (void)__sync_lock_test_and_set(&link->handler[evt_type], handler);
    }
}

static int roc_smart_recv(roc_link *link)
{
    roc_ringbuf *rb = link->ibuf;

    uint32_t len = roc_ringbuf_unused(rb);
    if (len == 0)
    {
        roc_ringbuf_resize(rb, rb->size + 1);
        return roc_smart_recv(link);
    }
    uint32_t tail_capacity = min(len, rb->size - (rb->tail & (rb->size - 1)));

    int ret;
    if (tail_capacity)
    {
        ret = roc_recv(link->fd,
                       rb->data + (rb->tail & (rb->size - 1)),
                       tail_capacity, 1);
        if (ret == -1) /* link closed by client or error occur */
        {
            roc_link_del(link, NULL);
            return -1;
        }
        if (ret == 0)
        {
            return 0;
        }
        rb->tail += ret;
        if (ret != tail_capacity)
        {
            return 0;
        }
    }

    uint32_t head_capacity = len - tail_capacity;
    if (head_capacity)
    {
        ret = roc_recv(link->fd, rb->data, head_capacity, 1);
        if (ret == -1) /* link closed by client or error occur */
        {
            roc_link_del(link, NULL);
            return -1;
        }
        if (ret == 0)
        {
            return 0;
        }
        rb->tail += ret;
    }

    if (roc_ringbuf_unused(rb) == 0)
    {
        roc_ringbuf_resize(rb, rb->size + 1);
        return roc_smart_recv(link);
    }
    return 0;
}
static void roc_pretreat_data(roc_evt_loop *el, int fd,
                              void *custom_data, int mask)
{
    roc_link *link = (roc_link *)custom_data;

    if (mask & ROC_EVENT_INPUT)
    {
        if (roc_smart_recv(link) == -1)
        {
            return;
        }
        if (link->handler[ROC_SOCK_DATA])
        {
            link->handler[ROC_SOCK_DATA](link, NULL);
        }
    }
    if (mask & ROC_EVENT_OUTPUT)
    {
        if (!roc_ringbuf_readable(link->obuf))
        {
            return;
        }
        if (roc_smart_send(link, NULL, 0) == -1)
        {
            return;
        }
    }
}

static int roc_dispatch_ioevt(roc_link *link, int mask)
{
    uint32_t next_loopid = curr_loop_offset % svr_thread_num;
    roc_evt_loop *el = (roc_evt_loop *)(work_arr[next_loopid].data);
    if (roc_add_io_evt(el, link->fd, mask, roc_pretreat_data, link) == -1)
    {
        roc_link_del(link, NULL);
        return -1;
    }
    link->evt_loop = el;
    curr_loop_offset++;
    return 0;
}

static void roc_auto_accept(roc_evt_loop *el, int fd,
                            void *custom_data, int mask)
{
    int cport;
    char ip_addr[16] = {0};
    int cfd = roc_accept(fd, ip_addr, sizeof(ip_addr), &cport);
    if (cfd <= 0)
    {
        return;
    }
    if (roc_set_fd_nonblock(cfd, 1) == -1)
    {
        close(cfd);
        return;
    }

    roc_svr *svr = (roc_svr *)custom_data;
    if (!svr)
    {
        close(cfd);
        return;
    }

    if (svr->handler[ROC_SOCK_CONNECT])
    {
        roc_link *link = roc_link_new(cfd, ip_addr, cport, svr);
        if (!link)
        {
            close(cfd);
            return;
        }
        svr->handler[ROC_SOCK_CONNECT](link, NULL);
        roc_dispatch_ioevt(link, ROC_EVENT_IOET);
    }
}
int roc_smart_send(roc_link *link, void *buf, int len)
{
    roc_ringbuf *rb = link->obuf;
    if (buf && len)
    {
        roc_ringbuf_write(rb, buf, len);
    }

    uint32_t rblen = roc_ringbuf_used(rb);
    uint32_t head_n = min(rblen, rb->size - (rb->head & (rb->size - 1)));

    int ret;
    if (head_n)
    {
        ret = roc_send(link->fd,
                       rb->data + (rb->head & (rb->size - 1)),
                       head_n, 1);
        if (ret == -1)
        {
            roc_link_del(link, NULL);
            return -1;
        }
        if (ret == 0)
        {
            return 0;
        }
        rb->head += ret;

        if (ret != head_n)
        {
            return roc_smart_send(link, NULL, 0);
        }
    }

    uint32_t tail_n = rblen - head_n;
    if (tail_n)
    {
        ret = roc_send(link->fd, rb->data, tail_n, 1);
        if (ret == -1)
        {
            roc_link_del(link, NULL);
            return -1;
        }
        if (ret == 0)
        {
            return 0;
        }
        rb->head += ret;
        if (ret != tail_n)
        {
            return roc_smart_send(link, NULL, 0);
        }
    }

    return 0;
}

int roc_svr_start(roc_svr *svr)
{
    svr->fd = roc_tcp_svr(svr->port, NULL, svr->domain, svr->backlog);
    if (svr->fd == -1)
    {
        free(svr);
        return -1;
    }
    if (svr->nonblock && roc_set_fd_nonblock(svr->fd, 1) == -1)
    {
        free(svr);
        return -1;
    }
    if (roc_add_io_evt(svr->evt_loop, svr->fd, ROC_EVENT_INPUT,
                       roc_auto_accept, svr) == -1)
    {
        free(svr);
        return -1;
    }
    if (svr->plugin[0].level != -1)
    {
        svr->plugin[0].init_handler(svr, NULL);
    }
    return 0;
}
int roc_svr_stop(roc_svr *svr)
{
    roc_del_io_evt(svr->evt_loop, svr->fd, ROC_EVENT_INPUT);
    if (svr->plugin[0].level != -1)
    {
        svr->plugin[0].fini_handler(svr, NULL);
    }
    close(svr->fd);
    free(svr);
    return 0;
}
