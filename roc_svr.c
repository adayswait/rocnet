#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "roc_svr.h"
#include "roc_net.h"
#include "roc_evt.h"
#include "roc_threadpool.h"

#define MAX_LINK_PER_SVR 65535
#define ROC_THREAD_NUM 4

roc_work work_arr[ROC_THREAD_NUM];
roc_evt_loop *default_loop;

unsigned int curr_loop_offset = 0;

static void roc_work_func(roc_work *w)
{
    roc_evt_loop *thread_loop = (roc_evt_loop *)(w->data);
    roc_evt_loop_start(thread_loop);
}

int roc_init()
{
    default_loop = roc_create_evt_loop(MAX_LINK_PER_SVR);
    if (!default_loop)
    {
        return -1;
    }
    int i;
    for (i = 0; i < ROC_THREAD_NUM; i++)
    {
        roc_evt_loop *thread_loop = roc_create_evt_loop(MAX_LINK_PER_SVR);
        roc_work w;
        work_arr[i] = w;
        roc_tpwork_submit(&work_arr[i], roc_work_func, thread_loop);
    }
}
int roc_run()
{
    roc_evt_loop_start(default_loop);
    return 0;
}

void roc_svr_on(roc_svr *svr, int evt_type, roc_handle_func *handler)
{
    if (evt_type < ROC_SOCK_EVTEND)
    {
        svr->handler[ROC_SOCK_CONNECT] = handler;
    }
}
void roc_link_on(roc_link *link, int evt_type, roc_handle_func *handler)
{
    if (evt_type < ROC_SOCK_EVTEND)
    {
        link->handler[evt_type] = handler;
    }
}

static void roc_auto_accept(roc_evt_loop *el, int fd, void *custom_data, int mask)
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
        close(fd);
        return;
    }

    if (svr->handler[ROC_SOCK_CONNECT])
    {
        roc_link *link = roc_link_new(cfd, ip_addr, cport);
        svr->handler[ROC_SOCK_CONNECT](link);
        roc_dispatch_ioevt(link, ROC_SOCK_ALLEVT);
    }
}
int roc_smart_send(roc_link *link)
{
    roc_ringbuf *rb = link->obuf;
    roc_evt_loop *el = link->evt_loop;

    uint32_t len = rb->tail - rb->head;
    /* first get the data from fifo->out until the end of the buffer */
    uint32_t head_readable = min(len, rb->size - (rb->head & (rb->size - 1)));

    int ret;
    if (head_readable)
    {
        ret = roc_send(link->fd,
                       rb->data + (rb->head & (rb->size - 1)),
                       head_readable, 1);
        if (ret == -1)
        {
            roc_del_io_evt(el, link->fd, ROC_SOCK_ALLEVT);
            roc_link_del(link);
            return -1;
        }
        if (ret == 0)
        {
            return 0;
        }
        rb->head += ret;

        if (ret != head_readable)
        {
            return roc_smart_send(link);
        }
    }

    uint32_t tail_readable = len - head_readable;
    if (tail_readable)
    {
        ret = roc_send(link->fd, rb->data, tail_readable, 1);
        if (ret == -1)
        {
            roc_del_io_evt(el, link->fd, ROC_SOCK_ALLEVT);
            roc_link_del(link);
            return -1;
        }
        if (ret == 0)
        {
            return 0;
        }
        rb->head += ret;
        if (ret != tail_readable)
        {
            return roc_smart_send(link);
        }
    }

    return 0;
}

static int roc_smart_recv(roc_link *link)
{
    roc_ringbuf *rb = link->obuf;
    roc_evt_loop *el = link->evt_loop;

    uint32_t len = roc_ringbuf_unused(rb);
    if (len == 0)
    {
        roc_ringbuf_resize(rb, rb->size + 1);
        return roc_smart_recv(link);
    }
    /* first put the data starting from fifo->in to buffer end */
    uint32_t tail_capacity = min(len, rb->size - (rb->tail & (rb->size - 1)));

    int ret;
    if (tail_capacity)
    {
        ret = roc_recv(link->fd,
                       rb->data + (rb->tail & (rb->size - 1)),
                       tail_capacity, 1);
        if (ret == -1) /* link closed by client or error occur */
        {
            roc_del_io_evt(el, link->fd, ROC_SOCK_ALLEVT);
            roc_link_del(link);
            return -1;
        }
        if (ret == 0)
        {
            return 0;
        }
        rb->tail += ret;
        if (ret < tail_capacity)
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
            roc_del_io_evt(el, link->fd, ROC_SOCK_ALLEVT);
            roc_link_del(link);
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

    char buffer[1024] = {0};
    if (mask & ROC_SOCK_DATA)
    {
        if (roc_smart_recv(link) == 0)
        {
            if (link->handler[ROC_SOCK_DATA])
            {
                link->handler[ROC_SOCK_DATA](link);
            }
        }
        else
        {
            return;
        }
    }
    if (mask & ROC_SOCK_SEND)
    {
        if (!roc_ringbuf_readable(link->obuf))
        {
            return;
        }
        if (roc_smart_send(link) == -1)
        {
            return;
        }
    }
}

static int roc_dispatch_ioevt(roc_link *link, int mask)
{
    unsigned int next_loopid = curr_loop_offset % ROC_THREAD_NUM;
    roc_evt_loop *el = (roc_evt_loop *)(work_arr[next_loopid].data);
    if (roc_add_io_evt(el, link->fd, mask, roc_pretreat_data, link) == -1)
    {
        roc_link_del(link);
        return -1;
    }
    link->evt_loop = el;
    curr_loop_offset++;
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
    if (roc_add_io_evt(svr->evt_loop, svr->fd, ROC_SOCK_CONNECT,
                       roc_auto_accept, svr) == -1)
    {
        free(svr);
        return -1;
    }

    return 0;
}
int roc_svr_stop(roc_svr *svr)
{
}

roc_svr *roc_svr_new(int port)
{
    roc_svr *svr = (roc_svr *)malloc(sizeof(roc_svr));
    if (!svr)
    {
        return NULL;
    }
    svr->port = port;
    svr->domain = AF_INET;
    svr->type = SOCK_STREAM;
    svr->backlog = 65535;
    svr->maxlink = 65535;
    svr->nonblock = 1;
    if (!default_loop)
    {
        free(svr);
    }
    svr->evt_loop = default_loop;
    return svr;
}

roc_link *roc_link_new(int fd, char *ip, int port)
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
    link->port = port;
    link->fd = fd;

    return link;
}
static inline void roc_link_del(roc_link *link)
{
    roc_ringbuf_del(link->ibuf);
    roc_ringbuf_del(link->obuf);
    free(link->ip);
    if (link->fd)
    {
        close(link->fd);
    }
    free(link);
}