#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include "roc_evt.h"
#include "roc_net.h"
#include "roc_ringbuf.h"
#include "roc_threadpool.h"
#include "roc_svr.h"
#include "roc_log.h"

void ondata(roc_link *link)
{
    int len = link->ibuf->tail - link->ibuf->head;
    if (len == 0)
    {
        return;
    }
    char *data = malloc(len + 1);
    if (!data)
    {
        return;
    }
    *(data + len) = '\0';
    roc_ringbuf_read(link->ibuf, data, len);
    ROC_LOG_INFO("recv data from fd:%d, addr:%s:%d\ndata:%s\n",
                 link->fd, link->ip, link->port, data);
    roc_smart_send(link, data, len);
    free(data);
}
void onclose(roc_link *link)
{
    ROC_LOG_WARN("link close, fd:%d, addr:%s:%d\n",
                 link->fd, link->ip, link->port);
}

void onconnect(roc_link *link)
{
    ROC_LOG_INFO("new connection, fd:%d, addr:%s:%d\n",
                 link->fd, link->ip, link->port);
    roc_link_on(link, ROC_SOCK_DATA, ondata);
    roc_link_on(link, ROC_SOCK_CLOSE, onclose);
}

int main()
{
    printf("welcome to use rocnet\n");
    int port = 3000;
    if (roc_init("./rocnet.r", ROC_LOG_LEVEL_DEBUG) == -1)
    {
        return -1;
    }
    roc_svr *svr = roc_svr_new(port);
    if (!svr)
    {
        return -1;
    }
    ROC_LOG_INFO("server listening on port:%d\n", port);
    roc_svr_on(svr, ROC_SOCK_CONNECT, onconnect);
    if (roc_svr_start(svr) == -1)
    {
        return -1;
    }

    return roc_run();
}
