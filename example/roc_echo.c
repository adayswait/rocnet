#include <stdio.h>
#include "roc.h"

void ondata(roc_link *link, void *custom_data)
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

void onclose(roc_link *link, void *custom_data)
{
    ROC_LOG_WARN("link close, fd:%d, addr:%s:%d\n",
                 link->fd, link->ip, link->port);
}

void onconnect(roc_link *link, void *custom_data)
{
    ROC_LOG_INFO("new connection, fd:%d, addr:%s:%d\n",
                 link->fd, link->ip, link->port);
    roc_link_on(link, ROC_SOCK_DATA, ondata);
    roc_link_on(link, ROC_SOCK_CLOSE, onclose);
}

int main(int argc, char **argv)
{
    printf("welcome to use rocnet\n");

    int port = 3000;

    if (roc_init(NULL, ROC_LOG_LEVEL_DEBUG) == -1)
    {
        return -1;
    }

    roc_svr *svr = roc_svr_new(port);
    
    if (!svr)
    {
        return -1;
    }
    //roc_svr_use(svr, "./websocket.so");
    //roc_svr_use(svr, "./echo.so");
    roc_svr_on(svr, ROC_SOCK_CONNECT, onconnect);

    if (roc_svr_start(svr) == -1)
    {
        return -1;
    }

    ROC_LOG_INFO("server listening on port:%d\n", port);

    return roc_run();
}
