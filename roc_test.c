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

#define WORKER_NUMBER 10000

void work(roc_work *w)
{
    printf("work get param %d\n", *((int *)(w->data)));
}

int print_data(byte *data, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        printf("%1.1s", data + i);
    }
    printf("\n");
}
void ondata(roc_link *link)
{
    /*高并发时printf影响性能*/
    /*printf("data recv from %s:%d in thread%d\n",
           link->ip, link->port, pthread_self());*/
    int len = link->ibuf->tail - link->ibuf->head;
    char *data = malloc(len);
    roc_ringbuf_read(link->ibuf, data, len);
    roc_ringbuf_write(link->obuf, data, len);
}

void onconnect(roc_link *link)
{
    /*高并发时printf影响性能*/
    /*printf("connected from %s:%d\n", link->ip, link->port);*/
    roc_link_on(link, ROC_SOCK_DATA, ondata);
}

int main()
{
    printf("welcome to use rocnet\n\n");
    roc_init();
    roc_svr *svr = roc_svr_new(3000);
    roc_svr_on(svr, ROC_SOCK_CONNECT, onconnect);
    roc_svr_start(svr);

    return roc_run();
}
