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
#include "roc_daemon.h"
#include "roc_log.h"

void ondata(roc_link *link)
{
    int len = link->ibuf->tail - link->ibuf->head;
    if (len == 0)
    {
        return;
    }
    char *data = malloc(len);
    if (!data)
    {
        return;
    }
    roc_ringbuf_read(link->ibuf, data, len);
    roc_ringbuf_write(link->obuf, data, len);
    roc_smart_send(link);
    free(data);
}

void onconnect(roc_link *link)
{
    roc_link_on(link, ROC_SOCK_DATA, ondata);
}

int main()
{
    printf("welcome to use rocnet\n\n");
    roc_daemon_start();
    roc_init();
    roc_log_init("./a.log");
    roc_svr *svr = roc_svr_new(3000);
    ROC_LOG_STDERR("server listening on port 3000\n", 30);
    roc_svr_on(svr, ROC_SOCK_CONNECT, onconnect);
    roc_svr_start(svr);

    return roc_run();
}
