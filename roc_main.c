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

void onconnect(roc_link *link)
{
    link->svr->plugin[0].connect_handler(link);
    roc_link_on(link, ROC_SOCK_DATA, link->svr->plugin[0].recv_handler);
    roc_link_on(link, ROC_SOCK_CLOSE, link->svr->plugin[0].close_handler);
}

int main(int argc, char **argv)
{
    printf("welcome to use rocnet\n");
    int port = 3000;
    if (roc_init("./rocnet.log", ROC_LOG_LEVEL_DEBUG) == -1)
    {
        return -1;
    }
    roc_svr *svr = roc_svr_new(port);
    if (!svr)
    {
        return -1;
    }
    ROC_LOG_INFO("server listening on port:%d\n", port);
    roc_svr_use(svr, "./plugin.so");
    roc_svr_on(svr, ROC_SOCK_CONNECT, onconnect);
    if (roc_svr_start(svr) == -1)
    {
        return -1;
    }

    return roc_run();
}
