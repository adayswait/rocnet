#include <stdio.h>
#include "roc_svr.h"
#include "roc_log.h"

void onconnect(roc_link *link, void *custom_data)
{
    link->svr->plugin[link->next_plugin_level]
        .connect_handler(link, custom_data);
    roc_link_on(link, ROC_SOCK_DATA,
                link->svr->plugin[link->next_plugin_level].recv_handler);
    roc_link_on(link, ROC_SOCK_CLOSE,
                link->svr->plugin[link->next_plugin_level].close_handler);
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
    
    roc_svr_use(svr, "./websocket.so");
    roc_svr_use(svr, "./echo.so");
    roc_svr_on(svr, ROC_SOCK_CONNECT, onconnect);
    
    if (roc_svr_start(svr) == -1)
    {
        return -1;
    }
    ROC_LOG_INFO("server listening on port:%d\n", port);

    return roc_run();
}
