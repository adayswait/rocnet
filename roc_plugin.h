#include "roc_svr.h"
typedef void *roc_send_func(roc_link *link, void *buf, int len);
typedef struct
{
    void *so_handle;
    void *data_so_handle;
    roc_handle_func *connect_handler;
    roc_handle_func *recv_handler;
    roc_handle_func *close_handler;
} roc_plugin;
