#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "roc_log.h"
#include "roc_plugin.h"

#define PLUGIN_LOAD_NOERR(h, v, name) \
    do                                \
    {                                 \
        v = dlsym(h, name);           \
        dlerror();                    \
    } while (0)

#define PLUGIN_LOAD(h, v, name)                      \
    do                                               \
    {                                                \
        v = dlsym(h, name);                          \
        if ((error = dlerror()) != NULL)             \
        {                                            \
            ROC_LOG_STDERR("dlsym error:%s", error); \
            dlclose(h);                              \
            h = NULL;                                \
            goto err;                                \
        }                                            \
    } while (0)

int register_plugin(roc_plugin *plugin_so, const char *so_path, int flag)
{
    char *error;
    int ret = -1;

    plugin_so->so_handle = dlopen(so_path, RTLD_NOW);
    if ((error = dlerror()) != NULL)
    {
        ROC_LOG_STDERR("dlopen error, %s\n", error);
        goto err;
    }

    /* link handler */
    PLUGIN_LOAD_NOERR(plugin_so->so_handle,
                      plugin_so->close_handler, "close_handler");
    PLUGIN_LOAD(plugin_so->so_handle,
                plugin_so->connect_handler, "connect_handler");
    PLUGIN_LOAD(plugin_so->so_handle,
                plugin_so->recv_handler, "recv_handler");

    /* svr handler */
    PLUGIN_LOAD(plugin_so->so_handle,
                plugin_so->init_handler, "init_handler");
    PLUGIN_LOAD(plugin_so->so_handle,
                plugin_so->fini_handler, "fini_handler");
    ret = 0;

err:
    if (!flag)
    {
        ROC_LOG_STDERR("dlopen %s\n", so_path);
    }
    else
    {
        ROC_LOG_STDERR("RELOAD %s\t[%s]\n", so_path,
                       (ret ? "FAIL" : "OK"));
    }
    return ret;
}

void unregister_plugin(roc_plugin *plugin_so)
{
    if (plugin_so->so_handle != NULL)
    {
        dlclose(plugin_so->so_handle);
        plugin_so->so_handle = NULL;
    }
}

int register_data_plugin(roc_plugin *plugin_so, const char *so_path)
{
    char *error;
    int ret = 0;
    if (so_path == NULL)
    {
        return 0;
    }

    plugin_so->data_so_handle = dlopen(so_path, RTLD_NOW | RTLD_GLOBAL);
    if ((error = dlerror()) != NULL)
    {
        ROC_LOG_STDERR("dlopen error:%s\n", error);
        ret = 0;
    }
    ROC_LOG_STDERR("dlopen:%s\n", so_path);
    return ret;
}

void unregister_data_plugin(roc_plugin *plugin_so)
{
    if (plugin_so->data_so_handle != NULL)
    {
        dlclose(plugin_so->data_so_handle);
        plugin_so->data_so_handle = NULL;
    }
}
