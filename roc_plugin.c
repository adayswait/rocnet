#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include "roc_plugin.h"

roc_plugin plugin;

#define DLFUNC_NO_ERROR(h, v, name) \
    do                              \
    {                               \
        v = dlsym(h, name);         \
        dlerror();                  \
    } while (0)

#define DLFUNC(h, v, name)                   \
    do                                       \
    {                                        \
        v = dlsym(h, name);                  \
        if ((error = dlerror()) != NULL)     \
        {                                    \
            printf("dlsym error:%s", error); \
            dlclose(h);                      \
            h = NULL;                        \
            goto err;                        \
        }                                    \
    } while (0)

int register_data_plugin(const char *so_path)
{
    char *error;
    int ret_code = 0;
    if (so_path == NULL)
    {
        return 0;
    }

    plugin.data_so_handle = dlopen(so_path, RTLD_NOW | RTLD_GLOBAL);
    if ((error = dlerror()) != NULL)
    {
        printf("dlopen error:%s", error);
        ret_code = 0;
    }
    printf("dlopen:%s", so_path);
    return ret_code;
}

int register_plugin(const char *so_path, int flag)
{
    char *error;
    int ret_code = -1;

    plugin.so_handle = dlopen(so_path, RTLD_NOW);
    if ((error = dlerror()) != NULL)
    {
        printf("dlopen error, %s", error);
        goto err;
    }

    DLFUNC_NO_ERROR(plugin.so_handle, plugin.close_handler, "close_handler");
    DLFUNC(plugin.so_handle, plugin.connect_handler, "connect_handler");
    DLFUNC(plugin.so_handle, plugin.recv_handler, "recv_handler");
    ret_code = 0;

err:
    if (!flag)
    {
        printf("dlopen %s", so_path);
    }
    else
    {
        printf("RELOAD %s\t[%s]", so_path, (ret_code ? "FAIL" : "OK"));
    }
    return ret_code;
}

void unregister_data_plugin()
{
    if (plugin.data_so_handle != NULL)
    {
        dlclose(plugin.data_so_handle);
        plugin.data_so_handle = NULL;
    }
}

void unregister_plugin()
{
    if (plugin.so_handle != NULL)
    {
        dlclose(plugin.so_handle);
        plugin.so_handle = NULL;
    }
}
