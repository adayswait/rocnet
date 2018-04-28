#ifndef ROC_PLUGIN_H
#define ROC_PLUGIN_H
#include "roc_svr.h"

int register_plugin(roc_plugin *plugin_so, const char *so_path, int flag);
void unregister_plugin(roc_plugin *plugin_so);
int register_data_plugin(roc_plugin *plugin_so, const char *so_path);
void unregister_data_plugin(roc_plugin *plugin_so);

#endif /* ROC_PLUGIN_H */