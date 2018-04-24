#ifndef ROC_LOG_H
#define ROC_LOG_H

#include "roc_ringbuf.h"

#define ROC_LOG_LEVEL_STDERR 0
#define ROC_LOG_LEVEL_EMERG 1
#define ROC_LOG_LEVEL_ALERT 2
#define ROC_LOG_LEVEL_CRIT 3
#define ROC_LOG_LEVEL_ERR 4
#define ROC_LOG_LEVEL_WARN 5
#define ROC_LOG_LEVEL_NOTICE 6
#define ROC_LOG_LEVEL_INFO 7
#define ROC_LOG_LEVEL_DEBUG 8

#define ROC_LOG_LEVEL_STDERR_PREFIX "[STDERR]"
#define ROC_LOG_LEVEL_EMERG_PREFIX "[EMERG]"
#define ROC_LOG_LEVEL_ALERT_PREFIX "[ALERT]"
#define ROC_LOG_LEVEL_CRIT_PREFIX "[CRIT]"
#define ROC_LOG_LEVEL_ERR_PREFIX "[ERR]"
#define ROC_LOG_LEVEL_WARN_PREFIX "[WARN]"
#define ROC_LOG_LEVEL_NOTICE_PREFIX "[NOTICE]"
#define ROC_LOG_LEVEL_INFO_PREFIX "[INFO]"
#define ROC_LOG_LEVEL_DEBUG_PREFIX "[DEBUG]"

#define ROC_LOG_CELL_NUM 1024
#define ROC_LOG_CELL_SIZE 1024

#define ROC_LOGCELL_UNUSED 0
#define ROC_LOGCELL_READ 1
#define ROC_LOGCELL_WRITE 2
int roc_log_level;
typedef struct
{
    int status;
    roc_ringbuf *rb;
    void *queue_node[2];

} roc_logcell;

int roc_log_init(const char *path, int level);
int roc_log_write(int level, const char *format, ...);
int roc_log_flush();

#define ROC_LOG_STDERR(format, ...)                                 \
    roc_log_write(ROC_LOG_LEVEL_STDERR, format, ##__VA_ARGS__);
#define ROC_LOG_EMERG(format, ...)                                  \
    if (roc_log_level >= ROC_LOG_LEVEL_EMERG)                       \
    {                                                               \
        roc_log_write(ROC_LOG_LEVEL_EMERG, format, ##__VA_ARGS__);  \
    }
#define ROC_LOG_ALERT(format, ...)                                  \
    if (roc_log_level >= ROC_LOG_LEVEL_ALERT)                       \
    {                                                               \
        roc_log_write(ROC_LOG_LEVEL_ALERT, format, ##__VA_ARGS__);  \
    }
#define ROC_LOG_CRIT(format, ...)                                   \
    if (roc_log_level >= ROC_LOG_LEVEL_CRIT)                        \
    {                                                               \
        roc_log_write(ROC_LOG_LEVEL_CRIT, format, ##__VA_ARGS__);   \
    }
#define ROC_LOG_ERR(format, ...)                                    \
    if (roc_log_level >= ROC_LOG_LEVEL_ERR)                         \
    {                                                               \
        roc_log_write(ROC_LOG_LEVEL_ERR, format, ##__VA_ARGS__);    \
    }
#define ROC_LOG_WARN(format, ...)                                   \
    if (roc_log_level >= ROC_LOG_LEVEL_WARN)                        \
    {                                                               \
        roc_log_write(ROC_LOG_LEVEL_WARN, format, ##__VA_ARGS__);   \
    }
#define ROC_LOG_NOTICE(format, ...)                                 \
    if (roc_log_level >= ROC_LOG_LEVEL_NOTICE)                      \
    {                                                               \
        roc_log_write(ROC_LOG_LEVEL_NOTICE, format, ##__VA_ARGS__); \
    }
#define ROC_LOG_INFO(format, ...)                                   \
    if (roc_log_level >= ROC_LOG_LEVEL_INFO)                        \
    {                                                               \
        roc_log_write(ROC_LOG_LEVEL_INFO, format, ##__VA_ARGS__);   \
    }
#define ROC_LOG_DEBUG(format, ...)                                  \
    if (roc_log_level >= ROC_LOG_LEVEL_DEBUG)                       \
    {                                                               \
        roc_log_write(ROC_LOG_LEVEL_DEBUG, format, ##__VA_ARGS__);  \
    }

#endif /* ROC_LOG_H */
