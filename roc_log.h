#ifndef ROC_LOG_H
#define ROC_LOG_H

#include "roc_ringbuf.h"

#define ROC_LOG_LEVEL_STDERR 0
#define ROC_LOG_LEVEL_EMERG 1
#define ROC_LOG_LEVEL_ALERT 3
#define ROC_LOG_LEVEL_CRIT 7
#define ROC_LOG_LEVEL_ERR 15
#define ROC_LOG_LEVEL_WARN 31
#define ROC_LOG_LEVEL_NOTICE 63
#define ROC_LOG_LEVEL_INFO 127
#define ROC_LOG_LEVEL_DEBUG 255

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

int roc_log_init();
int roc_log_write(int level, void *buf, int len);

#define ROC_LOG_STDERR(bufptr, buflen) \
    roc_log_write(ROC_LOG_LEVEL_STDERR, bufptr, buflen);
#define ROC_LOG_EMERG(bufptr, buflen)                       \
    if (roc_log_level & ROC_LOG_LEVEL_EMERG)                \
    {                                                       \
        roc_log_write(ROC_LOG_LEVEL_EMERG, bufptr, buflen); \
    }
#define ROC_LOG_ALERT(bufptr, buflen)                       \
    if (roc_log_level & ROC_LOG_LEVEL_ALERT)                \
    {                                                       \
        roc_log_write(ROC_LOG_LEVEL_ALERT, bufptr, buflen); \
    }
#define ROC_LOG_CRIT(bufptr, buflen)                       \
    if (roc_log_level & ROC_LOG_LEVEL_CRIT)                \
    {                                                      \
        roc_log_write(ROC_LOG_LEVEL_CRIT, bufptr, buflen); \
    }
#define ROC_LOG_ERR(bufptr, buflen)                       \
    if (roc_log_level & ROC_LOG_LEVEL_ERR)                \
    {                                                     \
        roc_log_write(ROC_LOG_LEVEL_ERR, bufptr, buflen); \
    }
#define ROC_LOG_WARN(bufptr, buflen)                       \
    if (roc_log_level & ROC_LOG_LEVEL_WARN)                \
    {                                                      \
        roc_log_write(ROC_LOG_LEVEL_WARN, bufptr, buflen); \
    }
#define ROC_LOG_NOTICE(bufptr, buflen)                       \
    if (roc_log_level & ROC_LOG_LEVEL_NOTICE)                \
    {                                                        \
        roc_log_write(ROC_LOG_LEVEL_NOTICE, bufptr, buflen); \
    }
#define ROC_LOG_INFO(bufptr, buflen)                       \
    if (roc_log_level & ROC_LOG_LEVEL_INFO)                \
    {                                                      \
        roc_log_write(ROC_LOG_LEVEL_INFO, bufptr, buflen); \
    }
#define ROC_LOG_DEBUG(bufptr, buflen)                       \
    if (roc_log_level & ROC_LOG_LEVEL_DEBUG)                \
    {                                                       \
        roc_log_write(ROC_LOG_LEVEL_DEBUG, bufptr, buflen); \
    }

#endif /* ROC_LOG_H */
