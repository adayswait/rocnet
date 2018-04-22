#include "roc_ringbuf.h"
extern int roc_log_level;
extern char roc_log_path[1024];
typedef struct
{
    int status;
    roc_ringbuf *rb;
    void *queue_node[2];

} roc_logcell;

int roc_log_init();
int roc_log_write(int level, void *buf, int len);

#define ROC_LOG_STDERR(level, bufptr, buflen) \
    roc_log_write(ROC_LOG_LEVEL_STDERR, bufptr, buflen);
#define ROC_LOG_EMERG(level, bufptr, buflen)                \
    if (roc_log_level & ROC_LOG_LEVEL_EMERG)                \
    {                                                       \
        roc_log_write(ROC_LOG_LEVEL_EMERG, bufptr, buflen); \
    }
#define ROC_LOG_ALERT(level, bufptr, buflen)                \
    if (roc_log_level & ROC_LOG_LEVEL_ALERT)                \
    {                                                       \
        roc_log_write(ROC_LOG_LEVEL_ALERT, bufptr, buflen); \
    }
#define ROC_LOG_CRIT(level, bufptr, buflen)                \
    if (roc_log_level & ROC_LOG_LEVEL_CRIT)                \
    {                                                      \
        roc_log_write(ROC_LOG_LEVEL_CRIT, bufptr, buflen); \
    }
#define ROC_LOG_ERR(level, bufptr, buflen)                \
    if (roc_log_level & ROC_LOG_LEVEL_ERR)                \
    {                                                     \
        roc_log_write(ROC_LOG_LEVEL_ERR, bufptr, buflen); \
    }
#define ROC_LOG_WARN(level, bufptr, buflen)                \
    if (roc_log_level & ROC_LOG_LEVEL_WARN)                \
    {                                                      \
        roc_log_write(ROC_LOG_LEVEL_WARN, bufptr, buflen); \
    }
#define ROC_LOG_NOTICE(level, bufptr, buflen)                \
    if (roc_log_level & ROC_LOG_LEVEL_NOTICE)                \
    {                                                        \
        roc_log_write(ROC_LOG_LEVEL_NOTICE, bufptr, buflen); \
    }
#define ROC_LOG_INFO(level, bufptr, buflen)                \
    if (roc_log_level & ROC_LOG_LEVEL_INFO)                \
    {                                                      \
        roc_log_write(ROC_LOG_LEVEL_INFO, bufptr, buflen); \
    }
#define ROC_LOG_DEBUG(level, bufptr, buflen)                \
    if (roc_log_level & ROC_LOG_LEVEL_DEBUG)                \
    {                                                       \
        roc_log_write(ROC_LOG_LEVEL_DEBUG, bufptr, buflen); \
    }
