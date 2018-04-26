#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include "roc_log.h"
#include "roc_queue.h"
#include "roc_ringbuf.h"
#include "roc_threadpool.h"

#define ROC_LOG_CELL_NUM 1024
#define ROC_LOG_CELL_SIZE 4096
#define ROC_PRELOG_SIZE 4096

#define ROC_LOGCELL_UNUSED 0
#define ROC_LOGCELL_READ 1
#define ROC_LOGCELL_WRITE 2

pthread_mutex_t logmutex;
pthread_cond_t logcond;
pthread_t thread_id;

QUEUE logq;
FILE *logfs;

roc_logcell *currcell;
roc_logcell cellmgr[ROC_LOG_CELL_NUM];

static void roc_log_worker(void *arg)
{
    roc_logcell *cell;
    QUEUE *q;

    arg = NULL;

    for (;;)
    {
        pthread_mutex_lock(&logmutex);

        if (QUEUE_EMPTY(&logq))
        {
            pthread_cond_wait(&logcond, &logmutex);
        }

        q = QUEUE_HEAD(&logq);
        QUEUE_REMOVE(q);
        QUEUE_INIT(q);

        pthread_mutex_unlock(&logmutex);

        cell = QUEUE_DATA(q, roc_logcell, queue_node);

        roc_ringbuf *rb = cell->rb;

        uint32_t len = rb->tail - rb->head;
        uint32_t head_n = min(len, rb->size - (rb->head & (rb->size - 1)));
        if (head_n)
        {
            fwrite_unlocked(rb->data + (rb->head & (rb->size - 1)),
                            1, head_n, logfs);
        }

        uint32_t tail_n = len - head_n;
        if (tail_n)
        {
            fwrite_unlocked(rb->data, 1, tail_n, logfs);
        }
        rb->head += len;
        __sync_lock_test_and_set(&cell->status, ROC_LOGCELL_UNUSED);
        fflush(logfs);
    }
}
static void roc_term_log(int signal)
{
    ROC_LOG_STDERR("recv signal:%d\n", signal);
    roc_log_flush();
    for (;;)
    {
        pthread_mutex_lock(&logmutex);

        if (QUEUE_EMPTY(&logq))
        {
            pthread_mutex_unlock(&logmutex);
            break;
        }
        pthread_cond_signal(&logcond);
        pthread_mutex_unlock(&logmutex);
        sleep(1);
    }
    exit(0);
}

int roc_log_init(const char *path, int level)
{

    if (path && strlen(path) != 0)
    {
        logfs = fopen(path, "a+");
        if (!logfs)
        {
            return -1;
        }
    }
    else
    {
        logfs = stdout;
    }
    if (pthread_mutex_init(&logmutex, NULL))
    {
        return -1;
    }
    if (pthread_cond_init(&logcond, NULL))
    {
        return -1;
    }
    QUEUE_INIT(&logq);
    int i;
    for (i = 0; i < ROC_LOG_CELL_NUM; i++)
    {
        cellmgr[i].status = ROC_LOGCELL_UNUSED;
        cellmgr[i].rb = NULL;
    }
    cellmgr[0].status = ROC_LOGCELL_READ;
    cellmgr[0].rb = roc_ringbuf_new(ROC_LOG_CELL_SIZE);
    if (!cellmgr[0].rb)
    {
        return -1;
    }
    currcell = &cellmgr[0];

    if (roc_thread_create(&thread_id, roc_log_worker, NULL))
    {
        return -1;
    }
    if (level == ROC_LOG_LEVEL_STDERR ||
        level == ROC_LOG_LEVEL_EMERG ||
        level == ROC_LOG_LEVEL_ALERT ||
        level == ROC_LOG_LEVEL_CRIT ||
        level == ROC_LOG_LEVEL_ERR ||
        level == ROC_LOG_LEVEL_WARN ||
        level == ROC_LOG_LEVEL_NOTICE ||
        level == ROC_LOG_LEVEL_DEBUG)
    {
        roc_log_level = level;
    }
    else
    {
        ROC_LOG_STDERR("invalid log level:%d\n", level);
        return -1;
    }
    signal(SIGINT, roc_term_log);
    signal(SIGTERM, roc_term_log);
    signal(SIGSEGV, roc_term_log);
    signal(SIGQUIT, roc_term_log);
    signal(SIGABRT, roc_term_log);
    return 0;
}

static inline roc_logcell *roc_logcell_get()
{
    int i;
    for (i = 0; i < ROC_LOG_CELL_NUM; i++)
    {
        if (cellmgr[i].status == ROC_LOGCELL_UNUSED)
        {
            cellmgr[i].status = ROC_LOGCELL_READ;
            if (!cellmgr[i].rb)
            {
                cellmgr[i].rb = roc_ringbuf_new(ROC_LOG_CELL_SIZE);
            }
            if (!cellmgr[i].rb)
            {
                return NULL;
            }
            return &cellmgr[i];
        }
    }
    return NULL;
}

/**
 * 将当前时间转换为标准时间格式,并储存在std_time_str中
 */
static inline void roc_fmt_time(char *std_time_str)
{
    time_t t = time(NULL);
    struct tm *ts = localtime(&t);
    strftime(std_time_str, 22, "[%Y-%m-%d %H:%M:%S]", ts);
}

void roc_log_write(int level, const char *format, ...)
{
    char buf[ROC_PRELOG_SIZE];
    int prefix_len = 0;
    switch (level)
    {
    case ROC_LOG_LEVEL_STDERR:
        prefix_len = strlen(ROC_LOG_LEVEL_STDERR_PREFIX);
        strcpy(buf, ROC_LOG_LEVEL_STDERR_PREFIX);
        break;
    case ROC_LOG_LEVEL_EMERG:
        prefix_len = strlen(ROC_LOG_LEVEL_EMERG_PREFIX);
        strcpy(buf, ROC_LOG_LEVEL_EMERG_PREFIX);
        break;
    case ROC_LOG_LEVEL_ALERT:
        prefix_len = strlen(ROC_LOG_LEVEL_ALERT_PREFIX);
        strcpy(buf, ROC_LOG_LEVEL_ALERT_PREFIX);
        break;
    case ROC_LOG_LEVEL_CRIT:
        prefix_len = strlen(ROC_LOG_LEVEL_CRIT_PREFIX);
        strcpy(buf, ROC_LOG_LEVEL_CRIT_PREFIX);
        break;
    case ROC_LOG_LEVEL_ERR:
        prefix_len = strlen(ROC_LOG_LEVEL_ERR_PREFIX);
        strcpy(buf, ROC_LOG_LEVEL_ERR_PREFIX);
        break;
    case ROC_LOG_LEVEL_WARN:
        prefix_len = strlen(ROC_LOG_LEVEL_WARN_PREFIX);
        strcpy(buf, ROC_LOG_LEVEL_WARN_PREFIX);
        break;
    case ROC_LOG_LEVEL_NOTICE:
        prefix_len = strlen(ROC_LOG_LEVEL_NOTICE_PREFIX);
        strcpy(buf, ROC_LOG_LEVEL_NOTICE_PREFIX);
        break;
    case ROC_LOG_LEVEL_INFO:
        prefix_len = strlen(ROC_LOG_LEVEL_INFO_PREFIX);
        strcpy(buf, ROC_LOG_LEVEL_INFO_PREFIX);
        break;
    case ROC_LOG_LEVEL_DEBUG:
        prefix_len = strlen(ROC_LOG_LEVEL_DEBUG_PREFIX);
        strcpy(buf, ROC_LOG_LEVEL_DEBUG_PREFIX);
        break;
    default:
        prefix_len = strlen(ROC_LOG_LEVEL_STDERR_PREFIX);
        strcpy(buf, ROC_LOG_LEVEL_STDERR_PREFIX);
        break;
    }

    char time_str[22];
    roc_fmt_time(time_str);
    strcpy(buf + prefix_len, time_str);
    prefix_len += strlen(time_str);

    va_list ap;
    va_start(ap, format);
    vsnprintf(buf + prefix_len, ROC_PRELOG_SIZE - prefix_len, format, ap);
    va_end(ap);
    uint32_t len = strlen(buf);
    pthread_mutex_lock(&logmutex);
    roc_ringbuf *rb = currcell->rb;
    roc_logcell *newcell;
    uint32_t writen_n, ret;
    for (writen_n = 0; writen_n != len; writen_n += ret)
    {
        ret = roc_ringbuf_write_rigid(rb, buf + writen_n, len - writen_n);
        if (ret != len - writen_n) //rb is full
        {
            newcell = roc_logcell_get();
            if (!newcell)
            {
                writen_n += ret;
                roc_ringbuf_write(rb, buf + writen_n, len - writen_n);
                break;
            }
            else
            {
                currcell->status = ROC_LOGCELL_WRITE;
                QUEUE_INSERT_TAIL(&logq, &currcell->queue_node);
                currcell = newcell;
                rb = currcell->rb;
            }
        }
    }
    if (!QUEUE_EMPTY(&logq))
    {
        pthread_cond_signal(&logcond);
    }
    pthread_mutex_unlock(&logmutex);
}

void roc_log_flush()
{
    pthread_mutex_lock(&logmutex);
    if (QUEUE_EMPTY(&logq) && currcell->rb->tail - currcell->rb->head != 0)
    {
        roc_logcell *newcell = roc_logcell_get();
        if (newcell)
        {
            currcell->status = ROC_LOGCELL_WRITE;
            QUEUE_INSERT_TAIL(&logq, &currcell->queue_node);
            currcell = newcell;
            pthread_cond_signal(&logcond);
        }
    }
    pthread_mutex_unlock(&logmutex);
}
