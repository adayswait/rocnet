#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "roc_log.h"
#include "roc_queue.h"
#include "roc_ringbuf.h"
#include "roc_threadpool.h"

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
pthread_mutex_t logmutex;
pthread_cond_t logcond;
QUEUE logq;
pthread_t thread_id;

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
        char *a = malloc(1024);
        roc_ringbuf_read(cell->rb, a, 1024);
        printf("%s\n", a);
        cell->rb->head = 0;
        cell->rb->tail = 0;
        __sync_lock_test_and_set(&cell->status, ROC_LOGCELL_UNUSED);
    }
}

int roc_log_init()
{
    if (pthread_mutex_init(&logmutex, NULL))
    {
        abort();
    }
    if (pthread_cond_init(&logcond, NULL))
    {
        abort();
    }
    QUEUE_INIT(&logq);
    int i;
    for (i = 0; i < ROC_LOG_CELL_NUM; i++)
    {
        cellmgr[i].status = ROC_LOGCELL_UNUSED;
        cellmgr[i].rb = NULL;
    }
    cellmgr[0].status = ROC_LOGCELL_READ;
    cellmgr[0].rb = roc_ringbuf_new(1024);
    if (!cellmgr[0].rb)
    {
        return -1;
    }
    currcell = &cellmgr[0];

    if (roc_thread_create(&thread_id, roc_log_worker, NULL))
    {
        abort();
    }
    return 0;
}
static inline int roc_logcell_init(roc_logcell *cell)
{
    cell->rb = roc_ringbuf_new(1024);
    if (!cell->rb)
    {
        return -1;
    }

    cell->status = ROC_LOGCELL_UNUSED;
    return 0;
}
static inline int roc_logcell_get()
{
    int i;
    for (i = 0; i < ROC_LOG_CELL_NUM; i++)
    {
        if (cellmgr[i].status == ROC_LOGCELL_UNUSED)
        {
            cellmgr[i].status = ROC_LOGCELL_READ;
            if (!cellmgr[i].rb)
            {
                cellmgr[i].rb = roc_ringbuf_new(1024);
            }
            if (!cellmgr[i].rb)
            {
                return -1;
            }
            currcell = &cellmgr[i];

            return 0;
        }
    }
    return -1;
}

int roc_log_write(int level, void *buf, int len)
{
    pthread_mutex_lock(&logmutex);
    roc_ringbuf *rb = currcell->rb;
    roc_logcell *lastcell;

    roc_ringbuf_write(rb, buf, len);
    if (rb->tail - rb->head > ROC_LOG_CELL_SIZE)
    {
        lastcell = currcell;
        if (roc_logcell_get() == 0)
        {
            lastcell->status = ROC_LOGCELL_WRITE;
            QUEUE_INSERT_TAIL(&logq, &lastcell->queue_node);
            pthread_cond_signal(&logcond);
        }
    }

    pthread_mutex_unlock(&logmutex);
}
