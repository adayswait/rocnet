#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "roc_log.h"
#include "roc_queue.h"
#include "roc_ringbuf.h"
#include "roc_threadpool.h"

pthread_mutex_t logmutex;
pthread_cond_t logcond;
QUEUE logq;
pthread_t thread_id;

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
        fflush(logfs);
        __sync_lock_test_and_set(&cell->status, ROC_LOGCELL_UNUSED);
    }
}

int roc_log_init(const char *path)
{
    if (path)
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
    cellmgr[0].rb = roc_ringbuf_new(1024);
    if (!cellmgr[0].rb)
    {
        return -1;
    }
    currcell = &cellmgr[0];

    if (roc_thread_create(&thread_id, roc_log_worker, NULL))
    {
        return -1;
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
    if (rb->tail - rb->head > 1)
    {
        lastcell = currcell;
        if (roc_logcell_get() == 0)
        {
            lastcell->status = ROC_LOGCELL_WRITE;
            QUEUE_INSERT_TAIL(&logq, &lastcell->queue_node);
            pthread_cond_signal(&logcond);
        }
        else
        {
            currcell = lastcell;
        }
    }
    pthread_mutex_unlock(&logmutex);
}
