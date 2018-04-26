/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <limits.h>
#include <errno.h>
#include <sys/resource.h>

#include "roc_queue.h"
#include "roc_threadpool.h"

#define ROC_THREADPOOL_MAXSIZE 128

static pthread_once_t tponce = PTHREAD_ONCE_INIT;
static pthread_cond_t tpcond;
static pthread_mutex_t tpmutex;
static unsigned int idle_thread_num;
static unsigned int thread_num;
static pthread_t *threads;
static pthread_t default_threads[4];
static QUEUE exit_message;
static QUEUE wq;

static inline void roc_sem_post(sem_t *sem)
{
    if (sem_post(sem))
    {
        abort();
    }
}

static inline void roc_mutex_lock(pthread_mutex_t *mutex)
{
    if (pthread_mutex_lock(mutex))
    {
        abort();
    }
}

static inline void roc_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    if (pthread_cond_wait(cond, mutex))
    {
        abort();
    }
}

static inline void roc_mutex_unlock(pthread_mutex_t *mutex)
{
    if (pthread_mutex_unlock(mutex))
    {
        abort();
    }
}

static void roc_cancelled_work(roc_work *w)
{
    abort();
}

/* On MacOS, threads other than the main thread are created with a reduced
 * stack size by default.  Adjust to RLIMIT_STACK aligned to the page size.
 *
 * On Linux, threads created by musl have a much smaller stack than threads
 * created by glibc (80 vs. 2048 or 4096 kB.)  Follow glibc for consistency.
 */
static size_t thread_stack_size(void)
{
#if defined(__APPLE__) || defined(__linux__)
    struct rlimit lim;

    if (getrlimit(RLIMIT_STACK, &lim))
        abort();

    if (lim.rlim_cur != RLIM_INFINITY)
    {
        /* pthread_attr_setstacksize() expects page-aligned values. */
        lim.rlim_cur -= lim.rlim_cur % (rlim_t)getpagesize();
        if (lim.rlim_cur >= PTHREAD_STACK_MIN)
            return lim.rlim_cur;
    }
#endif

#if !defined(__linux__)
    return 0;
#elif defined(__PPC__) || defined(__ppc__) || defined(__powerpc__)
    return 4 << 20; /* glibc default. */
#else
    return 2 << 20; /* glibc default. */
#endif
}

int roc_thread_create(pthread_t *tid, void (*entry)(void *), void *arg)
{
    int err;
    size_t stack_size;
    pthread_attr_t *attr;
    pthread_attr_t attr_storage;

    attr = NULL;
    stack_size = thread_stack_size();

    if (stack_size > 0)
    {
        attr = &attr_storage;

        if (pthread_attr_init(attr))
        {
            abort();
        }

        if (pthread_attr_setstacksize(attr, stack_size))
        {
            abort();
        }
    }

    err = pthread_create(tid, attr, (void *(*)(void *))entry, arg);

    if (attr != NULL)
    {
        pthread_attr_destroy(attr);
    }
    return err;
}

void roc_sem_wait(sem_t *sem)
{
    int r;

    do
    {
        r = sem_wait(sem);
    } while (r == -1 && errno == EINTR);

    if (r)
    {
        abort();
    }
}

void roc_sem_destroy(sem_t *sem)
{
    if (sem_destroy(sem))
    {
        abort();
    }
}

/* To avoid deadlock with tp_cancel() it's crucial that the roc_worker
 * never holds the global mutex and the loop-local mutex at the same time.
 */
static void roc_worker(void *arg)
{
    roc_work *w;
    QUEUE *q;

    roc_sem_post((sem_t *)arg);
    arg = NULL;

    for (;;)
    {
        roc_mutex_lock(&tpmutex);

        while (QUEUE_EMPTY(&wq))
        {
            idle_thread_num += 1;
            roc_cond_wait(&tpcond, &tpmutex);
            idle_thread_num -= 1;
        }

        q = QUEUE_HEAD(&wq);

        if (q == &exit_message)
        {
            pthread_cond_signal(&tpcond);
        }
        else
        {
            QUEUE_REMOVE(q);
            QUEUE_INIT(q);
        }

        roc_mutex_unlock(&tpmutex);

        if (q == &exit_message)
        {
            break;
        }

        w = QUEUE_DATA(q, roc_work, queue_node);
        w->work(w);
        w->work = NULL;
    }
}

static void roc_post_work(QUEUE *q)
{
    roc_mutex_lock(&tpmutex);
    QUEUE_INSERT_TAIL(&wq, q);
    if (idle_thread_num > 0)
    {
        pthread_cond_signal(&tpcond);
    }
    roc_mutex_unlock(&tpmutex);
}

#if 0
static void roc_destory_threadpool()
{
    unsigned int i;

    if (thread_num == 0)
    {
        return;
    }

    roc_post_work(&exit_message);

    for (i = 0; i < thread_num; i++)
    {
        if (pthread_join(*(threads + i), NULL))
        {
            abort();
        }
    }

    if (threads != default_threads)
    {
        free(threads);
    }

    pthread_mutex_destroy(&tpmutex);
    pthread_cond_destroy(&tpcond);

    threads = NULL;
    thread_num = 0;
}
#endif

static void roc_init_threadpool(void)
{
    unsigned int i;
    const char *val;
    sem_t sem;

    thread_num = ARRAY_SIZE(default_threads);
    val = getenv("ROC_THREADPOOL_SIZE");
    if (val != NULL)
    {
        thread_num = atoi(val);
    }
    if (thread_num == 0)
    {
        thread_num = 1;
    }
    if (thread_num > ROC_THREADPOOL_MAXSIZE)
    {
        thread_num = ROC_THREADPOOL_MAXSIZE;
    }

    threads = default_threads;
    if (thread_num > ARRAY_SIZE(default_threads))
    {
        threads = malloc(thread_num * sizeof(threads[0]));
        if (threads == NULL)
        {
            thread_num = ARRAY_SIZE(default_threads);
            threads = default_threads;
        }
    }

    if (pthread_cond_init(&tpcond, NULL))
    {
        abort();
    }

    if (pthread_mutex_init(&tpmutex, NULL))
    {
        abort();
    }

    QUEUE_INIT(&wq);

    if (sem_init(&sem, 0, 0))
    {
        abort();
    }

    for (i = 0; i < thread_num; i++)
    {
        if (roc_thread_create(threads + i, roc_worker, &sem))
        {
            abort();
        }
    }

    for (i = 0; i < thread_num; i++)
    {
        roc_sem_wait(&sem);
    }

    roc_sem_destroy(&sem);
}

static void roc_reset_tponce(void)
{
    pthread_once_t child_once = PTHREAD_ONCE_INIT;
    memcpy(&tponce, &child_once, sizeof(child_once));
}

static void roc_init_tponce(void)
{
    if (pthread_atfork(NULL, NULL, &roc_reset_tponce))
    {
        abort();
    }
    roc_init_threadpool();
}

/**
 * roc_work *w 应指向栈空间,不能在堆空间创建,否则QUEUE会出错
 */
void roc_tpwork_submit(roc_work *w,
                       void (*work)(roc_work *w),
                       void *data)
{
    pthread_once(&tponce, roc_init_tponce);
    w->work = work;
    w->data = data;
    roc_post_work(&w->queue_node);
}

int roc_tpwork_cancel(roc_work *w)
{
    int cancelled;

    roc_mutex_lock(&tpmutex);

    cancelled = !QUEUE_EMPTY(&w->queue_node) && w->work != NULL;
    if (cancelled)
    {
        QUEUE_REMOVE(&w->queue_node);
    }

    roc_mutex_unlock(&tpmutex);

    if (!cancelled)
    {
        return -1;
    }

    w->work = roc_cancelled_work;

    return 0;
}
