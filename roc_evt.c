#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/types.h>

#include "roc_evt.h"

roc_evt_loop *roc_create_evt_loop(int size)
{
    roc_evt_loop *evt_loop;
    int i;

    if ((evt_loop = malloc(sizeof(*evt_loop))) == NULL)
    {
        goto err;
    }
    evt_loop->all_io_evts = malloc(sizeof(roc_io_evt) * size);
    evt_loop->ready_evts = malloc(sizeof(roc_ready_evt) * size);
    if (evt_loop->all_io_evts == NULL || evt_loop->ready_evts == NULL)
    {
        goto err;
    }
    evt_loop->size = size;
    evt_loop->last_time = time(NULL);
    evt_loop->time_evt_head = NULL;
    evt_loop->time_evt_next_id = 0;
    evt_loop->stop = 0;
    evt_loop->maxfd = -1;
    if (roc_iom_create(evt_loop) == -1)
        goto err;
    /* Events with mask == ROC_EVENT_NONE are not set. 
     * So let's initialize the vector with it. */
    for (i = 0; i < size; i++)
        evt_loop->all_io_evts[i].mask = ROC_EVENT_NONE;
    return evt_loop;

err:
    if (evt_loop)
    {
        free(evt_loop->all_io_evts);
        free(evt_loop->ready_evts);
        free(evt_loop);
    }
    return NULL;
}

int roc_iom_create(roc_evt_loop *evt_loop)
{
    evt_loop->ret_evts = malloc(evt_loop->size * sizeof(struct epoll_event));
    if (!evt_loop->ret_evts)
    {
        free(evt_loop->ret_evts);
        return -1;
    }
    evt_loop->epfd = epoll_create(1024); /* 1024 is just a hint for the kernel */
    if (evt_loop->epfd == -1)
    {
        free(evt_loop->ret_evts);
        return -1;
    }
    return 0;
}

/* Resize the maximum size of the event loop.
 * If the requested newsize is smaller than the current size, but
 * there is already a file descriptor in use that is >= the requested
 * size minus one, -1 is returned and the operation is not
 * performed at all.
 *
 * Otherwise 0 is returned and the operation is successful. */
int roc_evt_loop_resize(roc_evt_loop *evt_loop, int newsize)
{
    int i;

    if (newsize == evt_loop->size)
    {
        return 0;
    }
    if (evt_loop->maxfd >= newsize)
    {
        return -1;
    }
    if (realloc(evt_loop->ret_evts,
                newsize * sizeof(struct epoll_event)) == NULL)
    {
        return -1;
    }
    evt_loop->all_io_evts = realloc(evt_loop->all_io_evts,
                                    newsize * sizeof(roc_io_evt));
    evt_loop->ready_evts = realloc(evt_loop->ready_evts,
                                   newsize * sizeof(roc_ready_evt));
    evt_loop->size = newsize;

    /* Make sure that if we created new slots, 
     * they are initialized with an ROC_EVENT_NONE mask. */
    for (i = evt_loop->maxfd + 1; i < newsize; i++)
    {
        evt_loop->all_io_evts[i].mask = ROC_EVENT_NONE;
    }
    return 0;
}

void roc_del_evt_loop(roc_evt_loop *evt_loop)
{
    close(evt_loop->epfd);
    free(evt_loop->all_io_evts);
    free(evt_loop->ready_evts);
    free(evt_loop->ret_evts);
    free(evt_loop);
}

void roc_evt_loop_stop(roc_evt_loop *evt_loop)
{
    evt_loop->stop = 1;
}

int roc_add_io_evt(roc_evt_loop *evt_loop, int fd, int mask,
                   roc_io_proc proc, void *custom_data)
{
    if (fd >= evt_loop->size)
    {
        errno = ERANGE;
        return -1;
    }
    roc_io_evt *io_evt = &evt_loop->all_io_evts[fd];

    if (roc_iom_add_evt(evt_loop, fd, mask) == -1)
    {
        return -1;
    }

    io_evt->mask |= mask;
    if (mask & ROC_EVENT_INPUT)
    {
        io_evt->iporc = proc;
    }
    if (mask & ROC_EVENT_OUTPUT)
    {
        io_evt->oproc = proc;
    }
    io_evt->custom_data = custom_data;
    if (fd > evt_loop->maxfd)
    {
        evt_loop->maxfd = fd;
    }
    return 0;
}

void roc_iom_del_evt(roc_evt_loop *evt_loop, int fd, int delmask)
{
    struct epoll_event ee = {0}; /* avoid valgrind warning */
    int mask = evt_loop->all_io_evts[fd].mask & (~delmask);

    ee.events = 0;
    if (mask & ROC_EVENT_INPUT)
    {
        ee.events |= EPOLLIN;
    }
    if (mask & ROC_EVENT_OUTPUT)
    {
        ee.events |= EPOLLOUT;
    }
    if (mask & ROC_EVENT_EPOLLET)
    {
        ee.events |= EPOLLET;
    }
    ee.data.fd = fd;
    if (mask != ROC_EVENT_NONE)
    {
        epoll_ctl(evt_loop->epfd, EPOLL_CTL_MOD, fd, &ee);
    }
    else
    {
        /* Note, Kernel < 2.6.9 requires a non null event pointer even for
         * EPOLL_CTL_DEL. */
        epoll_ctl(evt_loop->epfd, EPOLL_CTL_DEL, fd, &ee);
    }
}

void roc_del_io_evt(roc_evt_loop *evt_loop, int fd, int mask)
{
    if (fd >= evt_loop->size)
    {
        return;
    }
    roc_io_evt *io_evt = &evt_loop->all_io_evts[fd];
    if (io_evt->mask == ROC_EVENT_NONE)
    {
        return;
    }

    /* We want to always remove ROC_EVENT_BARRIER 
     * if set when ROC_EVENT_OUTPUT is removed. */
    if (mask & ROC_EVENT_OUTPUT)
    {
        mask |= ROC_EVENT_BARRIER;
    }

    roc_iom_del_evt(evt_loop, fd, mask);
    io_evt->mask = io_evt->mask & (~mask);
    if (fd == evt_loop->maxfd && io_evt->mask == ROC_EVENT_NONE)
    {
        /* Update the max fd */
        int i;

        for (i = evt_loop->maxfd - 1; i >= 0; i--)
        {
            if (evt_loop->all_io_evts[i].mask != ROC_EVENT_NONE)
            {
                break;
            }
        }
        evt_loop->maxfd = i;
    }
}

int roc_iom_add_evt(roc_evt_loop *evt_loop, int fd, int mask)
{

    struct epoll_event ee = {0}; /* avoid valgrind warning */
    /* If the fd was already monitored for some event, we need a MOD
     * operation. Otherwise we need an ADD operation. */
    int op = evt_loop->all_io_evts[fd].mask == ROC_EVENT_NONE
                 ? EPOLL_CTL_ADD
                 : EPOLL_CTL_MOD;

    ee.events = 0;
    mask |= evt_loop->all_io_evts[fd].mask; /* Merge old events */
    if (mask & ROC_EVENT_INPUT)
    {
        ee.events |= EPOLLIN;
    }

    if (mask & ROC_EVENT_OUTPUT)
    {
        ee.events |= EPOLLOUT;
    }
    if (mask & ROC_EVENT_EPOLLET)
    {
        ee.events |= EPOLLET;
    }

    ee.data.fd = fd;
    if (epoll_ctl(evt_loop->epfd, op, fd, &ee) == -1)
    {
        return -1;
    }
    return 0;
}

int roc_get_evts(roc_evt_loop *evt_loop, int fd)
{
    if (fd >= evt_loop->size)
    {
        return 0;
    }
    return evt_loop->all_io_evts[fd].mask;
}

void roc_get_time(int64_t *sec, int64_t *ms)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    *sec = (int64_t)(tv.tv_sec);
    *ms = (int64_t)(tv.tv_usec / 1000);
}

void roc_add_ms_to_now(int64_t addms, int64_t *ret_sec, int64_t *ret_ms)
{
    int64_t cur_sec, cur_ms, when_sec, when_ms;

    roc_get_time(&cur_sec, &cur_ms);
    when_sec = cur_sec + addms / 1000;
    when_ms = cur_ms + addms % 1000;
    if (when_ms >= 1000)
    {
        when_sec++;
        when_ms -= 1000;
    }
    *ret_sec = when_sec;
    *ret_ms = when_ms;
}

int64_t roc_add_time_evt(roc_evt_loop *evt_loop, int64_t ms,
                         roc_time_proc *proc, void *custom_data)
{
    int64_t id = evt_loop->time_evt_next_id++;
    roc_time_evt *te;

    te = malloc(sizeof(*te));
    if (te == NULL)
    {
        return -1;
    }
    te->id = id;
    roc_add_ms_to_now(ms, &te->when_sec, &te->when_ms);
    te->tproc = proc;
    te->custom_data = custom_data;
    te->next = evt_loop->time_evt_head;
    evt_loop->time_evt_head = te;
    return id;
}

int roc_del_time_evt(roc_evt_loop *evt_loop, int64_t id)
{
    roc_time_evt *te = evt_loop->time_evt_head;
    while (te)
    {
        if (te->id == id)
        {
            te->id = ROC_DELETED_EVENT_ID;
            return 0;
        }
        te = te->next;
    }
    return -1; /* NO event with the specified ID found */
}

/* Search the first timer to fire.
 * This operation is useful to know how many time the select can be
 * put in sleep without to delay any event.
 * If there are no timers NULL is returned.
 *
 * Note that's O(N) since time events are unsorted.
 * Possible optimizations (not needed by Redis so far, but...):
 * 1) Insert the event in order, so that the nearest is just the head.
 *    Much better but still insertion or deletion of timers is O(N).
 * 2) Use a skiplist to have this operation as O(1) and insertion as O(log(N)).
 */
roc_time_evt *roc_search_nearest_time_evt(roc_evt_loop *evt_loop)
{
    roc_time_evt *te = evt_loop->time_evt_head;
    roc_time_evt *nearest = NULL;

    while (te)
    {
        if ((!nearest) ||
            (te->when_sec < nearest->when_sec) ||
            (te->when_sec == nearest->when_sec && te->when_ms < nearest->when_ms))
        {
            nearest = te;
        }
        te = te->next;
    }
    return nearest;
}

/* Process time events */
int roc_process_time_evts(roc_evt_loop *evt_loop)
{
    int processed = 0;
    roc_time_evt *te, *prev;
    int64_t max_id;
    time_t now = time(NULL);

    /* If the system clock is moved to the future, and then set back to the
     * right value, time events may be delayed in a random way. Often this
     * means that scheduled operations will not be performed soon enough.
     *
     * Here we try to detect system clock skews, and force all the time
     * events to be processed ASAP when this happens: the idea is that
     * processing events earlier is less dangerous than delaying them
     * indefinitely, and practice suggests it is. */
    if (now < evt_loop->last_time)
    {
        te = evt_loop->time_evt_head;
        while (te)
        {
            te->when_sec = 0;
            te = te->next;
        }
    }
    evt_loop->last_time = now;

    prev = NULL;
    te = evt_loop->time_evt_head;
    max_id = evt_loop->time_evt_next_id - 1;
    while (te)
    {
        long now_sec, now_ms;
        long long id;

        /* Remove events scheduled for deletion. */
        if (te->id == ROC_DELETED_EVENT_ID)
        {
            roc_time_evt *next = te->next;
            if (prev == NULL)
            {
                evt_loop->time_evt_head = te->next;
            }
            else
            {
                prev->next = te->next;
            }
            free(te);
            te = next;
            continue;
        }

        /* Make sure we don't process time events created by time events in
         * this iteration. Note that this check is currently useless: we always
         * add new timers on the head, however if we change the implementation
         * detail, this check may be useful again: we keep it here for future
         * defense. */
        if (te->id > max_id)
        {
            te = te->next;
            continue;
        }
        roc_get_time(&now_sec, &now_ms);
        if ((now_sec > te->when_sec) ||
            (now_sec == te->when_sec && now_ms >= te->when_ms))
        {
            int retval;

            id = te->id;
            retval = te->tproc(evt_loop, id, te->custom_data);
            processed++;
            if (retval != ROC_NOMORE)
            {
                roc_add_ms_to_now(retval, &te->when_sec, &te->when_ms);
            }
            else
            {
                te->id = ROC_DELETED_EVENT_ID;
            }
        }
        prev = te;
        te = te->next;
    }
    return processed;
}

/* Process every pending time event, then every pending file event
 * (that may be registered by time event callbacks just processed).
 * Without special flags the function sleeps until some file event
 * fires, or when the next time event occurs (if any).
 *
 * If flags is 0, the function does nothing and returns.
 * if flags has ROC_ALL_EVENTS set, all the kind of events are processed.
 * if flags has ROC_FILE_EVENTS set, file events are processed.
 * if flags has ROC_TIME_EVENTS set, time events are processed.
 * if flags has ROC_DONT_WAIT set the function returns ASAP until all
 * if flags has ROC_CALL_AFTER_SLEEP set, the aftersleep callback is called.(drop)
 * the events that's possible to process without to wait are processed.
 *
 * The function returns the number of events processed. */
int roc_process_evts(roc_evt_loop *evt_loop, int flags)
{
    int processed = 0, numevents;

    /* Nothing to do, return*/
    if (!(flags & ROC_TIME_EVENTS) && !(flags & ROC_FILE_EVENTS))
    {
        return 0;
    }
    /* Note that we want call select() even if there are no
     * file events to process as long as we want to process time
     * events, in order to sleep until the next time event is ready
     * to fire. */
    if (evt_loop->maxfd != -1 ||
        ((flags & ROC_TIME_EVENTS) && !(flags & ROC_DONT_WAIT)))
    {
        int i;
        roc_time_evt *shortest = NULL;
        struct timeval tv, *tvp;

        if (flags & ROC_TIME_EVENTS && !(flags & ROC_DONT_WAIT))
        {
            shortest = roc_search_nearest_time_evt(evt_loop);
        }
        if (shortest)
        {
            long now_sec, now_ms;

            roc_get_time(&now_sec, &now_ms);
            tvp = &tv;

            /* How many milliseconds we need 
             * to wait for the next time event to fire? */
            int64_t ms = (shortest->when_sec - now_sec) * 1000 +
                         shortest->when_ms - now_ms;

            if (ms > 0)
            {
                tvp->tv_sec = ms / 1000;
                tvp->tv_usec = (ms % 1000) * 1000;
            }
            else
            {
                tvp->tv_sec = 0;
                tvp->tv_usec = 0;
            }
        }
        else
        {
            /* If we have to check for events but need to return
             * ASAP because of ROC_DONT_WAIT we need to set the timeout
             * to zero */
            if (flags & ROC_DONT_WAIT)
            {
                tv.tv_sec = tv.tv_usec = 0;
                tvp = &tv;
            }
            else
            {
                /* Otherwise we can block */
                tvp = NULL; /* wait forever */
            }
        }

        /* Call the multiplexing API, will return only on timeout or when
         * some event fires. */
        numevents = roc_iom_poll(evt_loop, tvp);

        for (i = 0; i < numevents; i++)
        {
            roc_io_evt *fe = &evt_loop->all_io_evts[evt_loop->ready_evts[i].fd];
            int mask = evt_loop->ready_evts[i].mask;
            int fd = evt_loop->ready_evts[i].fd;
            int fired = 0; /* Number of events fired for current fd. */

            /* Normally we execute the readable event first, and the writable
             * event laster. This is useful as sometimes we may be able
             * to serve the reply of a query immediately after processing the
             * query.
             *
             * However if ROC_EVENT_BARRIER is set in the mask, our application is
             * asking us to do the reverse: never fire the writable event
             * after the readable. In such a case, we invert the calls.
             * This is useful when, for instance, we want to do things
             * in the beforeSleep() hook, like fsynching a file to disk,
             * before replying to a client. */
            int invert = fe->mask & ROC_EVENT_BARRIER;

            /* Note the "fe->mask & mask & ..." code: maybe an already
             * processed event removed an element that fired and we still
             * didn't processed, so we check if the event is still valid.
             *
             * Fire the readable event if the call sequence is not
             * inverted. */
            if (!invert && fe->mask & mask & ROC_EVENT_INPUT)
            {
                fe->iporc(evt_loop, fd, fe->custom_data, mask);
                fired++;
            }

            /* Fire the writable event. */
            if (fe->mask & mask & ROC_EVENT_OUTPUT)
            {
                if (!fired || fe->oproc != fe->iporc)
                {
                    fe->oproc(evt_loop, fd, fe->custom_data, mask);
                    fired++;
                }
            }

            /* If we have to invert the call, fire the readable event now
             * after the writable one. */
            if (invert && fe->mask & mask & ROC_EVENT_INPUT)
            {
                if (!fired || fe->oproc != fe->iporc)
                {
                    fe->iporc(evt_loop, fd, fe->custom_data, mask);
                    fired++;
                }
            }

            processed++;
        }
    }
    /* Check time events */
    if (flags & ROC_TIME_EVENTS)
    {
        processed += roc_process_time_evts(evt_loop);
    }

    return processed; /* return the number of processed file/time events */
}

int roc_iom_poll(roc_evt_loop *evt_loop, struct timeval *tvp)
{
    int retval, numevents = 0;

    retval = epoll_wait(evt_loop->epfd, evt_loop->ret_evts, evt_loop->size,
                        tvp ? (tvp->tv_sec * 1000 + tvp->tv_usec / 1000) : -1);
    if (retval > 0)
    {
        int i;

        numevents = retval;
        for (i = 0; i < numevents; i++)
        {
            int mask = 0;
            struct epoll_event *e = evt_loop->ret_evts + i;

            if (e->events & EPOLLIN)
            {
                mask |= ROC_EVENT_INPUT;
            }
            if (e->events & EPOLLOUT)
            {
                mask |= ROC_EVENT_OUTPUT;
            }
            if (e->events & EPOLLERR)
            {
                mask |= ROC_EVENT_OUTPUT;
            }
            if (e->events & EPOLLHUP)
            {
                mask |= ROC_EVENT_OUTPUT;
            }
            evt_loop->ready_evts[i].fd = e->data.fd;
            evt_loop->ready_evts[i].mask = mask;
        }
    }
    return numevents;
}

void roc_evt_loop_start(roc_evt_loop *evt_loop)
{
    evt_loop->stop = 0;
    while (!evt_loop->stop)
    {
        roc_process_evts(evt_loop, ROC_ALL_EVENTS);
    }
}