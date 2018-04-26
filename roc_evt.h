#ifndef ROC_EVT_H
#define ROC_EVT_H

#include <time.h>
#include <stdint.h>

#define ROC_EVENT_NONE 0
#define ROC_EVENT_INPUT 1
#define ROC_EVENT_OUTPUT 2
#define ROC_EVENT_BARRIER 4
#define ROC_EVENT_EPOLLET 8
#define ROC_EVENT_IOET (ROC_EVENT_INPUT | ROC_EVENT_OUTPUT | ROC_EVENT_EPOLLET)

#define ROC_SOCK_CONNECT 0
#define ROC_SOCK_DATA 0
#define ROC_SOCK_DRAIN 1
#define ROC_SOCK_CLOSE 2
#define ROC_SOCK_EVTEND 3

#define ROC_NOMORE -1
#define ROC_DELETED_EVENT_ID -1

#define ROC_FILE_EVENTS 1
#define ROC_TIME_EVENTS 2
#define ROC_ALL_EVENTS (ROC_FILE_EVENTS | ROC_TIME_EVENTS)
#define ROC_DONT_WAIT 4
#define ROC_CALL_AFTER_SLEEP 8

struct roc_evt_loop;

/* Types and data structures */
typedef void roc_io_proc(struct roc_evt_loop *evt_loop,
                         int fd, void *custom_data, int mask);
typedef int roc_time_proc(struct roc_evt_loop *evt_loop,
                          int64_t id, void *custom_data);

/* File event structure */
typedef struct roc_io_evt
{
    int mask; /* one of ROC_(INPUT_EVENT|OUTPUT_EVENT|EVENT_BARRIER) */
    roc_io_proc *iporc;
    roc_io_proc *oproc;
    void *custom_data;
} roc_io_evt;

/* Time event structure */
typedef struct roc_time_evt
{
    int64_t id;       /* time event identifier. */
    int64_t when_sec; /* seconds */
    int64_t when_ms;  /* milliseconds */
    roc_time_proc *tproc;
    void *custom_data;
    struct roc_time_evt *next;
} roc_time_evt;

typedef struct roc_ready_evt
{
    int fd;
    int mask;
} roc_ready_evt;

/* State of an event based program */
typedef struct roc_evt_loop
{
    int size;           /* max number of file descriptors tracked */
    volatile int maxfd; /* highest file descriptor currently registered */

    roc_io_evt *all_io_evts; /* Registered events */
    roc_time_evt *time_evt_head;
    roc_ready_evt *ready_evts; /* Fired events */

    int64_t time_evt_next_id;
    time_t last_time; /* Used to detect system clock skew */

    int stop;
    int epfd;
    struct epoll_event *ret_evts;
} roc_evt_loop;

roc_evt_loop *roc_create_evt_loop(int size);
void roc_del_evt_loop(roc_evt_loop *evt_loop);
void roc_evt_loop_start(roc_evt_loop *evt_loop);
void roc_evt_loop_stop(roc_evt_loop *evt_loop);

int roc_add_io_evt(roc_evt_loop *evt_loop, int fd, int mask,
                   roc_io_proc proc, void *custom_data);
void roc_del_io_evt(roc_evt_loop *evt_loop, int fd, int mask);

int64_t roc_add_time_evt(roc_evt_loop *evt_loop, int64_t ms,
                         roc_time_proc *proc, void *custom_data);

int roc_del_time_evt(roc_evt_loop *evt_loop, int64_t id);

int roc_evt_loop_resize(roc_evt_loop *evt_loop, int newsize);

int roc_get_evts(roc_evt_loop *evt_loop, int fd);

#endif /* ROC_EVT_H */
