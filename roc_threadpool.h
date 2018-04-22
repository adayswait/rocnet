#ifndef THREADPOOL_H_
#define THREADPOOL_H_

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct roc_work_s
{
    void (*work)(struct roc_work_s *w);
    void *data;
    void *queue_node[2];
};
typedef struct roc_work_s roc_work;

void roc_tpwork_submit(roc_work *w,
                       void (*work)(roc_work *w),
                       void *data);
int roc_tpwork_cancel(roc_work *w);
int roc_thread_create(pthread_t *tid, void (*entry)(void *), void *arg);
#endif /* THREADPOOL_H_ */
