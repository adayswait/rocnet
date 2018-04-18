#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>

#include "roc_evt.h"
#include "roc_net.h"
#include "roc_ringbuf.h"
#include "roc_threadpool.h"

#define WORKER_NUMBER 10000

void work(roc_work *w)
{
    printf("work get param %d\n", *((int *)(w->data)));
}

int print_data(byte *data, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        printf("%1.1s", data + i);
    }
    printf("\n");
}

int main()
{
    printf("welcome to use rocnet\n\n");

    printf(">>test ringbuf\n");
    uint32_t read_len, wrote_len;
    char *r1 = malloc(1024);
    uint32_t read_offset = 0;
    char *w1 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char *w2 = "abcdefghijklmnopqrstuvwxyz";
    roc_ringbuf *rb = roc_ringbuf_new(1);
    roc_ringbuf_write(rb, "A", 1);
    roc_ringbuf_write(rb, "B", 1);
    roc_ringbuf_write(rb, "CD", 2);
    roc_ringbuf_write(rb, "E", 1);
    roc_ringbuf_write(rb, "FGHI", 4);
    roc_ringbuf_write(rb, "JKLMNOP~", 8);
    roc_ringbuf_write(rb, w1, 36);
    read_offset += roc_ringbuf_read(rb, r1 + read_offset, 10);
    roc_ringbuf_write(rb, "-", 1);
    roc_ringbuf_write(rb, w2, 26);
    read_offset += roc_ringbuf_read(rb, r1 + read_offset, 21);
    roc_ringbuf_write(rb, "-", 1);
    roc_ringbuf_write(rb, w1, 36);
    read_offset += roc_ringbuf_read(rb, r1 + read_offset, 21);
    roc_ringbuf_write(rb, "-", 1);
    roc_ringbuf_write(rb, w1, 36);
    read_offset += roc_ringbuf_read(rb, r1 + read_offset, 10);
    read_offset += roc_ringbuf_read(rb, r1 + read_offset, 72);
    read_offset += roc_ringbuf_read(rb, r1 + read_offset, 16);
    print_data(r1, 1024);
    roc_ringbuf_del(rb);

    printf(">>test threadpool\n");
    setenv("ROC_THREADPOOL_SIZE", "100", 1);
    int n_arr[WORKER_NUMBER];
    roc_work w_arr[WORKER_NUMBER];
    int i;
    for (i = 0; i < WORKER_NUMBER; i++)
    {
        roc_work w;
        w_arr[i] = w;
        n_arr[i] = i;
        roc_tpwork_submit(&w_arr[i], work, &n_arr[i]);
    }
    sleep(100);
    return 0;
}
