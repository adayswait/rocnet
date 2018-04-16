#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>

#include "roc_evt.h"
#include "roc_net.h"
#include "roc_ringbuf.h"

int main()
{
    printf("welcome to use rocnet\n\n");

    printf(">>test ringbuf\n");
    roc_ringbuf *rb = roc_ringbuf_new(6);
    printf("\troc_ringbuf created, size is %u\n", rb->size);
    char *write_data = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint32_t write_data_offset = 0;
    printf("\tdata to write:%12.12s\n", write_data);
    uint32_t wrote_len = roc_ringbuf_write(rb, write_data, 12);
    write_data_offset += wrote_len;
    printf("\t%u bytes wrote,roc_ringbuf data:%8.8s\n", wrote_len, rb->data);
    char *read_data = malloc(32);
    printf("\ttry to read 5 bytes from ringbuf\n");
    uint32_t read_len = roc_ringbuf_read(rb, read_data, 5);
    printf("\t%u bytes read, data is:%5.5s\n", read_len, read_data);
    printf("\tdata to write:%4.4s\n", write_data + write_data_offset);
    wrote_len = roc_ringbuf_write(rb, write_data + write_data_offset, 4);
    write_data_offset += wrote_len;
    printf("\t%u bytes wrote,roc_ringbuf data:%8.8s\n", wrote_len, rb->data);
    printf("\ttry to read 6 bytes from ringbuf\n");
    read_len = roc_ringbuf_read(rb, read_data, 6);
    printf("\t%u bytes read, data is:%6.6s\n", read_len, read_data);
    printf("\tdata to write:%8.8s\n", write_data + write_data_offset);
    wrote_len = roc_ringbuf_write(rb, write_data + write_data_offset, 8);
    write_data_offset += wrote_len;
    printf("\t%u bytes wrote,roc_ringbuf data:%8.8s\n", wrote_len, rb->data);
    roc_ringbuf_del(rb);
    return 0;
}