#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "roc_bitops.h"

#define min(a, b) (((a) < (b)) ? (a) : (b))

typedef unsigned char byte;

typedef struct
{
    uint32_t head;
    uint32_t tail;
    byte *data;
    uint32_t size;
} roc_ringbuf;

static inline roc_ringbuf *roc_ringbuf_new(uint32_t size)
{
    size = is_power_of_2(size) ? size : roundup_pow_of_two(size);
    roc_ringbuf *self = (roc_ringbuf *)malloc(sizeof(roc_ringbuf));
    if (!self)
    {
        return NULL;
    }
    self->data = (byte *)malloc(size * sizeof(byte));
    if (!self->data)
    {
        free(self);
        return NULL;
    }
    self->size = size;
    self->head = 0;
    self->tail = 0;
}

static inline void roc_ringbuf_del(roc_ringbuf *self)
{
    free(self->data);
    free(self);
}

/**
 * 判断环形缓冲区空闲字节数
 */
static inline uint32_t roc_ringbuf_unused(roc_ringbuf *self)
{
    return self->size - self->head + self->tail;
}

static inline uint32_t roc_ringbuf_write(roc_ringbuf *self,
                                         const byte *data,
                                         uint32_t len)
{
    uint32_t tail_capacity;
    len = min(len, roc_ringbuf_unused(self));
    /* first put the data starting from fifo->in to buffer end */
    tail_capacity = min(len, self->size - (self->tail & (self->size - 1)));
    memcpy(self->data + (self->tail & (self->size - 1)), data, tail_capacity);
    /* then put the rest (if any) at the beginning of the buffer */
    memcpy(self->data, data + tail_capacity, len - tail_capacity);
    self->tail += len; /* 到达最大值后溢出, 转为0, 从头开始 */
    return len;
}

static inline uint32_t roc_ringbuf_read(roc_ringbuf *self,
                                        byte *data,
                                        uint32_t len)
{
    uint32_t head_readable;
    len = min(len, self->tail - self->head);
    /* first get the data from fifo->out until the end of the buffer */
    head_readable = min(len, self->size - (self->head & (self->size - 1)));
    memcpy(data, self->data + (self->head & (self->size - 1)), head_readable);
    /* then get the rest (if any) from the beginning of the buffer */
    memcpy(data + head_readable, self->data, len - head_readable);
    self->head += len; /* 到达最大值后溢出, 转为0, 从头开始 */
    return len;
}

/*未实现*/
static inline int roc_ringbuf_resize(roc_ringbuf *self, uint32_t newsize)
{
    return 0;
}