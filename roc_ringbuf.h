#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "roc_bitops.h"

#define min(a, b) (((a) < (b)) ? (a) : (b))

const uint32_t MAX_RINGBUF_SIZE = 5 * 1024 * 1024; /* 5MB */

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
    return self;
}

static inline void roc_ringbuf_del(roc_ringbuf *self)
{
    free(self->data);
    free(self);
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
    self->head += len; /* 到达最大值后溢出, 逻辑仍然成立 */
    return len;
}

static inline int roc_ringbuf_resize(roc_ringbuf *self, uint32_t newsize)
{
    if (newsize <= self->size)
    {
        return 0;
    }
    newsize = is_power_of_2(newsize) ? newsize : roundup_pow_of_two(newsize);
    if (newsize >= MAX_RINGBUF_SIZE)
    {
        return -1;
    }
    byte *bakptr = self->data;
    self->data = (byte *)realloc(self->data, newsize);
    if (!self->data)
    {
        self->data = bakptr;
        return -1;
    }
    uint8_t readable = self->tail - self->head;
    byte *bak_data = (byte *)malloc(readable);
    roc_ringbuf_read(self, bak_data, readable);
    memcpy(self->data, bak_data, readable);
    free(bak_data);
    self->head = 0;
    self->tail = readable;
    self->size = newsize;
    return 0;
}

/**
 * 判断环形缓冲区空闲字节数
 */
static inline uint32_t roc_ringbuf_unused(roc_ringbuf *self)
{
    return self->size + self->head - self->tail;
}

static inline uint32_t roc_ringbuf_write(roc_ringbuf *self,
                                         const byte *data,
                                         uint32_t len)
{
    uint32_t tail_capacity;
    uint32_t uu = roc_ringbuf_unused(self);
    len = len > uu && roc_ringbuf_resize(self, self->size + len - uu) == -1
              ? min(len, uu)
              : len;
    /* first put the data starting from fifo->in to buffer end */
    tail_capacity = min(len, self->size - (self->tail & (self->size - 1)));
    memcpy(self->data + (self->tail & (self->size - 1)), data, tail_capacity);
    /* then put the rest (if any) at the beginning of the buffer */
    memcpy(self->data, data + tail_capacity, len - tail_capacity);
    self->tail += len; /* 到达最大值后溢出, 逻辑仍然成立 */
    return len;
}
