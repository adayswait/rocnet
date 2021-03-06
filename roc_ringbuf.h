#ifndef ROC_RINGBUF_H
#define ROC_RINGBUF_H
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "roc_bitops.h"

#define min(a, b) (((a) < (b)) ? (a) : (b))

typedef struct
{
    uint32_t head;
    uint32_t tail;
    char *data;
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
    self->data = (char *)malloc(size * sizeof(char));
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
                                        char *data,
                                        uint32_t len)
{
    uint32_t head_readable;
    len = min(len, self->tail - self->head);
    head_readable = min(len, self->size - (self->head & (self->size - 1)));
    memcpy(data, self->data + (self->head & (self->size - 1)), head_readable);
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
    char *bakptr = self->data;
    self->data = (char *)realloc(self->data, newsize * sizeof(char));
    if (!self->data)
    {
        self->data = bakptr;
        return -1;
    }
    uint32_t readable = self->tail - self->head;
    char *newmem = self->data + self->size;
    roc_ringbuf_read(self, newmem, readable);
    memcpy(self->data, newmem, readable);
    self->head = 0;
    self->tail = readable;
    self->size = newsize;
    return 0;
}

/**
 * 判断环形缓冲区已使用字节数
 */
static inline uint32_t roc_ringbuf_used(roc_ringbuf *self)
{
    return self->tail - self->head;
}

/**
 * 判断环形缓冲区空闲字节数
 */
static inline uint32_t roc_ringbuf_unused(roc_ringbuf *self)
{
    return self->size + self->head - self->tail;
}

/**
 * 如果可用字节数小于len,自动扩容
 */
static inline uint32_t roc_ringbuf_write(roc_ringbuf *self,
                                         char *data,
                                         uint32_t len)
{
    uint32_t tail_capacity;
    uint32_t uu = roc_ringbuf_unused(self);
    len = len > uu && roc_ringbuf_resize(self, self->size + len - uu) == -1
              ? min(len, uu)
              : len;
    tail_capacity = min(len, self->size - (self->tail & (self->size - 1)));
    memcpy(self->data + (self->tail & (self->size - 1)), data, tail_capacity);
    memcpy(self->data, data + tail_capacity, len - tail_capacity);
    self->tail += len; /* 到达最大值后溢出, 逻辑仍然成立 */
    return len;
}

/**
 * 不会自动扩容,减少resize开销,提升性能,用于特殊场景
 */
static inline uint32_t roc_ringbuf_write_rigid(roc_ringbuf *self,
                                               char *data,
                                               uint32_t len)
{
    uint32_t tail_capacity;
    len = min(len, roc_ringbuf_unused(self));
    tail_capacity = min(len, self->size - (self->tail & (self->size - 1)));
    memcpy(self->data + (self->tail & (self->size - 1)), data, tail_capacity);
    memcpy(self->data, data + tail_capacity, len - tail_capacity);
    self->tail += len; /* 到达最大值后溢出, 逻辑仍然成立 */
    return len;
}

static inline uint32_t roc_ringbuf_readable(roc_ringbuf *self)
{
    return self->tail - self->head;
}

#endif /* ROC_RINGBUF_H */
