#ifndef ROC_INTERFACE_H
#define ROC_INTERFACE_H


/*** Start of inlined file: roc_log.h ***/
#ifndef ROC_LOG_H
#define ROC_LOG_H


/*** Start of inlined file: roc_ringbuf.h ***/
#ifndef ROC_RINGBUF_H
#define ROC_RINGBUF_H
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/*** Start of inlined file: roc_bitops.h ***/
#ifndef ROC_BITOPS_H
#define ROC_BITOPS_H

#include <stdint.h>

#define is_power_of_2(x) ((x) != 0 && (((x) & ((x)-1)) == 0))

/**
 * 返回参数x的最高有效bit位的序号,若无有效bit位则返回0
 */
static inline uint8_t fls32(uint32_t x)
{
	uint8_t r = 32;

	if (!x)
	{
		return 0;
	}
	if (!(x & 0xffff0000u))
	{
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000u))
	{
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000u))
	{
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000u))
	{
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000u))
	{
		x <<= 1;
		r -= 1;
	}
	return r;
}

static inline uint8_t fls64(uint64_t x)
{
	uint32_t h = x >> 32;
	if (h)
	{
		return fls32(h) + 32;
	}
	return fls32(x);
}

static inline uint64_t __roundup_pow_of_two(uint64_t n)
{
	uint64_t one = 1;
	return one << fls64(n - 1);
}

static inline uint64_t __rounddown_pow_of_two(uint64_t n)
{
	uint64_t one = 1;
	return one << (fls64(n) - 1);
}

static inline uint8_t __ilog2_u32(uint32_t n)
{
	return fls32(n) - 1;
}

static inline uint64_t __ilog2_u64(uint64_t n)
{
	return fls64(n) - 1;
}

#define ilog2(n)                    \
(                                   \
	__builtin_constant_p(n) ? (     \
		(n) < 2 ? 0 :               \
		(n) & (1ULL << 63) ? 63 :   \
		(n) & (1ULL << 62) ? 62 :   \
		(n) & (1ULL << 61) ? 61 :   \
		(n) & (1ULL << 60) ? 60 :   \
		(n) & (1ULL << 59) ? 59 :   \
		(n) & (1ULL << 58) ? 58 :   \
		(n) & (1ULL << 57) ? 57 :   \
		(n) & (1ULL << 56) ? 56 :   \
		(n) & (1ULL << 55) ? 55 :   \
		(n) & (1ULL << 54) ? 54 :   \
		(n) & (1ULL << 53) ? 53 :   \
		(n) & (1ULL << 52) ? 52 :   \
		(n) & (1ULL << 51) ? 51 :   \
		(n) & (1ULL << 50) ? 50 :   \
		(n) & (1ULL << 49) ? 49 :   \
		(n) & (1ULL << 48) ? 48 :   \
		(n) & (1ULL << 47) ? 47 :   \
		(n) & (1ULL << 46) ? 46 :   \
		(n) & (1ULL << 45) ? 45 :   \
		(n) & (1ULL << 44) ? 44 :   \
		(n) & (1ULL << 43) ? 43 :   \
		(n) & (1ULL << 42) ? 42 :   \
		(n) & (1ULL << 41) ? 41 :   \
		(n) & (1ULL << 40) ? 40 :   \
		(n) & (1ULL << 39) ? 39 :   \
		(n) & (1ULL << 38) ? 38 :   \
		(n) & (1ULL << 37) ? 37 :   \
		(n) & (1ULL << 36) ? 36 :   \
		(n) & (1ULL << 35) ? 35 :   \
		(n) & (1ULL << 34) ? 34 :   \
		(n) & (1ULL << 33) ? 33 :   \
		(n) & (1ULL << 32) ? 32 :   \
		(n) & (1ULL << 31) ? 31 :   \
		(n) & (1ULL << 30) ? 30 :   \
		(n) & (1ULL << 29) ? 29 :   \
		(n) & (1ULL << 28) ? 28 :   \
		(n) & (1ULL << 27) ? 27 :   \
		(n) & (1ULL << 26) ? 26 :   \
		(n) & (1ULL << 25) ? 25 :   \
		(n) & (1ULL << 24) ? 24 :   \
		(n) & (1ULL << 23) ? 23 :   \
		(n) & (1ULL << 22) ? 22 :   \
		(n) & (1ULL << 21) ? 21 :   \
		(n) & (1ULL << 20) ? 20 :   \
		(n) & (1ULL << 19) ? 19 :   \
		(n) & (1ULL << 18) ? 18 :   \
		(n) & (1ULL << 17) ? 17 :   \
		(n) & (1ULL << 16) ? 16 :   \
		(n) & (1ULL << 15) ? 15 :   \
		(n) & (1ULL << 14) ? 14 :   \
		(n) & (1ULL << 13) ? 13 :   \
		(n) & (1ULL << 12) ? 12 :   \
		(n) & (1ULL << 11) ? 11 :   \
		(n) & (1ULL << 10) ? 10 :   \
		(n) & (1ULL <<  9) ?  9 :   \
		(n) & (1ULL <<  8) ?  8 :   \
		(n) & (1ULL <<  7) ?  7 :   \
		(n) & (1ULL <<  6) ?  6 :   \
		(n) & (1ULL <<  5) ?  5 :   \
		(n) & (1ULL <<  4) ?  4 :   \
		(n) & (1ULL <<  3) ?  3 :   \
		(n) & (1ULL <<  2) ?  2 :   \
		1 ) :                       \
		(sizeof(n) <= 4) ?          \
		__ilog2_u32(n) :            \
		__ilog2_u64(n)              \
 )

#define rounddown_pow_of_two(n)     \
(__builtin_constant_p(n) ?          \
((1UL << ilog2(n))) :               \
__rounddown_pow_of_two(n))

#define roundup_pow_of_two(n)                   \
(__builtin_constant_p(n) ?                      \
((n == 1) ? 1 : (1UL << (ilog2((n)-1) + 1))) :  \
 __roundup_pow_of_two(n))

#endif /* ROC_BITOPS_H */

/*** End of inlined file: roc_bitops.h ***/


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

/*** End of inlined file: roc_ringbuf.h ***/

#define ROC_LOG_LEVEL_STDERR 0
#define ROC_LOG_LEVEL_EMERG 1
#define ROC_LOG_LEVEL_ALERT 2
#define ROC_LOG_LEVEL_CRIT 3
#define ROC_LOG_LEVEL_ERR 4
#define ROC_LOG_LEVEL_WARN 5
#define ROC_LOG_LEVEL_NOTICE 6
#define ROC_LOG_LEVEL_INFO 7
#define ROC_LOG_LEVEL_DEBUG 8

#define ROC_LOG_LEVEL_STDERR_PREFIX "[STDERR]"
#define ROC_LOG_LEVEL_EMERG_PREFIX "[EMERG]"
#define ROC_LOG_LEVEL_ALERT_PREFIX "[ALERT]"
#define ROC_LOG_LEVEL_CRIT_PREFIX "[CRIT]"
#define ROC_LOG_LEVEL_ERR_PREFIX "[ERR]"
#define ROC_LOG_LEVEL_WARN_PREFIX "[WARN]"
#define ROC_LOG_LEVEL_NOTICE_PREFIX "[NOTICE]"
#define ROC_LOG_LEVEL_INFO_PREFIX "[INFO]"
#define ROC_LOG_LEVEL_DEBUG_PREFIX "[DEBUG]"

extern int roc_log_level;
typedef struct
{
	int status;
	roc_ringbuf *rb;
	void *queue_node[2];

} roc_logcell;

int roc_log_init(const char *path, int level);
void roc_log_flush();
void roc_log_write(int level, const char *format, ...);

#define ROC_LOG_STDERR(format, ...)                                 \
	roc_log_write(ROC_LOG_LEVEL_STDERR, format, ##__VA_ARGS__);
#define ROC_LOG_EMERG(format, ...)                                  \
	if (roc_log_level >= ROC_LOG_LEVEL_EMERG)                       \
	{                                                               \
		roc_log_write(ROC_LOG_LEVEL_EMERG, format, ##__VA_ARGS__);  \
	}
#define ROC_LOG_ALERT(format, ...)                                  \
	if (roc_log_level >= ROC_LOG_LEVEL_ALERT)                       \
	{                                                               \
		roc_log_write(ROC_LOG_LEVEL_ALERT, format, ##__VA_ARGS__);  \
	}
#define ROC_LOG_CRIT(format, ...)                                   \
	if (roc_log_level >= ROC_LOG_LEVEL_CRIT)                        \
	{                                                               \
		roc_log_write(ROC_LOG_LEVEL_CRIT, format, ##__VA_ARGS__);   \
	}
#define ROC_LOG_ERR(format, ...)                                    \
	if (roc_log_level >= ROC_LOG_LEVEL_ERR)                         \
	{                                                               \
		roc_log_write(ROC_LOG_LEVEL_ERR, format, ##__VA_ARGS__);    \
	}
#define ROC_LOG_WARN(format, ...)                                   \
	if (roc_log_level >= ROC_LOG_LEVEL_WARN)                        \
	{                                                               \
		roc_log_write(ROC_LOG_LEVEL_WARN, format, ##__VA_ARGS__);   \
	}
#define ROC_LOG_NOTICE(format, ...)                                 \
	if (roc_log_level >= ROC_LOG_LEVEL_NOTICE)                      \
	{                                                               \
		roc_log_write(ROC_LOG_LEVEL_NOTICE, format, ##__VA_ARGS__); \
	}
#define ROC_LOG_INFO(format, ...)                                   \
	if (roc_log_level >= ROC_LOG_LEVEL_INFO)                        \
	{                                                               \
		roc_log_write(ROC_LOG_LEVEL_INFO, format, ##__VA_ARGS__);   \
	}
#define ROC_LOG_DEBUG(format, ...)                                  \
	if (roc_log_level >= ROC_LOG_LEVEL_DEBUG)                       \
	{                                                               \
		roc_log_write(ROC_LOG_LEVEL_DEBUG, format, ##__VA_ARGS__);  \
	}

#endif /* ROC_LOG_H */

/*** End of inlined file: roc_log.h ***/


/*** Start of inlined file: roc_threadpool.h ***/
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

/*** End of inlined file: roc_threadpool.h ***/


/*** Start of inlined file: roc_net.h ***/
#ifndef ROC_NET_H
#define ROC_NET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>

int roc_set_fd_nonblock(int fd, int nonblock);
int roc_set_tcp_keepalive(int sockfd, int interval);
int roc_tcp_svr(int port, char *bindaddr, int domain, int backlog);
int roc_connect(char *addr, int port, char *source_addr, int flags);
int roc_local_connect(char *path, int flags);
int roc_accept(int sockfd, char *ip, size_t ip_len, int *port);
int roc_local_tcp_svr(char *path, mode_t perm, int backlog);
int roc_local_accpet(int sockfd);
int roc_net_resolve(char *host, char *ipbuf, size_t ipbuf_len, int flags);
int roc_getsockname(int fd, char *ip, size_t ip_len, int *port);
int roc_get_peer_ip_port(int fd, char *ip, size_t ip_len, int *port);
int roc_fmt_addr(char *buf, size_t buf_len, char *ip, int port);
int roc_fmt_peer(int sockfd, char *buf, size_t buf_len);
int roc_fmt_sock(int fd, char *fmt, size_t fmt_len);
int roc_recv(int sockfd, void *buf, int len, int nonblock);
int roc_send(int sockfd, const void *buf, int len, int nonblock);

/**
 * flag = 1 open nodelay
 * flag = 0 close nodelay
 */
static inline int roc_set_tcp_nodelay(int sockfd, int flag)
{
	return setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
}

static inline int roc_set_sock_sndbuf(int sockfd, int size)
{
	return setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
}

/* Set the socket send timeout (SO_SNDTIMEO socket option) to the specified
 * number of milliseconds, or disable it if the 'ms' argument is zero. */
static inline int roc_set_sock_sndtimeo(int sockfd, int64_t ms)
{
	struct timeval tv;

	tv.tv_sec = ms / 1000;
	tv.tv_usec = (ms % 1000) * 1000;
	return setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* Set the socket receive timeout (SO_RCVTIMEO socket option) to the specified
 * number of milliseconds, or disable it if the 'ms' argument is zero. */
static inline int roc_set_sock_rcvtimeo(int sockfd, int64_t ms)
{
	struct timeval tv;

	tv.tv_sec = ms / 1000;
	tv.tv_usec = (ms % 1000) * 1000;
	return setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static inline int roc_set_sock_reuseaddr(int sockfd)
{
	int yes = 1;
	/* Make sure connection-intensive things
	 * will be able to close/open sockets a zillion of times */
	return setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
}

#endif /* ROC_NET_H */

/*** End of inlined file: roc_net.h ***/


/*** Start of inlined file: roc_evt.h ***/
#ifndef ROC_EVT_H
#define ROC_EVT_H

#include <time.h>
#include <stdint.h>

#define ROC_EVENT_NONE 0
#define ROC_EVENT_INPUT 1
#define ROC_EVENT_OUTPUT 2
#define ROC_EVENT_BARRIER 4
#define ROC_EVENT_EPOLLET 8
#define ROC_EVENT_IOET ( \
	ROC_EVENT_INPUT |    \
	ROC_EVENT_OUTPUT |   \
	ROC_EVENT_EPOLLET)

#define ROC_SOCK_CONNECT 0
#define ROC_SOCK_DATA 0
#define ROC_SOCK_DRAIN 1
#define ROC_SOCK_CLOSE 2
#define ROC_SOCK_EVTEND 3

#define ROC_NOMORE -1
#define ROC_DELETED_EVENT_ID -1

#define ROC_FILE_EVENTS 1
#define ROC_TIME_EVENTS 2
#define ROC_ALL_EVENTS ( \
	ROC_FILE_EVENTS |    \
	ROC_TIME_EVENTS)
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

/*** End of inlined file: roc_evt.h ***/


/*** Start of inlined file: roc_plugin.h ***/
#ifndef ROC_PLUGIN_H
#define ROC_PLUGIN_H

/*** Start of inlined file: roc_svr.h ***/
#ifndef ROC_SVR_H
#define ROC_SVR_H

#define ROC_PLUGIN_MAX 16

struct roc_svr_s;
struct roc_link_s;
struct roc_plugin_s;
typedef struct roc_svr_s roc_svr;
typedef struct roc_link_s roc_link;
typedef struct roc_plugin_s roc_plugin;

typedef void roc_handle_func_link(roc_link *link, void *custom_data);
typedef void roc_handle_func_svr(roc_svr *svr, void *custom_data);
typedef int roc_send_func(roc_link *link, void *buf, int len);
typedef void roc_log_func(int level, const char *format, ...);

struct roc_plugin_s
{
	void *so_handle;
	void *data_so_handle;
	roc_handle_func_link *connect_handler;
	roc_handle_func_link *recv_handler;
	roc_handle_func_link *close_handler;

	roc_handle_func_svr *init_handler;
	roc_handle_func_svr *fini_handler;
	int level; /* level == -1表示该插件未初始化 */
};

struct roc_svr_s
{
	int fd;
	int port;
	int domain;
	int type;
	int backlog;
	int maxlink;
	int nonblock;
	int next_plugin_level;
	roc_evt_loop *evt_loop;
	roc_handle_func_link *handler[ROC_SOCK_EVTEND];
	roc_handle_func_link *close_link;
	roc_plugin plugin[ROC_PLUGIN_MAX];
	roc_send_func *send;
	roc_log_func *log;
};

struct roc_link_s
{
	int fd;
	int port;
	char *ip;
	int next_plugin_level;
	roc_ringbuf *ibuf;
	roc_ringbuf *obuf;
	roc_evt_loop *evt_loop;
	roc_handle_func_link *handler[ROC_SOCK_EVTEND];
	roc_svr *svr;
};
roc_svr *roc_svr_new(int port);
int roc_init(const char *log_path, int log_level);
int roc_run();
int roc_svr_start(roc_svr *svr);
int roc_svr_stop(roc_svr *svr);
int roc_smart_send(roc_link *link, void *buf, int len);
int roc_svr_use(roc_svr *svr, char *plugin_path);
void roc_svr_on(roc_svr *svr, int evt_type, roc_handle_func_link *handler);
void roc_link_on(roc_link *link, int evt_type, roc_handle_func_link *handler);

#endif /* ROC_SVR_H */

/*** End of inlined file: roc_svr.h ***/


int register_plugin(roc_plugin *plugin_so, const char *so_path, int flag);
void unregister_plugin(roc_plugin *plugin_so);
int register_data_plugin(roc_plugin *plugin_so, const char *so_path);
void unregister_data_plugin(roc_plugin *plugin_so);

#endif /* ROC_PLUGIN_H */

/*** End of inlined file: roc_plugin.h ***/

#endif /* ROC_INTERFACE_H */

