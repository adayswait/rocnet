
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

int roc_log_level;
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


/*** Start of inlined file: roc_log.c ***/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>


/*** Start of inlined file: roc_queue.h ***/
#ifndef ROC_QUEUE_H
#define ROC_QUEUE_H

#include <stddef.h>

typedef void *QUEUE[2];

/* Private macros. */
#define QUEUE_NEXT(q) (*(QUEUE **)&((*(q))[0]))
#define QUEUE_PREV(q) (*(QUEUE **)&((*(q))[1]))
#define QUEUE_PREV_NEXT(q) (QUEUE_NEXT(QUEUE_PREV(q)))
#define QUEUE_NEXT_PREV(q) (QUEUE_PREV(QUEUE_NEXT(q)))

/* Public macros. */
#define QUEUE_DATA(ptr, type, field) \
  ((type *)((char *)(ptr)-offsetof(type, field)))

/* Important note: mutating the list while QUEUE_FOREACH is
 * iterating over its elements results in undefined behavior.
 */
#define QUEUE_FOREACH(q, h) \
  for ((q) = QUEUE_NEXT(h); (q) != (h); (q) = QUEUE_NEXT(q))

#define QUEUE_EMPTY(q) \
  ((const QUEUE *)(q) == (const QUEUE *)QUEUE_NEXT(q))

#define QUEUE_HEAD(q) \
  (QUEUE_NEXT(q))

#define QUEUE_INIT(q)    \
  do                     \
  {                      \
	QUEUE_NEXT(q) = (q); \
	QUEUE_PREV(q) = (q); \
  } while (0)

#define QUEUE_ADD(h, n)                 \
  do                                    \
  {                                     \
	QUEUE_PREV_NEXT(h) = QUEUE_NEXT(n); \
	QUEUE_NEXT_PREV(n) = QUEUE_PREV(h); \
	QUEUE_PREV(h) = QUEUE_PREV(n);      \
	QUEUE_PREV_NEXT(h) = (h);           \
  } while (0)

#define QUEUE_SPLIT(h, q, n)       \
  do                               \
  {                                \
	QUEUE_PREV(n) = QUEUE_PREV(h); \
	QUEUE_PREV_NEXT(n) = (n);      \
	QUEUE_NEXT(n) = (q);           \
	QUEUE_PREV(h) = QUEUE_PREV(q); \
	QUEUE_PREV_NEXT(h) = (h);      \
	QUEUE_PREV(q) = (n);           \
  } while (0)

#define QUEUE_MOVE(h, n)        \
  do                            \
  {                             \
	if (QUEUE_EMPTY(h))         \
	  QUEUE_INIT(n);            \
	else                        \
	{                           \
	  QUEUE *q = QUEUE_HEAD(h); \
	  QUEUE_SPLIT(h, q, n);     \
	}                           \
  } while (0)

#define QUEUE_INSERT_HEAD(h, q)    \
  do                               \
  {                                \
	QUEUE_NEXT(q) = QUEUE_NEXT(h); \
	QUEUE_PREV(q) = (h);           \
	QUEUE_NEXT_PREV(q) = (q);      \
	QUEUE_NEXT(h) = (q);           \
  } while (0)

#define QUEUE_INSERT_TAIL(h, q)    \
  do                               \
  {                                \
	QUEUE_NEXT(q) = (h);           \
	QUEUE_PREV(q) = QUEUE_PREV(h); \
	QUEUE_PREV_NEXT(q) = (q);      \
	QUEUE_PREV(h) = (q);           \
  } while (0)

#define QUEUE_REMOVE(q)                 \
  do                                    \
  {                                     \
	QUEUE_PREV_NEXT(q) = QUEUE_NEXT(q); \
	QUEUE_NEXT_PREV(q) = QUEUE_PREV(q); \
  } while (0)

#endif /* ROC_QUEUE_H */

/*** End of inlined file: roc_queue.h ***/

#define ROC_LOG_CELL_NUM 1024
#define ROC_LOG_CELL_SIZE 4096
#define ROC_PRELOG_SIZE 4096

#define ROC_LOGCELL_UNUSED 0
#define ROC_LOGCELL_READ 1
#define ROC_LOGCELL_WRITE 2

pthread_mutex_t logmutex;
pthread_cond_t logcond;
pthread_t thread_id;

QUEUE logq;
FILE *logfs;

roc_logcell *currcell;
roc_logcell cellmgr[ROC_LOG_CELL_NUM];

static void roc_log_worker(void *arg)
{
	roc_logcell *cell;
	QUEUE *q;

	arg = NULL;

	for (;;)
	{
		pthread_mutex_lock(&logmutex);

		if (QUEUE_EMPTY(&logq))
		{
			pthread_cond_wait(&logcond, &logmutex);
		}

		q = QUEUE_HEAD(&logq);
		QUEUE_REMOVE(q);
		QUEUE_INIT(q);

		pthread_mutex_unlock(&logmutex);

		cell = QUEUE_DATA(q, roc_logcell, queue_node);

		roc_ringbuf *rb = cell->rb;

		uint32_t len = rb->tail - rb->head;
		uint32_t head_n = min(len, rb->size - (rb->head & (rb->size - 1)));
		if (head_n)
		{
			fwrite_unlocked(rb->data + (rb->head & (rb->size - 1)),
							1, head_n, logfs);
		}

		uint32_t tail_n = len - head_n;
		if (tail_n)
		{
			fwrite_unlocked(rb->data, 1, tail_n, logfs);
		}
		rb->head += len;
		__sync_lock_test_and_set(&cell->status, ROC_LOGCELL_UNUSED);
		fflush(logfs);
	}
}
static void roc_term_log(int signal)
{
	ROC_LOG_STDERR("recv signal:%d\n", signal);
	roc_log_flush();
	for (;;)
	{
		pthread_mutex_lock(&logmutex);

		if (QUEUE_EMPTY(&logq))
		{
			pthread_mutex_unlock(&logmutex);
			break;
		}
		pthread_cond_signal(&logcond);
		pthread_mutex_unlock(&logmutex);
		sleep(1);
	}
	exit(0);
}

int roc_log_init(const char *path, int level)
{

	if (path != NULL && strlen(path) != 0)
	{
		logfs = fopen(path, "a+");
		if (!logfs)
		{
			return -1;
		}
	}
	else
	{
		logfs = stdout;
	}
	if (pthread_mutex_init(&logmutex, NULL))
	{
		return -1;
	}
	if (pthread_cond_init(&logcond, NULL))
	{
		return -1;
	}
	QUEUE_INIT(&logq);
	int i;
	for (i = 0; i < ROC_LOG_CELL_NUM; i++)
	{
		cellmgr[i].status = ROC_LOGCELL_UNUSED;
		cellmgr[i].rb = NULL;
	}
	cellmgr[0].status = ROC_LOGCELL_READ;
	cellmgr[0].rb = roc_ringbuf_new(ROC_LOG_CELL_SIZE);
	if (!cellmgr[0].rb)
	{
		return -1;
	}
	currcell = &cellmgr[0];

	if (roc_thread_create(&thread_id, roc_log_worker, NULL))
	{
		return -1;
	}
	if (level == ROC_LOG_LEVEL_STDERR ||
		level == ROC_LOG_LEVEL_EMERG ||
		level == ROC_LOG_LEVEL_ALERT ||
		level == ROC_LOG_LEVEL_CRIT ||
		level == ROC_LOG_LEVEL_ERR ||
		level == ROC_LOG_LEVEL_WARN ||
		level == ROC_LOG_LEVEL_NOTICE ||
		level == ROC_LOG_LEVEL_DEBUG)
	{
		roc_log_level = level;
	}
	else
	{
		ROC_LOG_STDERR("invalid log level:%d\n", level);
		return -1;
	}
	signal(SIGINT, roc_term_log);
	signal(SIGTERM, roc_term_log);
	signal(SIGSEGV, roc_term_log);
	signal(SIGQUIT, roc_term_log);
	signal(SIGABRT, roc_term_log);
	return 0;
}

static inline roc_logcell *roc_logcell_get()
{
	int i;
	for (i = 0; i < ROC_LOG_CELL_NUM; i++)
	{
		if (cellmgr[i].status == ROC_LOGCELL_UNUSED)
		{
			cellmgr[i].status = ROC_LOGCELL_READ;
			if (!cellmgr[i].rb)
			{
				cellmgr[i].rb = roc_ringbuf_new(ROC_LOG_CELL_SIZE);
			}
			if (!cellmgr[i].rb)
			{
				return NULL;
			}
			return &cellmgr[i];
		}
	}
	return NULL;
}

/**
 * 将当前时间转换为标准时间格式,并储存在std_time_str中
 */
static inline void roc_fmt_time(char *std_time_str)
{
	time_t t = time(NULL);
	struct tm *ts = localtime(&t);
	strftime(std_time_str, 22, "[%Y-%m-%d %H:%M:%S]", ts);
}

void roc_log_write(int level, const char *format, ...)
{
	char buf[ROC_PRELOG_SIZE];
	int prefix_len = 0;
	switch (level)
	{
	case ROC_LOG_LEVEL_STDERR:
		prefix_len = strlen(ROC_LOG_LEVEL_STDERR_PREFIX);
		strcpy(buf, ROC_LOG_LEVEL_STDERR_PREFIX);
		break;
	case ROC_LOG_LEVEL_EMERG:
		prefix_len = strlen(ROC_LOG_LEVEL_EMERG_PREFIX);
		strcpy(buf, ROC_LOG_LEVEL_EMERG_PREFIX);
		break;
	case ROC_LOG_LEVEL_ALERT:
		prefix_len = strlen(ROC_LOG_LEVEL_ALERT_PREFIX);
		strcpy(buf, ROC_LOG_LEVEL_ALERT_PREFIX);
		break;
	case ROC_LOG_LEVEL_CRIT:
		prefix_len = strlen(ROC_LOG_LEVEL_CRIT_PREFIX);
		strcpy(buf, ROC_LOG_LEVEL_CRIT_PREFIX);
		break;
	case ROC_LOG_LEVEL_ERR:
		prefix_len = strlen(ROC_LOG_LEVEL_ERR_PREFIX);
		strcpy(buf, ROC_LOG_LEVEL_ERR_PREFIX);
		break;
	case ROC_LOG_LEVEL_WARN:
		prefix_len = strlen(ROC_LOG_LEVEL_WARN_PREFIX);
		strcpy(buf, ROC_LOG_LEVEL_WARN_PREFIX);
		break;
	case ROC_LOG_LEVEL_NOTICE:
		prefix_len = strlen(ROC_LOG_LEVEL_NOTICE_PREFIX);
		strcpy(buf, ROC_LOG_LEVEL_NOTICE_PREFIX);
		break;
	case ROC_LOG_LEVEL_INFO:
		prefix_len = strlen(ROC_LOG_LEVEL_INFO_PREFIX);
		strcpy(buf, ROC_LOG_LEVEL_INFO_PREFIX);
		break;
	case ROC_LOG_LEVEL_DEBUG:
		prefix_len = strlen(ROC_LOG_LEVEL_DEBUG_PREFIX);
		strcpy(buf, ROC_LOG_LEVEL_DEBUG_PREFIX);
		break;
	default:
		prefix_len = strlen(ROC_LOG_LEVEL_STDERR_PREFIX);
		strcpy(buf, ROC_LOG_LEVEL_STDERR_PREFIX);
		break;
	}

	char time_str[22];
	roc_fmt_time(time_str);
	strcpy(buf + prefix_len, time_str);
	prefix_len += strlen(time_str);

	va_list ap;
	va_start(ap, format);
	vsnprintf(buf + prefix_len, ROC_PRELOG_SIZE - prefix_len, format, ap);
	va_end(ap);
	uint32_t len = strlen(buf);
	pthread_mutex_lock(&logmutex);
	roc_ringbuf *rb = currcell->rb;
	roc_logcell *newcell;
	uint32_t writen_n, ret;
	for (writen_n = 0; writen_n != len; writen_n += ret)
	{
		ret = roc_ringbuf_write_rigid(rb, buf + writen_n, len - writen_n);
		if (ret != len - writen_n) //rb is full
		{
			newcell = roc_logcell_get();
			if (!newcell)
			{
				writen_n += ret;
				roc_ringbuf_write(rb, buf + writen_n, len - writen_n);
				break;
			}
			else
			{
				currcell->status = ROC_LOGCELL_WRITE;
				QUEUE_INSERT_TAIL(&logq, &currcell->queue_node);
				currcell = newcell;
				rb = currcell->rb;
			}
		}
	}
	if (!QUEUE_EMPTY(&logq))
	{
		pthread_cond_signal(&logcond);
	}
	pthread_mutex_unlock(&logmutex);
}

void roc_log_flush()
{
	pthread_mutex_lock(&logmutex);
	if (QUEUE_EMPTY(&logq) && currcell->rb->tail - currcell->rb->head != 0)
	{
		roc_logcell *newcell = roc_logcell_get();
		if (newcell)
		{
			currcell->status = ROC_LOGCELL_WRITE;
			QUEUE_INSERT_TAIL(&logq, &currcell->queue_node);
			currcell = newcell;
			pthread_cond_signal(&logcond);
		}
	}
	pthread_mutex_unlock(&logmutex);
}

/*** End of inlined file: roc_log.c ***/


/*** Start of inlined file: roc_threadpool.c ***/
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <limits.h>
#include <errno.h>
#include <sys/resource.h>

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
		ROC_LOG_STDERR("abort at %s (%s:%d)\n", __func__, __FILE__, __LINE__);
		abort();
	}
}

static inline void roc_mutex_lock(pthread_mutex_t *mutex)
{
	if (pthread_mutex_lock(mutex))
	{
		ROC_LOG_STDERR("abort at %s (%s:%d)\n", __func__, __FILE__, __LINE__);
		abort();
	}
}

static inline void roc_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
	if (pthread_cond_wait(cond, mutex))
	{
		ROC_LOG_STDERR("abort at %s (%s:%d)\n", __func__, __FILE__, __LINE__);
		abort();
	}
}

static inline void roc_mutex_unlock(pthread_mutex_t *mutex)
{
	if (pthread_mutex_unlock(mutex))
	{
		ROC_LOG_STDERR("abort at %s (%s:%d)\n", __func__, __FILE__, __LINE__);
		abort();
	}
}

static void roc_cancelled_work(roc_work *w)
{
	ROC_LOG_STDERR("abort at %s (%s:%d)\n", __func__, __FILE__, __LINE__);
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
	{
		ROC_LOG_STDERR("abort at %s (%s:%d)\n", __func__, __FILE__, __LINE__);
		abort();
	}

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
			ROC_LOG_STDERR("abort at %s (%s:%d)\n",
						   __func__, __FILE__, __LINE__);
			abort();
		}

		if (pthread_attr_setstacksize(attr, stack_size))
		{
			ROC_LOG_STDERR("abort at %s (%s:%d)\n",
						   __func__, __FILE__, __LINE__);
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
		ROC_LOG_STDERR("abort at %s (%s:%d)\n", __func__, __FILE__, __LINE__);
		abort();
	}
}

void roc_sem_destroy(sem_t *sem)
{
	if (sem_destroy(sem))
	{
		ROC_LOG_STDERR("abort at %s (%s:%d)\n", __func__, __FILE__, __LINE__);
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
			ROC_LOG_STDERR("abort at %s (%s:%d)\n", __func__, __FILE__, __LINE__);
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
		ROC_LOG_STDERR("abort at %s (%s:%d)\n", __func__, __FILE__, __LINE__);
		abort();
	}

	if (pthread_mutex_init(&tpmutex, NULL))
	{
		ROC_LOG_STDERR("abort at %s (%s:%d)\n", __func__, __FILE__, __LINE__);
		abort();
	}

	QUEUE_INIT(&wq);

	if (sem_init(&sem, 0, 0))
	{
		ROC_LOG_STDERR("abort at %s (%s:%d)\n", __func__, __FILE__, __LINE__);
		abort();
	}

	for (i = 0; i < thread_num; i++)
	{
		if (roc_thread_create(threads + i, roc_worker, &sem))
		{
			ROC_LOG_STDERR("abort at %s (%s:%d)\n",
						   __func__, __FILE__, __LINE__);
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
		ROC_LOG_STDERR("abort at %s (%s:%d)\n", __func__, __FILE__, __LINE__);
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

/*** End of inlined file: roc_threadpool.c ***/


/*** Start of inlined file: roc_net.c ***/
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>

int roc_set_fd_nonblock(int fd, int nonblock)
{
	int flags;

	/* Set the socket blocking (if nonblock is zero) or non-blocking.
	 * Note that fcntl(2) for F_GETFL and F_SETFL can't be
	 * interrupted by a signal. */
	if ((flags = fcntl(fd, F_GETFL)) == -1)
	{
		return -1;
	}

	if (nonblock)
	{
		flags |= O_NONBLOCK;
	}
	else
	{
		flags &= ~O_NONBLOCK;
	}
	if (fcntl(fd, F_SETFL, flags) == -1)
	{
		return -1;
	}
	return 0;
}

/* Set TCP keep alive option to detect dead peers. The interval option
 * is only used for Linux as we are using Linux-specific APIs to set
 * the probe send time, interval, and count. */
int roc_set_tcp_keepalive(int sockfd, int interval)
{
	int val = 1;

	if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) == -1)
	{
		return -1;
	}

#ifdef __linux__
	/* Default settings are more or less garbage, with the keepalive time
	 * set to 7200 by default on Linux. Modify settings to make the feature
	 * actually useful. */

	/* Send first probe after interval. */
	val = interval;
	if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val)) < 0)
	{
		return -1;
	}

	/* Send next probes after the specified interval. Note that we set the
	 * delay as interval / 3, as we send three probes before detecting
	 * an error (see the next setsockopt call). */
	val = interval / 3;
	if (val == 0)
	{
		val = 1;
	}

	if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val)) < 0)
	{
		return -1;
	}

	/* Consider the socket in error state after three we send three ACK
	 * probes without getting a reply. */
	val = 3;
	if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val)) < 0)
	{
		return -1;
	}
#else
	((void)interval); /* Avoid unused var warning for non Linux systems. */
#endif

	return 0;
}

/* roc_net_resolve() resolves the hostname "host" and set the string
 * representation of the IP address into the buffer pointed by "ipbuf".
 *
 * If (flags & 1) the function only resolves hostnames
 * that are actually already IPv4 or IPv6 addresses. This turns the function
 * into a validating / normalizing function. */
int roc_net_resolve(char *host, char *ipbuf, size_t ipbuf_len, int flags)
{
	struct addrinfo hints, *info;
	int rv;

	memset(&hints, 0, sizeof(hints));
	if (flags & 1)
	{
		hints.ai_flags = AI_NUMERICHOST;
	}
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM; /* specify socktype to avoid dups */

	if ((rv = getaddrinfo(host, NULL, &hints, &info)) != 0)
	{
		return -1;
	}
	if (info->ai_family == AF_INET)
	{
		struct sockaddr_in *sa = (struct sockaddr_in *)info->ai_addr;
		inet_ntop(AF_INET, &(sa->sin_addr), ipbuf, ipbuf_len);
	}
	else
	{
		struct sockaddr_in6 *sa = (struct sockaddr_in6 *)info->ai_addr;
		inet_ntop(AF_INET6, &(sa->sin6_addr), ipbuf, ipbuf_len);
	}

	freeaddrinfo(info);
	return 0;
}

static int roc_create_sock(int domain, int type)
{
	if (type != SOCK_STREAM || type != SOCK_DGRAM)
	{
		return -1;
	}
	int sockfd;
	if ((sockfd = socket(domain, type, 0)) == -1)
	{
		return -1;
	}
	return sockfd;
}

/**
 * (flags & (1 << 0)) 创建非阻塞模式socket
 * (flags & (1 << 1)) 尝试绑定到source_addr
 */
int roc_connect(char *addr, int port, char *source_addr, int flags)
{
	int sockfd = -1, rv;
	char portstr[6]; /* strlen("65535") + 1; */
	struct addrinfo hints, *servinfo, *bservinfo, *p, *b;

	snprintf(portstr, sizeof(portstr), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(addr, portstr, &hints, &servinfo)) != 0)
	{
		return -1;
	}
	for (p = servinfo; p != NULL; p = p->ai_next)
	{
		/* Try to create the socket and to connect it.
		 * If we fail in the socket() call, or on connect(), we retry with
		 * the next entry in servinfo. */
		sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sockfd == -1)
		{
			continue;
		}

		if (roc_set_sock_reuseaddr(sockfd) == -1)
		{
			goto error;
		}
		if (flags & (1 << 0) && roc_set_fd_nonblock(sockfd, 1) != 0)
		{
			goto error;
		}
		if (source_addr)
		{
			int bound = 0;
			/* Using getaddrinfo saves us from self-determining IPv4 vs IPv6 */
			if ((rv = getaddrinfo(source_addr, NULL, &hints, &bservinfo)) != 0)
			{
				goto error;
			}
			for (b = bservinfo; b != NULL; b = b->ai_next)
			{
				if (bind(sockfd, b->ai_addr, b->ai_addrlen) != -1)
				{
					bound = 1;
					break;
				}
			}
			freeaddrinfo(bservinfo);
			if (!bound)
			{
				goto error;
			}
		}
		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
		{
			/* If the socket is non-blocking, it is ok for connect() to
			 * return an EINPROGRESS error here. */
			if (errno == EINPROGRESS && flags & (1 << 0))
			{
				goto end;
			}
			close(sockfd);
			sockfd = -1;
			continue;
		}

		/* If we ended an iteration of the for loop without errors, we
		 * have a connected socket. Let's return to the caller. */
		goto end;
	}

error:
	if (sockfd != -1)
	{
		close(sockfd);
		sockfd = -1;
	}

end:
	freeaddrinfo(servinfo);

	/* Handle best effort binding: if a binding address was used, but it is
	 * not possible to create a socket, try again without a binding address. */
	if (sockfd == -1 && source_addr && (flags & (1 << 1)))
	{
		return roc_connect(addr, port, NULL, flags);
	}
	else
	{
		return sockfd;
	}
}

/**
 * (flags & (1 << 0)) 创建非阻塞模式socket
 * (flags & (1 << 1)) 尝试绑定到source_addr
 */
int roc_local_connect(char *path, int flags)
{
	int sockfd;
	struct sockaddr_un sa;

	if ((sockfd = roc_create_sock(AF_LOCAL, SOCK_STREAM)) == -1)
	{
		return -1;
	}
	if (roc_set_sock_reuseaddr(sockfd) == -1)
	{
		return -1;
	}

	sa.sun_family = AF_LOCAL;
	strncpy(sa.sun_path, path, sizeof(sa.sun_path) - 1);
	if (flags & (1 << 0))
	{
		if (roc_set_fd_nonblock(sockfd, 1) != 0)
		{
			close(sockfd);
			return -1;
		}
	}
	if (connect(sockfd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
	{
		if (errno == EINPROGRESS && flags & (1 << 0))
			return sockfd;

		close(sockfd);
		return -1;
	}
	return sockfd;
}

static int roc_listen(int sockfd, struct sockaddr *sa,
					  socklen_t len, int backlog)
{
	if (bind(sockfd, sa, len) == -1)
	{
		close(sockfd);
		return -1;
	}

	if (listen(sockfd, backlog) == -1)
	{
		close(sockfd);
		return -1;
	}
	return 0;
}

static int roc_set_sock_ipv6only(int sockfd)
{
	int yes = 1;
	if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes)) == -1)
	{
		close(sockfd);
		return -1;
	}
	return 0;
}

int roc_tcp_svr(int port, char *bindaddr, int domain, int backlog)
{
	int sockfd = -1, rv;
	char _port[6]; /* strlen("65535") */
	struct addrinfo hints, *servinfo, *p;

	snprintf(_port, 6, "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = domain;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; /* No effect if bindaddr != NULL */

	if ((rv = getaddrinfo(bindaddr, _port, &hints, &servinfo)) != 0)
	{
		return -1;
	}
	for (p = servinfo; p != NULL; p = p->ai_next)
	{
		sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sockfd == -1)
		{
			continue;
		}
		if (domain == AF_INET6 && roc_set_sock_ipv6only(sockfd) == -1)
		{
			goto error;
		}

		if (roc_set_sock_reuseaddr(sockfd) == -1)
		{
			goto error;
		}
		if (roc_listen(sockfd, p->ai_addr, p->ai_addrlen, backlog) == -1)
		{
			sockfd = -1;
		}

		goto end;
	}
	if (p == NULL)
	{
		goto error;
	}

error:
	if (sockfd != -1)
	{
		close(sockfd);
	}
	sockfd = -1;
end:
	freeaddrinfo(servinfo);
	return sockfd;
}

/**
 * AF_LOCAL || AF_UNIX
 */
int roc_local_tcp_svr(char *path, mode_t perm, int backlog)
{
	int sockfd;
	struct sockaddr_un sa;

	if ((sockfd = roc_create_sock(AF_LOCAL, SOCK_STREAM)) == -1)
	{
		return -1;
	}
	if (roc_set_sock_reuseaddr(sockfd) == -1)
	{
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_LOCAL;
	strncpy(sa.sun_path, path, sizeof(sa.sun_path) - 1);
	if (roc_listen(sockfd, (struct sockaddr *)&sa, sizeof(sa), backlog) == -1)
	{
		return -1;
	}
	if (perm)
	{
		chmod(sa.sun_path, perm);
	}
	return sockfd;
}

static int _roc_accept(int sockfd, struct sockaddr *sa, socklen_t *len)
{
	int fd;
	while (1)
	{
		fd = accept(sockfd, sa, len);
		if (fd == -1)
		{
			if (errno == EINTR)
				continue;
			else
			{
				return -1;
			}
		}
		break;
	}
	return fd;
}

int roc_accept(int sockfd, char *ip, size_t ip_len, int *port)
{
	int fd;
	struct sockaddr_storage sa;
	socklen_t salen = sizeof(sa);
	if ((fd = _roc_accept(sockfd, (struct sockaddr *)&sa, &salen)) == -1)
	{
		return -1;
	}

	if (sa.ss_family == AF_INET)
	{
		struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
		if (ip)
		{
			inet_ntop(AF_INET, (void *)&(sin->sin_addr), ip, ip_len);
		}
		if (port)
		{
			*port = ntohs(sin->sin_port);
		}
	}
	else
	{
		struct sockaddr_in6 *sin = (struct sockaddr_in6 *)&sa;
		if (ip)
		{
			inet_ntop(AF_INET6, (void *)&(sin->sin6_addr), ip, ip_len);
		}
		if (port)
		{
			*port = ntohs(sin->sin6_port);
		}
	}
	return fd;
}

/**
 * AF_UNIX || AF_LOCAL
 */
int roc_local_accpet(int sockfd)
{
	int fd;
	struct sockaddr_un sa;
	socklen_t salen = sizeof(sa);
	if ((fd = _roc_accept(sockfd, (struct sockaddr *)&sa, &salen)) == -1)
		return -1;

	return fd;
}

int roc_get_peer_ip_port(int fd, char *ip, size_t ip_len, int *port)
{
	struct sockaddr_storage sa;
	socklen_t salen = sizeof(sa);

	if (getpeername(fd, (struct sockaddr *)&sa, &salen) == -1)
	{
		goto error;
	}
	if (ip_len == 0)
	{
		goto error;
	}

	if (sa.ss_family == AF_INET)
	{
		struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
		if (ip)
		{
			inet_ntop(AF_INET, (void *)&(sin->sin_addr), ip, ip_len);
		}
		if (port)
		{
			*port = ntohs(sin->sin_port);
		}
	}
	else if (sa.ss_family == AF_INET6)
	{
		struct sockaddr_in6 *sin = (struct sockaddr_in6 *)&sa;
		if (ip)
		{
			inet_ntop(AF_INET6, (void *)&(sin->sin6_addr), ip, ip_len);
		}
		if (port)
		{
			*port = ntohs(sin->sin6_port);
		}
	}
	else if (sa.ss_family == AF_LOCAL)
	{
		if (ip)
		{
			strncpy(ip, "/localsocket", ip_len);
		}
		if (port)
		{
			*port = 0;
		}
	}
	else
	{
		goto error;
	}
	return 0;

error:
	if (ip)
	{
		if (ip_len >= 2)
		{
			ip[0] = '?';
			ip[1] = '\0';
		}
		else if (ip_len == 1)
		{
			ip[0] = '\0';
		}
	}
	if (port)
	{
		*port = 0;
	}
	return -1;
}

/* Format an IP,port pair into something easy to parse. If IP is IPv6
 * (matches for ":"), the ip is surrounded by []. IP and port are just
 * separated by colons.  */
int roc_fmt_addr(char *buf, size_t buf_len, char *ip, int port)
{
	return snprintf(buf, buf_len,
					strchr(ip, ':') ? "[%s]:%d" : "%s:%d", ip, port);
}

/* Like roc_fmt_addr() but extract ip and port from the socket's peer. */
int roc_fmt_peer(int sockfd, char *buf, size_t buf_len)
{
	char ip[INET6_ADDRSTRLEN];
	int port;

	roc_get_peer_ip_port(sockfd, ip, sizeof(ip), &port);
	return roc_fmt_addr(buf, buf_len, ip, port);
}

/**
 * 在一个没有调用bind的TCP客户上,connect成功返回后
 * roc_getsockname用于返回由内核赋予该连接的本地IP地址和本地端口号。
 */
int roc_getsockname(int fd, char *ip, size_t ip_len, int *port)
{
	struct sockaddr_storage sa;
	socklen_t salen = sizeof(sa);

	if (getsockname(fd, (struct sockaddr *)&sa, &salen) == -1)
	{
		if (port)
		{
			*port = 0;
		}
		ip[0] = '?';
		ip[1] = '\0';
		return -1;
	}
	if (sa.ss_family == AF_INET)
	{
		struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
		if (ip)
		{
			inet_ntop(AF_INET, (void *)&(sin->sin_addr), ip, ip_len);
		}
		if (port)
		{
			*port = ntohs(sin->sin_port);
		}
	}
	else
	{
		struct sockaddr_in6 *sin = (struct sockaddr_in6 *)&sa;
		if (ip)
		{
			inet_ntop(AF_INET6, (void *)&(sin->sin6_addr), ip, ip_len);
		}
		if (port)
		{
			*port = ntohs(sin->sin6_port);
		}
	}
	return 0;
}

int roc_fmt_sock(int fd, char *fmt, size_t fmt_len)
{
	char ip[INET6_ADDRSTRLEN];
	int port;

	roc_getsockname(fd, ip, sizeof(ip), &port);
	return roc_fmt_addr(fmt, fmt_len, ip, port);
}

/**
 * 自动recv来自sockfd的数据
 * nonblock为0时,按阻塞模式recv,其余情况按非阻塞模式收取
 * 正常情况返回接受的字节数,返回-1代表错误或sockfd已被对端关闭
 */
int roc_recv(int sockfd, void *buf, int len, int nonblock)
{
	int recvd_bytes, ret_len;

	for (recvd_bytes = 0; recvd_bytes < len; recvd_bytes += ret_len)
	{
		ret_len = recv(sockfd, buf + recvd_bytes, len - recvd_bytes, 0);

		if (ret_len == 0) /*connection closed by peer*/
		{
			return -1; /*将返回值改为-1,使外层在阻塞或非阻塞模式可以一样处理*/
		}
		if (ret_len == -1)
		{
			if (errno == EINTR)
			{
				ret_len = 0;
				continue;
			}
			else if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				return recvd_bytes;
			}
			else
			{
				return -1;
			}
		}
		if (nonblock == 0)
		{
			return ret_len;
		}
	}

	return recvd_bytes;
}

int roc_send(int sockfd, const void *buf, int len, int nonblock)
{
	int sent_bytes, ret_len;

	for (sent_bytes = 0; sent_bytes < len; sent_bytes += ret_len)
	{
		ret_len = send(sockfd, buf + sent_bytes, len - sent_bytes, 0);
		if (ret_len == -1)
		{
			if (errno == EINTR)
			{
				ret_len = 0;
				continue;
			}
			else if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				return sent_bytes;
			}
			else
			{
				return -1;
			}
		}
		if (nonblock == 0)
		{
			return ret_len;
		}
	}

	return sent_bytes;
}
/*** End of inlined file: roc_net.c ***/


/*** Start of inlined file: roc_evt.c ***/
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/types.h>

static int roc_iom_create(roc_evt_loop *evt_loop)
{
	evt_loop->ret_evts = malloc(evt_loop->size * sizeof(struct epoll_event));
	if (!evt_loop->ret_evts)
	{
		free(evt_loop->ret_evts);
		return -1;
	}

	/* 1024 is just a hint for the kernel */
	evt_loop->epfd = epoll_create(1024);
	if (evt_loop->epfd == -1)
	{
		free(evt_loop->ret_evts);
		return -1;
	}
	return 0;
}

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

static int roc_iom_add_evt(roc_evt_loop *evt_loop, int fd, int mask)
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

int roc_add_io_evt(roc_evt_loop *evt_loop, int fd, int mask,
				   roc_io_proc proc, void *custom_data)
{
	if (fd >= evt_loop->size)
	{
		errno = ERANGE;
		return -1;
	}
	roc_io_evt *io_evt = &evt_loop->all_io_evts[fd];

	if (mask & ROC_EVENT_INPUT)
	{
		io_evt->iporc = proc;
	}
	if (mask & ROC_EVENT_OUTPUT)
	{
		io_evt->oproc = proc;
	}
	io_evt->custom_data = custom_data;

	if (roc_iom_add_evt(evt_loop, fd, mask) == -1)
	{
		io_evt->mask = ROC_EVENT_NONE;
		return -1;
	}
	if (fd > evt_loop->maxfd)
	{
		__sync_lock_test_and_set(&evt_loop->maxfd, fd);
	}
	io_evt->mask |= mask;
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
		__sync_lock_test_and_set(&evt_loop->maxfd, i);
	}
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
			(te->when_sec == nearest->when_sec &&
			 te->when_ms < nearest->when_ms))
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
		int64_t now_sec, now_ms;
		int64_t id;

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

static int roc_iom_poll(roc_evt_loop *evt_loop, struct timeval *tvp)
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
			int64_t now_sec, now_ms;

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
			int fd = evt_loop->ready_evts[i].fd;
			roc_io_evt *ioe = &evt_loop->all_io_evts[fd];
			int mask = evt_loop->ready_evts[i].mask;

			int fired = 0; /* Number of events fired for current fd. */

			/* Normally we execute the readable event first, and the writable
			 * event laster. This is useful as sometimes we may be able
			 * to serve the reply of a query immediately after processing the
			 * query.
			 *
			 * However if ROC_EVENT_BARRIER is set in the mask, our application
			 * is asking us to do the reverse: never fire the writable event
			 * after the readable. In such a case, we invert the calls.
			 * This is useful when, for instance, we want to do things
			 * in the beforeSleep() hook, like fsynching a file to disk,
			 * before replying to a client. */
			int invert = ioe->mask & ROC_EVENT_BARRIER;

			/* Note the "ioe->mask & mask & ..." code: maybe an already
			 * processed event removed an element that fired and we still
			 * didn't processed, so we check if the event is still valid.
			 *
			 * Fire the readable event if the call sequence is not
			 * inverted. */
			if (!invert && ioe->mask & mask & ROC_EVENT_INPUT)
			{
				ioe->iporc(evt_loop, fd, ioe->custom_data, mask);
				fired++;
			}

			/* Fire the writable event. */
			if (ioe->mask & mask & ROC_EVENT_OUTPUT)
			{
				if (!fired || ioe->oproc != ioe->iporc)
				{
					ioe->oproc(evt_loop, fd, ioe->custom_data, mask);
					fired++;
				}
			}

			/* If we have to invert the call, fire the readable event now
			 * after the writable one. */
			if (invert && ioe->mask & mask & ROC_EVENT_INPUT)
			{
				if (!fired || ioe->oproc != ioe->iporc)
				{
					ioe->iporc(evt_loop, fd, ioe->custom_data, mask);
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

void roc_evt_loop_start(roc_evt_loop *evt_loop)
{
	evt_loop->stop = 0;
	while (!evt_loop->stop)
	{
		roc_process_evts(evt_loop, ROC_ALL_EVENTS);
	}
}
/*** End of inlined file: roc_evt.c ***/


/*** Start of inlined file: roc_plugin.c ***/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#define PLUGIN_LOAD_NOERR(h, v, name) \
	do                                \
	{                                 \
		v = dlsym(h, name);           \
		dlerror();                    \
	} while (0)

#define PLUGIN_LOAD(h, v, name)                      \
	do                                               \
	{                                                \
		v = dlsym(h, name);                          \
		if ((error = dlerror()) != NULL)             \
		{                                            \
			ROC_LOG_STDERR("dlsym error:%s", error); \
			dlclose(h);                              \
			h = NULL;                                \
			goto err;                                \
		}                                            \
	} while (0)

int register_plugin(roc_plugin *plugin_so, const char *so_path, int flag)
{
	char *error;
	int ret = -1;

	plugin_so->so_handle = dlopen(so_path, RTLD_NOW);
	if ((error = dlerror()) != NULL)
	{
		ROC_LOG_STDERR("dlopen error, %s\n", error);
		goto err;
	}

	/* link handler */
	PLUGIN_LOAD_NOERR(plugin_so->so_handle,
					  plugin_so->close_handler, "close_handler");
	PLUGIN_LOAD(plugin_so->so_handle,
				plugin_so->connect_handler, "connect_handler");
	PLUGIN_LOAD(plugin_so->so_handle,
				plugin_so->recv_handler, "recv_handler");

	/* svr handler */
	PLUGIN_LOAD(plugin_so->so_handle,
				plugin_so->init_handler, "init_handler");
	PLUGIN_LOAD(plugin_so->so_handle,
				plugin_so->fini_handler, "fini_handler");
	ret = 0;

err:
	if (!flag)
	{
		ROC_LOG_STDERR("dlopen %s\n", so_path);
	}
	else
	{
		ROC_LOG_STDERR("RELOAD %s\t[%s]\n", so_path,
					   (ret ? "FAIL" : "OK"));
	}
	return ret;
}

void unregister_plugin(roc_plugin *plugin_so)
{
	if (plugin_so->so_handle != NULL)
	{
		dlclose(plugin_so->so_handle);
		plugin_so->so_handle = NULL;
	}
}

int register_data_plugin(roc_plugin *plugin_so, const char *so_path)
{
	char *error;
	int ret = 0;
	if (so_path == NULL)
	{
		return 0;
	}

	plugin_so->data_so_handle = dlopen(so_path, RTLD_NOW | RTLD_GLOBAL);
	if ((error = dlerror()) != NULL)
	{
		ROC_LOG_STDERR("dlopen error:%s\n", error);
		ret = 0;
	}
	ROC_LOG_STDERR("dlopen:%s\n", so_path);
	return ret;
}

void unregister_data_plugin(roc_plugin *plugin_so)
{
	if (plugin_so->data_so_handle != NULL)
	{
		dlclose(plugin_so->data_so_handle);
		plugin_so->data_so_handle = NULL;
	}
}

/*** End of inlined file: roc_plugin.c ***/


/*** Start of inlined file: roc_svr.c ***/
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <sys/socket.h>


/*** Start of inlined file: roc_daemon.h ***/
#ifndef ROC_DAEMON_H
#define ROC_DAEMON_H

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

static int roc_daemon_start()
{
	int fd;

	switch (fork())
	{
	case -1:
		return -1;

	case 0:
		break;

	default:
		exit(0);
	}
	int pid = getpid();
	printf("daemon started, pid:%d\n", pid);

	if (setsid() == -1)
	{
		return -1;
	}

	umask(0);

	fd = open("/dev/null", O_RDWR);
	if (fd == -1)
	{
		return -1;
	}

	if (dup2(fd, STDIN_FILENO) == -1)
	{
		return -1;
	}

	if (dup2(fd, STDOUT_FILENO) == -1)
	{
		return -1;
	}

	if (dup2(fd, STDERR_FILENO) == -1)
	{
		return -1;
	}

	if (fd > STDERR_FILENO)
	{
		if (close(fd) == -1)
		{
			return -1;
		}
	}

	return 0;
}

#endif /* ROC_DAEMON_H */

/*** End of inlined file: roc_daemon.h ***/

#define MAX_LINK_PER_SVR 65535
#define ROC_THREAD_MAX_NUM 1024

int flush_log_interval = 3000;
int svr_thread_num = 4; /* default 4 threads */

roc_work work_arr[ROC_THREAD_MAX_NUM];
roc_evt_loop *default_loop;

uint32_t curr_loop_offset = 0;

static void roc_work_func(roc_work *w)
{
	roc_evt_loop *thread_loop = (roc_evt_loop *)(w->data);
	roc_evt_loop_start(thread_loop);
}

static int roc_flush_log_func(roc_evt_loop *evt_loop,
							  int64_t id, void *intptr_interval)
{

	roc_log_flush();
	return *((int *)intptr_interval);
}

int roc_init(const char *log_path, int log_level)
{
	//roc_daemon_start(); /* 测试时暂时屏蔽,正式环境建议开启 */
	if (roc_log_init(log_path, log_level) == -1)
	{
		return -1;
	}
	ROC_LOG_STDERR("log inited\n");
	default_loop = roc_create_evt_loop(MAX_LINK_PER_SVR);

	if (!default_loop)
	{
		return -1;
	}
	if (roc_add_time_evt(default_loop, flush_log_interval,
						 roc_flush_log_func, &flush_log_interval) == -1)
	{
		return -1;
	}

	char *val = getenv("ROC_THREADPOOL_SIZE");
	if (val != NULL)
	{
		svr_thread_num = atoi(val);
	}
	int i;
	for (i = 0; i < svr_thread_num; i++)
	{
		roc_evt_loop *thread_loop = roc_create_evt_loop(MAX_LINK_PER_SVR);
		roc_work w;
		work_arr[i] = w;
		roc_tpwork_submit(&work_arr[i], roc_work_func, thread_loop);
	}
	signal(SIGPIPE, SIG_IGN);
	ROC_LOG_STDERR("roc inited\n");
	return 0;
}

int roc_run()
{
	roc_evt_loop_start(default_loop);
	return 0;
}

static inline void roc_link_del(roc_link *link, void *custom_data)
{
	roc_del_io_evt(link->evt_loop, link->fd, ROC_EVENT_IOET);
	if (link->handler[ROC_SOCK_CLOSE])
	{
		link->handler[ROC_SOCK_CLOSE](link, NULL);
	}
	close(link->fd);
	roc_ringbuf_del(link->ibuf);
	roc_ringbuf_del(link->obuf);
	free(link->ip);
	free(link);
}

roc_svr *roc_svr_new(int port)
{
	roc_svr *svr = (roc_svr *)malloc(sizeof(roc_svr));
	if (!svr)
	{
		return NULL;
	}
	if (!default_loop)
	{
		free(svr);
		return NULL;
	}
	svr->port = port;
	svr->domain = AF_INET;
	svr->type = SOCK_STREAM;
	svr->backlog = 65535;
	svr->maxlink = 65535;
	svr->nonblock = 1;
	svr->next_plugin_level = 0;
	svr->evt_loop = default_loop;
	int i;
	for (i = 0; i < ROC_PLUGIN_MAX; i++)
	{
		svr->plugin[i].level = -1;
	}
	for (i = 0; i < ROC_SOCK_EVTEND; i++)
	{
		svr->handler[i] = NULL;
	}
	svr->close_link = roc_link_del;
	svr->send = roc_smart_send;
	svr->log = roc_log_write;

	return svr;
}

void roc_svr_on(roc_svr *svr, int evt_type, roc_handle_func_link *handler)
{
	if (evt_type < ROC_SOCK_EVTEND)
	{
		svr->handler[evt_type] = handler;
	}
}
int roc_svr_use(roc_svr *svr, char *plugin_path)
{
	int i;
	for (i = 0; i < ROC_PLUGIN_MAX; i++)
	{
		if (svr->plugin[i].level != -1)
		{
			continue;
		}
		svr->plugin[i].level = i;
		if (register_plugin(&svr->plugin[i], plugin_path, 0) == -1)
		{
			free(svr);
			return -1;
		}
		return 0;
	}
	return -1;
}

static roc_link *roc_link_new(int fd, char *ip, int port, roc_svr *svr)
{
	roc_link *link = (roc_link *)malloc(sizeof(roc_link));
	if (!link)
	{
		return NULL;
	}
	link->ip = malloc(16);
	if (!link->ip)
	{
		free(link);
		return NULL;
	}
	memcpy(link->ip, ip, 16);
	link->ibuf = roc_ringbuf_new(1024);
	if (!link->ibuf)
	{
		free(link->ip);
		free(link);
		return NULL;
	}
	link->obuf = roc_ringbuf_new(1024);
	if (!link->obuf)
	{
		free(link->ip);
		roc_ringbuf_del(link->ibuf);
		free(link);
		return NULL;
	}
	int i;
	for (i = 0; i < ROC_SOCK_EVTEND; i++)
	{
		link->handler[i] = NULL;
	}
	link->port = port;
	link->fd = fd;
	link->svr = svr;
	link->next_plugin_level = 0;
	return link;
}

void roc_link_on(roc_link *link, int evt_type, roc_handle_func_link *handler)
{
	if (evt_type < ROC_SOCK_EVTEND)
	{
		(void)__sync_lock_test_and_set(&link->handler[evt_type], handler);
	}
}

static int roc_smart_recv(roc_link *link)
{
	roc_ringbuf *rb = link->ibuf;

	uint32_t len = roc_ringbuf_unused(rb);
	if (len == 0)
	{
		roc_ringbuf_resize(rb, rb->size + 1);
		return roc_smart_recv(link);
	}
	uint32_t tail_capacity = min(len, rb->size - (rb->tail & (rb->size - 1)));

	int ret;
	if (tail_capacity)
	{
		ret = roc_recv(link->fd,
					   rb->data + (rb->tail & (rb->size - 1)),
					   tail_capacity, 1);
		if (ret == -1) /* link closed by client or error occur */
		{
			roc_link_del(link, NULL);
			return -1;
		}
		if (ret == 0)
		{
			return 0;
		}
		rb->tail += ret;
		if (ret != tail_capacity)
		{
			return 0;
		}
	}

	uint32_t head_capacity = len - tail_capacity;
	if (head_capacity)
	{
		ret = roc_recv(link->fd, rb->data, head_capacity, 1);
		if (ret == -1) /* link closed by client or error occur */
		{
			roc_link_del(link, NULL);
			return -1;
		}
		if (ret == 0)
		{
			return 0;
		}
		rb->tail += ret;
	}

	if (roc_ringbuf_unused(rb) == 0)
	{
		roc_ringbuf_resize(rb, rb->size + 1);
		return roc_smart_recv(link);
	}
	return 0;
}
static void roc_pretreat_data(roc_evt_loop *el, int fd,
							  void *custom_data, int mask)
{
	roc_link *link = (roc_link *)custom_data;

	if (mask & ROC_EVENT_INPUT)
	{
		if (roc_smart_recv(link) == -1)
		{
			return;
		}
		if (link->handler[ROC_SOCK_DATA])
		{
			link->handler[ROC_SOCK_DATA](link, NULL);
		}
	}
	if (mask & ROC_EVENT_OUTPUT)
	{
		if (!roc_ringbuf_readable(link->obuf))
		{
			return;
		}
		if (roc_smart_send(link, NULL, 0) == -1)
		{
			return;
		}
	}
}

static int roc_dispatch_ioevt(roc_link *link, int mask)
{
	uint32_t next_loopid = curr_loop_offset % svr_thread_num;
	roc_evt_loop *el = (roc_evt_loop *)(work_arr[next_loopid].data);
	if (roc_add_io_evt(el, link->fd, mask, roc_pretreat_data, link) == -1)
	{
		roc_link_del(link, NULL);
		return -1;
	}
	link->evt_loop = el;
	curr_loop_offset++;
	return 0;
}

static void roc_auto_accept(roc_evt_loop *el, int fd,
							void *custom_data, int mask)
{
	int cport;
	char ip_addr[16] = {0};
	int cfd = roc_accept(fd, ip_addr, sizeof(ip_addr), &cport);
	if (cfd <= 0)
	{
		return;
	}
	if (roc_set_fd_nonblock(cfd, 1) == -1)
	{
		close(cfd);
		return;
	}

	roc_svr *svr = (roc_svr *)custom_data;
	if (!svr)
	{
		close(cfd);
		return;
	}

	if (svr->handler[ROC_SOCK_CONNECT])
	{
		roc_link *link = roc_link_new(cfd, ip_addr, cport, svr);
		if (!link)
		{
			close(cfd);
			return;
		}
		svr->handler[ROC_SOCK_CONNECT](link, NULL);
		roc_dispatch_ioevt(link, ROC_EVENT_IOET);
	}
}
int roc_smart_send(roc_link *link, void *buf, int len)
{
	roc_ringbuf *rb = link->obuf;
	if (buf && len)
	{
		roc_ringbuf_write(rb, buf, len);
	}

	uint32_t rblen = rb->tail - rb->head;
	uint32_t head_n = min(rblen, rb->size - (rb->head & (rb->size - 1)));

	int ret;
	if (head_n)
	{
		ret = roc_send(link->fd,
					   rb->data + (rb->head & (rb->size - 1)),
					   head_n, 1);
		if (ret == -1)
		{
			roc_link_del(link, NULL);
			return -1;
		}
		if (ret == 0)
		{
			return 0;
		}
		rb->head += ret;

		if (ret != head_n)
		{
			return roc_smart_send(link, NULL, 0);
		}
	}

	uint32_t tail_n = rblen - head_n;
	if (tail_n)
	{
		ret = roc_send(link->fd, rb->data, tail_n, 1);
		if (ret == -1)
		{
			roc_link_del(link, NULL);
			return -1;
		}
		if (ret == 0)
		{
			return 0;
		}
		rb->head += ret;
		if (ret != tail_n)
		{
			return roc_smart_send(link, NULL, 0);
		}
	}

	return 0;
}

int roc_svr_start(roc_svr *svr)
{
	svr->fd = roc_tcp_svr(svr->port, NULL, svr->domain, svr->backlog);
	if (svr->fd == -1)
	{
		free(svr);
		return -1;
	}
	if (svr->nonblock && roc_set_fd_nonblock(svr->fd, 1) == -1)
	{
		free(svr);
		return -1;
	}
	if (roc_add_io_evt(svr->evt_loop, svr->fd, ROC_EVENT_INPUT,
					   roc_auto_accept, svr) == -1)
	{
		free(svr);
		return -1;
	}
	if (svr->plugin[0].level != -1)
	{
		svr->plugin[0].init_handler(svr, NULL);
	}
	return 0;
}
int roc_svr_stop(roc_svr *svr)
{
	roc_del_io_evt(svr->evt_loop, svr->fd, ROC_EVENT_INPUT);
	if (svr->plugin[0].level != -1)
	{
		svr->plugin[0].fini_handler(svr, NULL);
	}
	close(svr->fd);
	free(svr);
	return 0;
}

/*** End of inlined file: roc_svr.c ***/

