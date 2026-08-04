#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdatomic.h>
#include <limits.h>
#include <string.h>
#ifndef WIN32
#include <sys/queue.h>
#endif

#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <pthread.h>

#include <event2/event.h>
#include <event2/thread.h>

#include "evhtp/config.h"
#include "internal.h"
#include "evhtp/mpsc-queue.h"
#include "evhtp/spsc_queue.h"
#include "evhtp/thread.h"

#ifndef CACHE_LINE_SIZE
#define CACHE_LINE_SIZE 64
#endif

//#define WITH_COUNTERS
#ifdef WITH_COUNTERS
#define IF_COUNTERS(x, ...) x##__VA_ARGS__
#else
#define IF_COUNTERS(x, ...)
#endif

//#define WITH_SEND_MSG
#ifdef WITH_SEND_MSG
#define IF_SEND_MSG(x, ...) x##__VA_ARGS__
#else
#define IF_SEND_MSG(x, ...)
#endif

static __thread evthr_t * tls_thread;

typedef struct evthr_cmd        evthr_cmd_t;
typedef struct evthr_pool_slist evthr_pool_slist_t;

struct evthr_cmd {
    struct mpsc_queue_node node;
    struct producer_q    * msg_cache_p;
    void                 * args;
    evthr_cb               cb;
};

struct evthr_pool {
    evthr_t       ** threads;
    size_t           nthreads;
    _Atomic uint32_t next_choice;
    alignas(CACHE_LINE_SIZE) char padding[CACHE_LINE_SIZE];
};

struct evthr {
    struct mpsc_queue queue;

    struct producer_q msg_cache_p;
    struct consumer_q msg_cache_c;
    void            * msg_cache_buf;

    ev_t          * msg_event;
    ev_t          * stop_event;
    evbase_t      * evbase;
    pthread_mutex_t lock;
IF_SEND_MSG(pthread_cond_t  cond;)
    pthread_t     * thr;
    evthr_init_cb   init_cb;
    evthr_exit_cb   exit_cb;
    void          * arg;
    void          * aux;

    int             msg_fd;  // msg available wakeup fd.
    int             stop_fd; // stop wakeup fd.

#ifdef WITH_COUNTERS
    int             alloc_count;
    int             free_count;
    int             msg_count;
    int             reuse_count;
#endif

    _Atomic size_t tail; // Enqueued count (read-only for producers)
    /* NOTE: currently head isn't used; could be used for debug or stats. */
    _Atomic size_t head; // Dequeued count (consumer updates)
    alignas(CACHE_LINE_SIZE) char padding[CACHE_LINE_SIZE];
};

static void
_evthr_run_callbacks(void *args)
{
    evthr_t *thread;
    struct mpsc_queue_node *node;

    thread = (evthr_t *)args;
    if (thread == NULL) {
        return;
    }

    while (mpsc_queue_poll(&thread->queue, &node) == MPSC_QUEUE_ITEM)
    {
        evthr_cmd_t *cmd = (evthr_cmd_t *)node;
        struct producer_q* pq = cmd->msg_cache_p;
        cmd->cb(thread, cmd->args, thread->arg);
        atomic_fetch_add_explicit(&thread->head, 1, memory_order_relaxed);
        if (!pq)
        {
            free(cmd);
        }
        else if (spsc_enqueue(pq, cmd) != 0)
        {
            IF_COUNTERS(++thread->free_count;)
            free(cmd);
        }
        IF_COUNTERS(++thread->msg_count;)
    }
}

static void
_evthr_read_cmd(evutil_socket_t sock, short which, void *args)
{
    evthr_t *thread;
    eventfd_t value;

    (void)which;

    thread = (evthr_t *)args;
    if (thread == NULL) {
        return;
    }

    if (read(sock, &value, sizeof(value)) != sizeof(value))
    {
        return;
    }

    if (sock == thread->msg_fd)
    {
        _evthr_run_callbacks(args);
    }
    else if (sock == thread->stop_fd)
    {
        event_base_loopbreak(thread->evbase);
    }

} /* _evthr_read_cmd */

static void *
_evthr_loop(void * args)
{
    evthr_t * thread = args;

    if (thread == NULL || thread->thr == NULL) {
        pthread_exit(NULL);
    }

    tls_thread = thread;

    thread->evbase = event_base_new();
    thread->msg_event = event_new(thread->evbase, thread->msg_fd,
                               EV_READ | EV_PERSIST, _evthr_read_cmd, args);
    thread->stop_event = event_new(thread->evbase, thread->stop_fd,
                               EV_READ | EV_PERSIST, _evthr_read_cmd, args);

    event_add(thread->msg_event, NULL);
    event_add(thread->stop_event, NULL);

    pthread_mutex_lock(&thread->lock);
    if (thread->init_cb != NULL) {
        (thread->init_cb)(thread, thread->arg);
    }

    pthread_mutex_unlock(&thread->lock);

    event_base_loop(thread->evbase, 0);

    pthread_mutex_lock(&thread->lock);
    if (thread->exit_cb != NULL) {
        (thread->exit_cb)(thread, thread->arg);
    }

    pthread_mutex_unlock(&thread->lock);

    tls_thread = NULL;

    pthread_exit(NULL);
} /* _evthr_loop */

evthr_res
evthr_defer(evthr_t * thread, evthr_cb cb, void * arg)
{
    evthr_t     * sender = tls_thread;
    evthr_cmd_t * cmd;
    eventfd_t     value = 1;
    ssize_t       nbytes;

    if (thread == NULL) {
        return EVTHR_RES_FATAL;
    }

    if (cb == NULL) {
        return EVTHR_RES_NOCB;
    }

    cmd = sender ? spsc_dequeue(&sender->msg_cache_c) : NULL;
    if (cmd) {
        IF_COUNTERS(++sender->reuse_count;)
    }
    else {
        IF_COUNTERS(if (sender) ++sender->alloc_count;)
        if (!(cmd = calloc(sizeof(evthr_cmd_t), 1))) {
            return EVTHR_RES_FATAL;
        }
    }

    cmd->msg_cache_p = sender ? &sender->msg_cache_p : NULL;
    cmd->cb = cb;
    cmd->args = arg;

    /* Wake up the target thread. */
    mpsc_queue_insert(&thread->queue, (void*)cmd);

    nbytes = write(thread->msg_fd, &value, sizeof(value));
    if (nbytes == sizeof(value)) {
        return EVTHR_RES_OK;
    }

    if (errno == EAGAIN) {
        return EVTHR_RES_RETRY;
    }

    return EVTHR_RES_FATAL;
}

#ifdef WITH_SEND_MSG
typedef struct msg_ctx msg_ctx_t;
struct msg_ctx {
    evthr_t* thread;
    const void* smsg;
    void* rmsg;
    size_t rbytes;
    bool done;
};
static void
_evthr_msg_send_cb(evthr_t * thread, void * cmd_arg, void * shared)
{
    msg_ctx_t * msg = cmd_arg;
    evthr_t   * sender = msg->thread;

    pthread_mutex_lock(&sender->lock);
    msg->done = true;
    pthread_cond_signal(&sender->cond);
    pthread_mutex_unlock(&sender->lock);
}
evthr_res
evthr_msg_send(evthr_t * thread, evthr_t * dst, const void * smsg, void * rmsg, size_t rbytes)
{
    if (thread == NULL) {
        return EVTHR_RES_FATAL;
    }

    if (dst == NULL) {
        return EVTHR_RES_FATAL;
    }

    msg_ctx_t* msg = calloc(sizeof(msg_ctx_t), 1);
    if (!msg) {
        return EVTHR_RES_FATAL;
    }

    msg->thread = thread;
    msg->smsg = smsg;
    msg->rmsg = rmsg;
    msg->rbytes = rbytes;
    msg->done = false;

    evthr_defer(dst, _evthr_msg_send_cb, msg);

    // Wait for the reply to be ready.
    pthread_mutex_lock(&thread->lock);
    while (!msg->done)
    {
        pthread_cond_wait(&thread->cond, &thread->lock);
    }
    pthread_mutex_unlock(&thread->lock);

    free(msg);

    return EVTHR_RES_OK;
}
#endif//WITH_SEND_MSG

evthr_res
evthr_stop(evthr_t * thread)
{
    eventfd_t value = 1;
    ssize_t   nbytes;

    if (thread == NULL) {
        return EVTHR_RES_FATAL;
    }

    nbytes = write(thread->stop_fd, &value, sizeof(value));
    if (nbytes == sizeof(value)) {
        pthread_join(*thread->thr, NULL);
        return EVTHR_RES_OK;
    }

    if (errno == EAGAIN) {
        return EVTHR_RES_RETRY;
    }

    return EVTHR_RES_FATAL;
}

evbase_t *
evthr_get_base(evthr_t * thr)
{
    return thr ? thr->evbase : NULL;
}

void
evthr_set_aux(evthr_t * thr, void * aux)
{
    if (thr) {
        thr->aux = aux;
    }
}

void *
evthr_get_aux(evthr_t * thr)
{
    return thr ? thr->aux : NULL;
}

int
evthr_set_initcb(evthr_t * thr, evthr_init_cb cb)
{
    if (thr == NULL) {
        return -1;
    }

    thr->init_cb = cb;

    return 0;
}

int
evthr_set_exitcb(evthr_t * thr, evthr_exit_cb cb)
{
    if (thr == NULL) {
        return -1;
    }

    thr->exit_cb = cb;

    return 0;
}

static evthr_t *
_evthr_new(evthr_init_cb init_cb, evthr_exit_cb exit_cb, void * args)
{
    evthr_t * thread;
    int       msg_fd;
    int       stop_fd;

    msg_fd = eventfd(0, EFD_NONBLOCK);
    if (msg_fd == -1) {
        return NULL;
    }

    stop_fd = eventfd(0, EFD_NONBLOCK);
    if (stop_fd == -1) {
        close(msg_fd);
        return NULL;
    }

    if (!(thread = calloc(sizeof(evthr_t), 1))) {
        return NULL;
    }

    thread->thr     = malloc(sizeof(pthread_t));
    thread->arg     = args;
    thread->msg_fd  = msg_fd;
    thread->stop_fd = stop_fd;

    thread->init_cb = init_cb;
    thread->exit_cb = exit_cb;

    mpsc_queue_init(&thread->queue);

    size_t size = 64;
    void* buffer = malloc(size * sizeof(void**));
    spsc_queue_init(&thread->msg_cache_p, &thread->msg_cache_c, buffer, size);

    thread->msg_cache_buf = buffer;

    if (pthread_mutex_init(&thread->lock, NULL)) {
        evthr_free(thread);
        return NULL;
    }

#ifdef WITH_SEND_MSG

    if (pthread_cond_init(&thread->cond, NULL)) {
        evthr_free(thread);
        return NULL;
    }

#endif

log_debug("thread %p, %zu bytes", thread, sizeof(*thread));
    return thread;
} /* evthr_new */

evthr_t *
evthr_new(evthr_init_cb init_cb, void * args)
{
    return _evthr_new(init_cb, NULL, args);
}

evthr_t *
evthr_wexit_new(evthr_init_cb init_cb, evthr_exit_cb exit_cb, void * args)
{
    return _evthr_new(init_cb, exit_cb, args);
}

int
evthr_start(evthr_t * thread)
{
    if (thread == NULL || thread->thr == NULL) {
        return -1;
    }

    if (pthread_create(thread->thr, NULL, _evthr_loop, (void *)thread)) {
        return -1;
    }

    return 0;
}

void
evthr_free(evthr_t * thread)
{
    if (thread == NULL) {
        return;
    }

    if (thread->msg_fd > 0) {
        close(thread->msg_fd);
    }

    if (thread->stop_fd > 0) {
        close(thread->stop_fd);
    }

    if (thread->thr) {
        free(thread->thr);
    }

    if (thread->msg_event) {
        event_free(thread->msg_event);
    }

    if (thread->stop_event) {
        event_free(thread->stop_event);
    }

    if (thread->evbase) {
        event_base_free(thread->evbase);
    }

    if (thread->msg_cache_buf) {
        evthr_cmd_t* cmd;
        while ((cmd = spsc_dequeue(&thread->msg_cache_c)))
        {
            IF_COUNTERS(++thread->free_count;)
            free(cmd);
        }
        free(thread->msg_cache_buf);
    }

IF_COUNTERS(printf("%s - %p, %d alloc'd, %d freed, %d reused, %d processed\n", __func__, thread, thread->alloc_count, thread->free_count, thread->reuse_count, thread->msg_count);)

    free(thread);
} /* evthr_free */

void
evthr_pool_free(evthr_pool_t * pool)
{
    if (pool == NULL) {
        return;
    }

    if (tls_thread) {
        evthr_free(tls_thread);
        tls_thread = NULL;
    }

    IF_COUNTERS(printf("evthr_pool_free(%p)\n", pool);)

    for (size_t i = 0; i < pool->nthreads; ++i) {
        evthr_free(pool->threads[i]);
    }

    if (pool->threads) free(pool->threads);
    free(pool);
}

evthr_res
evthr_pool_stop(evthr_pool_t * pool)
{
    if (pool == NULL) {
        return EVTHR_RES_FATAL;
    }

    for (size_t i = 0; i < pool->nthreads; ++i) {
        evthr_stop(pool->threads[i]);
    }

    return EVTHR_RES_OK;
}

static inline size_t
get_second_index_(size_t i, size_t n)
{
    size_t step;

    if (n <= 1) {
        return i;
    }

    step = n / 2;
    if (step == 0) {
        step = 1;
    }

    return (i + step) % n;
}

evthr_res
evthr_pool_defer_all(evthr_pool_t * pool, evthr_cb cb, void * arg)
{
    if (pool == NULL) {
        return EVTHR_RES_FATAL;
    }

    for (size_t i = 0; i < pool->nthreads; ++i) {
        evthr_res res = evthr_defer(pool->threads[i], cb, arg);
        if (res != EVTHR_RES_OK) {
            return res;
        }
    }

    return EVTHR_RES_OK;
}

typedef struct defer_sync_ctx defer_sync_ctx_t;
struct defer_sync_ctx {
    pthread_cond_t cond;
    pthread_mutex_t mut;
    evthr_cb cb;
    void   * arg;
    size_t nthreads;
};

static void
defer_sync_cb(evthr_t * thr, void * cmd_arg, void * shared)
{
    defer_sync_ctx_t * ctx = cmd_arg;
    ctx->cb(thr, ctx->arg, shared);
    pthread_mutex_lock(&ctx->mut);
    --ctx->nthreads;
    pthread_cond_signal(&ctx->cond);
    pthread_mutex_unlock(&ctx->mut);
}

evthr_res
evthr_pool_defer_all_sync(evthr_pool_t * pool, evthr_cb cb, void * arg)
{
    defer_sync_ctx_t ctx = {
        .cond = PTHREAD_COND_INITIALIZER,
        .mut = PTHREAD_MUTEX_INITIALIZER,
        .cb = cb,
        .arg = arg
    };

    if (pool == NULL) {
        return EVTHR_RES_FATAL;
    }

    ctx.nthreads = pool->nthreads;

    evthr_res res = evthr_pool_defer_all(pool, defer_sync_cb, &ctx);
    if (res != EVTHR_RES_OK) {
        return res;
    }

    pthread_mutex_lock(&ctx.mut);
    while (ctx.nthreads > 0)
    {
        pthread_cond_wait(&ctx.cond, &ctx.mut);
    }
    pthread_mutex_unlock(&ctx.mut);

    return EVTHR_RES_OK;
}

typedef struct defer_completed_ctx defer_completed_ctx_t;
struct defer_completed_ctx {
    evthr_t       * sender;
    evthr_eval_cb   cb;
    evthr_cb        complete_cb;
    void          * arg;
};

static void
defer_completed_cb(evthr_t * thr, void * cmd_arg, void * shared)
{
    defer_completed_ctx_t * ctx = cmd_arg;
    void* arg = ctx->cb(thr, ctx->arg, shared);
    evthr_defer(ctx->sender, ctx->complete_cb, arg);
}

evthr_res
evthr_pool_defer_all_completed(evthr_pool_t * pool, evthr_eval_cb cb, void * arg, evthr_cb complete_cb)
{

if (!tls_thread && !(tls_thread = _evthr_new(NULL, NULL, NULL))) {
    return EVTHR_RES_FATAL;
}

    defer_completed_ctx_t ctx = {
        .sender = tls_thread,
        .cb = cb,
        .complete_cb = complete_cb,
        .arg = arg
    };

    if (pool == NULL) {
        return EVTHR_RES_FATAL;
    }

    if (complete_cb == NULL) {
        return EVTHR_RES_FATAL;
    }

    return evthr_pool_defer_all_sync(pool, defer_completed_cb, &ctx);
}

evthr_res
evthr_pool_defer(evthr_pool_t * pool, evthr_cb cb, void * arg)
{
    uint32_t  ticket;
    size_t    i;
    size_t    j;
    evthr_t * a;
    evthr_t * b;
    evthr_t * c;
    size_t    backlog_a;
    size_t    backlog_b;

    if (pool == NULL) {
        return EVTHR_RES_FATAL;
    }

    if (cb == NULL) {
        return EVTHR_RES_NOCB;
    }

    if (pool->threads == NULL || pool->nthreads == 0) {
        return EVTHR_RES_FATAL;
    }

    if (pool->nthreads == 1) {
        return evthr_defer(pool->threads[0], cb, arg);
    }

    ticket = atomic_fetch_add_explicit(&pool->next_choice, 1, memory_order_relaxed);

    i = (size_t)(ticket % pool->nthreads);
    j = get_second_index_(i, pool->nthreads);

    a = pool->threads[i];
    b = pool->threads[j];

    backlog_a = atomic_load_explicit(&a->tail, memory_order_relaxed);
    if (backlog_a == 0) {
        atomic_fetch_add_explicit(&a->tail, 1, memory_order_relaxed);
        return evthr_defer(a, cb, arg);
    }

    backlog_b = atomic_load_explicit(&b->tail, memory_order_relaxed);
    if (backlog_b == 0) {
        atomic_fetch_add_explicit(&b->tail, 1, memory_order_relaxed);
        return evthr_defer(b, cb, arg);
    }

    c = (backlog_a <= backlog_b) ? a : b;
    atomic_fetch_add_explicit(&c->tail, 1, memory_order_relaxed);
    return evthr_defer(c, cb, arg);

} /* evthr_pool_defer */

static evthr_pool_t *
_evthr_pool_new(int           nthreads,
                evthr_init_cb init_cb,
                evthr_exit_cb exit_cb,
                void        * shared)
{
    evthr_pool_t * pool;
    int            i;

    if (nthreads == 0) {
        return NULL;
    }

    if (!(pool = calloc(sizeof(evthr_pool_t), 1))) {
        return NULL;
    }

    if (!(pool->threads = calloc(nthreads, sizeof(pool->threads[0])))) {
        evthr_pool_free(pool);
        return NULL;
    }

    if (!tls_thread && !(tls_thread = _evthr_new(NULL, NULL, NULL))) {
        evthr_pool_free(pool);
        return NULL;
    }

    pool->nthreads = nthreads;
    atomic_init(&pool->next_choice, 0);

    for (i = 0; i < nthreads; i++) {
        evthr_t * thread;

        if (!(thread = evthr_wexit_new(init_cb, exit_cb, shared))) {
            evthr_pool_free(pool);
            return NULL;
        }

        pool->threads[i] = thread;
    }

    return pool;
} /* _evthr_pool_new */

evthr_pool_t *
evthr_pool_new(int nthreads, evthr_init_cb init_cb, void * shared)
{
    return _evthr_pool_new(nthreads, init_cb, NULL, shared);
}

evthr_pool_t *
evthr_pool_wexit_new(int nthreads,
                     evthr_init_cb init_cb,
                     evthr_exit_cb exit_cb, void * shared)
{
    return _evthr_pool_new(nthreads, init_cb, exit_cb, shared);
}

int
evthr_pool_start(evthr_pool_t * pool)
{
    evthr_t * evthr = NULL;

    if (pool == NULL) {
        return -1;
    }

    for (size_t i = 0; i < pool->nthreads; ++i) {
        if (evthr_start(pool->threads[i]) < 0) {
            return -1;
        }

        usleep(5000);
    }

    return 0;
}
