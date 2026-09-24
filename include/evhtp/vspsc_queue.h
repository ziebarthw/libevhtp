/* vspsc_queue.h - Vyukov-style SPSC ring queue, pure C11, header-only */
#pragma once
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>  /* malloc, free, NULL */
#include <stdbool.h>

#define CACHE_LINE_SIZE 64

typedef struct {
    _Alignas(CACHE_LINE_SIZE) atomic_size_t head;
    _Alignas(CACHE_LINE_SIZE) atomic_size_t tail;
    size_t   capacity;   /* must be power of two */
    void**   buffer;
} spsc_queue_t;

/* Returns true on success, false on allocation failure.
 * |capacity| must be a power of two. */
static inline bool
spsc_init(spsc_queue_t* q, size_t capacity)
{
    /* Capacity must be a power of two and at least 2 so that the
     * full/empty distinction (next == head) is unambiguous. */
    if (capacity < 2 || (capacity & (capacity - 1)) != 0)
        return false;

    q->buffer = malloc(capacity * sizeof(void*));
    if (!q->buffer)
        return false;

    atomic_init(&q->head, 0);
    atomic_init(&q->tail, 0);
    q->capacity = capacity;
    return true;
}

static inline void
spsc_destroy(spsc_queue_t* q)
{
    free(q->buffer);
    q->buffer = NULL;
}

static inline bool
spsc_push(spsc_queue_t* q, void* item)
{
    size_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    size_t next = (tail + 1) & (q->capacity - 1);
    if (next == atomic_load_explicit(&q->head, memory_order_acquire))
        return false; /* full */
    q->buffer[tail] = item;
    atomic_store_explicit(&q->tail, next, memory_order_release);
    return true;
}

static inline bool
spsc_pop(spsc_queue_t* q, void** item)
{
    size_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    if (head == atomic_load_explicit(&q->tail, memory_order_acquire))
        return false; /* empty */
    *item = q->buffer[head];
    atomic_store_explicit(&q->head,
                          (head + 1) & (q->capacity - 1),
                          memory_order_release);
    return true;
}
