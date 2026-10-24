/*
 * test_h2_streaming.c - streaming replies (evhtp_send_reply_start/_body/
 * _end and evhtp_send_reply_chunk_start/_chunk/_chunk_end) over HTTP/2 and
 * HTTP/1.1.
 *
 * The server streams a known byte pattern, in pieces, from timers (as a
 * proxy relaying an origin would), and the test fetches it with curl and
 * checks every byte. Cases: delayed pieces, a body far beyond the HTTP/2
 * flow-control window, body already in buffer_out before the reply starts,
 * an empty body, the chunk_* functions, several streams at once on one
 * HTTP/2 connection, and a client that gives up mid-reply (the request is
 * freed; the server stops on the request_fini hook and serves on).
 *
 * Usage: test_h2_streaming <cert.pem> <key.pem>
 * Needs curl with HTTP/2 support on PATH.
 *
 *   openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
 *       -keyout key.pem -out cert.pem
 *   ./test_h2_streaming cert.pem key.pem
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/wait.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <evhtp.h>

#define PORT 9444

static int passed, failed;

#define CHECK(c) do {                                                      \
        if (c) { passed++; }                                               \
        else { failed++; fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } \
    } while (0)

static struct event_base * base;

static unsigned char
pattern(size_t i)
{
    return (unsigned char)('a' + (i * 7 + i / 251) % 26);
}

/* ======================================================================== */
/* Server: one streaming reply per request, driven by a timer               */
/* ======================================================================== */

typedef struct stream {
    evhtp_request_t * req;          /* NULL once request_fini has run */
    struct event    * timer;
    size_t            piece;        /* bytes per piece */
    int               pieces;       /* pieces still to send */
    int               delay_ms;
    size_t            sent;         /* pattern offset */
    int               chunked;      /* use the chunk_* functions */
} stream;

static int freed_early;             /* requests freed before their end */

static void
send_piece(stream * st)
{
    struct evbuffer * b = evbuffer_new();

    for (size_t i = 0; i < st->piece; i++) {
        unsigned char c = pattern(st->sent + i);
        evbuffer_add(b, &c, 1);
    }

    st->sent += st->piece;

    if (st->chunked) {
        evhtp_send_reply_chunk(st->req, b);
    } else {
        evhtp_send_reply_body(st->req, b);
    }

    evbuffer_free(b);
}

static void
finish(stream * st)
{
    if (st->chunked) {
        evhtp_send_reply_chunk_end(st->req);
    } else {
        evhtp_send_reply_end(st->req);
    }

    /* HTTP/1.x: the reply is queued, so let the connection read again (it
     * was paused in stream_cb). Without this a keep-alive connection never
     * notices the client closing it. No-op on HTTP/2. */
    evhtp_request_resume(st->req);
}

static void
tick(evutil_socket_t fd, short what, void * arg)
{
    stream * st = arg;
    struct timeval tv = { 0, st->delay_ms * 1000 };

    (void)fd;
    (void)what;

    if (st->req == NULL) {                      /* client went away */
        event_free(st->timer);
        free(st);
        return;
    }

    if (st->pieces > 0) {
        send_piece(st);
        st->pieces--;
        evtimer_add(st->timer, &tv);
        return;
    }

    finish(st);
    /* st is freed by on_fini when the request goes */
}

static evhtp_res
on_fini(evhtp_request_t * req, void * arg)
{
    stream * st = arg;

    (void)req;

    if (st->pieces > 0 || evtimer_pending(st->timer, NULL)) {
        /* freed before the reply ended: the timer cleans up */
        freed_early++;
        st->req = NULL;
        return EVHTP_RES_OK;
    }

    event_free(st->timer);
    free(st);
    return EVHTP_RES_OK;
}

/* /stream/PIECES/SIZE/DELAY_MS/PRE/CHUNKED (the parameters are in the
 * path: this fork does not parse an HTTP/2 request's query string) */
static void
stream_cb(evhtp_request_t * req, void * arg)
{
    stream * st = calloc(1, sizeof(*st));
    int      pre = 0, pieces = 4, size = 1000, delay = 20, chunked = 0;

    (void)arg;
    sscanf(req->uri->path->full, "/stream/%d/%d/%d/%d/%d", &pieces, &size, &delay, &pre, &chunked);
    st->req      = req;
    st->pieces   = pieces;
    st->piece    = (size_t)size;
    st->delay_ms = delay;
    st->chunked  = chunked;
    st->timer    = evtimer_new(base, tick, st);

    evhtp_request_set_hook(req, evhtp_hook_on_request_fini, (evhtp_hook)on_fini, st);

    /* body put in buffer_out before the reply starts goes out first */
    for (int i = 0; i < pre; i++) {
        unsigned char c = pattern(st->sent++);
        evbuffer_add(req->buffer_out, &c, 1);
    }

    evhtp_headers_add_header(req->headers_out,
        evhtp_header_new("Content-Type", "application/octet-stream", 0, 0));

    if (!st->chunked) {
        /* evhtp_send_reply_start() needs the length on HTTP/1.x (unknown
         * lengths use the chunk_* functions); on HTTP/2 it is optional */
        char cl[32];

        snprintf(cl, sizeof(cl), "%zu", (size_t)pre + (size_t)pieces * (size_t)size);
        evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Length", cl, 0, 1));
    }

    if (st->chunked) {
        evhtp_send_reply_chunk_start(req, EVHTP_RES_OK);
    } else {
        evhtp_send_reply_start(req, EVHTP_RES_OK);
    }

    {
        struct timeval tv = { 0, st->delay_ms * 1000 };
        evtimer_add(st->timer, &tv);
    }

    evhtp_request_pause(req);   /* reply comes later (no-op on HTTP/2) */
}

static void *
loop_main(void * arg)
{
    event_base_dispatch(arg);
    return NULL;
}

/* ======================================================================== */
/* Client: curl                                                             */
/* ======================================================================== */

/* Body of |path| into a file; returns curl's exit status. */
static int
fetch(const char * proto, const char * path, const char * out, const char * extra)
{
    char cmd[512];

    snprintf(cmd, sizeof(cmd),
             "curl -sS -k --max-time 20 %s %s -o %s -w '%%{http_version} %%{http_code}\\n' "
             "'https://127.0.0.1:%d%s' > %s.meta 2>&1",
             proto, extra ? extra : "", out, PORT, path, out);
    return WEXITSTATUS(system(cmd));
}

/* The file holds exactly bytes [0, len) of the pattern? */
static int
body_ok(const char * file, size_t len)
{
    FILE * f = fopen(file, "rb");
    size_t i = 0;
    int    c, ok = 1;

    if (f == NULL) {
        return 0;
    }

    while ((c = fgetc(f)) != EOF) {
        if (i >= len || (unsigned char)c != pattern(i)) {
            ok = 0;
            break;
        }
        i++;
    }

    fclose(f);

    if (!ok || i != len) {
        fprintf(stderr, "    %s: %zu bytes, %s\n", file, i, ok ? "short" : "wrong data");
    }

    return ok && i == len;
}

static int
meta_is(const char * file, const char * want)
{
    char path[256], line[64] = "";
    FILE * f;

    snprintf(path, sizeof(path), "%s.meta", file);

    if ((f = fopen(path, "r")) == NULL || fgets(line, sizeof(line), f) == NULL) {
        if (f) fclose(f);
        return 0;
    }

    fclose(f);

    if (strncmp(line, want, strlen(want)) != 0) {
        fprintf(stderr, "    %s: \"%.*s\", want \"%s\"\n", file, (int)strcspn(line, "\n"), line, want);
        return 0;
    }

    return 1;
}

static void
one(const char * proto, const char * want, const char * label, const char * path, size_t len)
{
    char out[64];
    int  before = failed;

    snprintf(out, sizeof(out), "/tmp/h2s_%d.out", getpid());
    printf("  %-40s", label);
    CHECK(fetch(proto, path, out, NULL) == 0);
    CHECK(meta_is(out, want));
    CHECK(body_ok(out, len));
    printf(" %s\n", failed == before ? "ok" : "FAILED");
    unlink(out);
}

static void
run_cases(const char * proto, const char * want)
{
    one(proto, want, "4 pieces, 20 ms apart",       "/stream/4/1000/20/0/0",     4000);
    one(proto, want, "1 MB, beyond the 64K window", "/stream/16/65536/1/0/0",    1048576);
    one(proto, want, "body in buffer_out first",    "/stream/2/500/20/300/0",    1300);
    one(proto, want, "empty body",                  "/stream/0/1000/20/0/0",     0);
    one(proto, want, "chunk_* functions",           "/stream/5/777/20/0/1",      3885);
}

int
main(int argc, char ** argv)
{
    evhtp_t       * htp;
    evhtp_ssl_cfg_t ssl;
    pthread_t       th;

    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 3) {
        fprintf(stderr, "usage: %s <cert.pem> <key.pem>\n", argv[0]);
        return 2;
    }

    evthread_use_pthreads();    /* the loop is stopped from this thread */
    base = event_base_new();
    htp  = evhtp_new(base, NULL);

    memset(&ssl, 0, sizeof(ssl));
    ssl.pemfile         = argv[1];
    ssl.privfile        = argv[2];
    ssl.ssl_opts        = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1;
    ssl.ssl_ctx_timeout = 60;

    if (evhtp_ssl_init(htp, &ssl) != 0) {
        fprintf(stderr, "TLS setup failed\n");
        return 1;
    }

    evhtp_set_glob_cb(htp, "/stream/*", stream_cb, NULL);

    if (evhtp_bind_socket(htp, "127.0.0.1", PORT, 64) != 0) {
        fprintf(stderr, "bind failed\n");
        return 1;
    }

    pthread_create(&th, NULL, loop_main, base);

    puts("HTTP/2:");
    run_cases("--http2", "2 200");

    puts("HTTP/1.1 (unchanged):");
    run_cases("--http1.1", "1.1 200");

    puts("HTTP/2: 6 streams at once on one connection");
    {
        char   cmd[2048], out[6][64];
        size_t len[6];
        int    n = 0;

        n += snprintf(cmd + n, sizeof(cmd) - n,
                      "curl -sS -k --max-time 30 --http2 --parallel --parallel-max 6");
        for (int i = 0; i < 6; i++) {
            snprintf(out[i], sizeof(out[i]), "/tmp/h2s_%d_p%d.out", getpid(), i);
            len[i] = (size_t)(i + 1) * 3 * 4096;
            n += snprintf(cmd + n, sizeof(cmd) - n,
                          " -o %s 'https://127.0.0.1:%d/stream/3/%d/%d/0/1'",
                          out[i], PORT, (i + 1) * 4096, 10 + 15 * i);
        }
        snprintf(cmd + n, sizeof(cmd) - n, " -w '%%{http_version} %%{num_connects}\\n' > /tmp/h2s_%d_p.meta 2>&1", getpid());
        CHECK(WEXITSTATUS(system(cmd)) == 0);

        for (int i = 0; i < 6; i++) {
            CHECK(body_ok(out[i], len[i]));
            unlink(out[i]);
        }

        {
            char path[64], line[64];
            FILE * f;
            int conns = 0, lines = 0;

            snprintf(path, sizeof(path), "/tmp/h2s_%d_p.meta", getpid());
            if ((f = fopen(path, "r")) != NULL) {
                while (fgets(line, sizeof(line), f)) {
                    lines++;
                    if (strncmp(line, "2 ", 2) == 0) conns += atoi(line + 2);
                    else fprintf(stderr, "    parallel: %s", line);
                }
                fclose(f);
            }
            CHECK(lines == 6);
            CHECK(conns == 1);      /* one TCP connection for all six */
            printf("  6 replies correct, %d connection(s) opened\n", conns);
            unlink(path);
        }
    }

    puts("HTTP/2: client gives up mid-reply; the server carries on");
    {
        char out[64];
        int  before = freed_early;

        snprintf(out, sizeof(out), "/tmp/h2s_%d_g.out", getpid());
        CHECK(fetch("--http2", "/stream/20/100/100/0/1", out, "--max-time 1") != 0);
        usleep(300 * 1000);         /* the server notices the reset */
        CHECK(freed_early == before + 1);
        unlink(out);
        snprintf(out, sizeof(out), "/tmp/h2s_%d_g.out.meta", getpid());
        unlink(out);
        one("--http2", "2 200", "next request is served", "/stream/2/100/20/0/0", 200);
    }

    sleep(2);                       /* let the abandoned stream's timer end */
    event_base_loopbreak(base);
    pthread_join(th, NULL);
    evhtp_unbind_socket(htp);
    evhtp_free(htp);
    event_base_free(base);

    {
        char m[64];
        snprintf(m, sizeof(m), "/tmp/h2s_%d.out.meta", getpid());
        unlink(m);
    }

    printf("%d checks, %d failed\n", passed + failed, failed);
    return failed != 0;
}
