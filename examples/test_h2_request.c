/*
 * test_h2_request.c - receiving a request over HTTP/2 the way HTTP/1.1
 * does, for applications that take over a request in their hooks:
 *
 *   - req->cb / req->cbarg set in the on_headers hook stand: the request
 *     callback gets the application's argument (HTTP/2 used to reset both
 *     after the hook, so it got the registered callback's argument);
 *   - a request body taken by an on_read hook (which drains it) keeps
 *     flowing past the 64 KB HTTP/2 flow-control windows (they used to be
 *     given back only for data left in the buffer, so the upload stalled).
 *
 * Every request is made over HTTP/2 and HTTP/1.1; the answers must match.
 *
 * Usage: test_h2_request <cert.pem> <key.pem>
 * Needs curl with HTTP/2 support on PATH.
 *
 *   openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
 *       -keyout key.pem -out cert.pem
 *   ./test_h2_request cert.pem key.pem
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <evhtp.h>

#define PORT 9446

static int passed, failed;

#define CHECK(c) do {                                                      \
        if (c) { passed++; }                                               \
        else { failed++; fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } \
    } while (0)

/* Per-request state the application attaches in its on_headers hook. */
typedef struct app_req {
    char          tag[16];
    size_t        got;
    unsigned long sum;
} app_req;

static char registered_arg[] = "registered";

/* The request callback: its argument must be the application's app_req. */
static void
done_cb(evhtp_request_t * req, void * arg)
{
    if (arg == registered_arg) {
        evbuffer_add_printf(req->buffer_out, "cbarg=registered (the hook's was lost)");
    } else {
        app_req * a = arg;

        evbuffer_add_printf(req->buffer_out, "cbarg=%s n=%zu sum=%lu", a->tag, a->got, a->sum);
        free(a);
    }

    evhtp_send_reply(req, EVHTP_RES_OK);
}

/* Takes the body as it arrives, leaving nothing in the buffer. */
static evhtp_res
on_read(evhtp_request_t * req, struct evbuffer * buf, void * arg)
{
    app_req       * a   = arg;
    size_t          len = evbuffer_get_length(buf);
    unsigned char * p   = evbuffer_pullup(buf, (ev_ssize_t)len);

    (void)req;

    for (size_t i = 0; i < len; i++) {
        a->sum = a->sum * 31 + p[i];
    }

    a->got += len;
    evbuffer_drain(buf, len);

    return EVHTP_RES_OK;
}

/* Takes the request over: its own argument for the callback and hooks. */
static evhtp_res
on_headers(evhtp_request_t * req, evhtp_headers_t * hdrs, void * arg)
{
    app_req * a = calloc(1, sizeof(*a));

    (void)hdrs;
    (void)arg;
    snprintf(a->tag, sizeof(a->tag), "app");
    req->cb    = done_cb;
    req->cbarg = a;
    evhtp_request_set_hook(req, evhtp_hook_on_read, (evhtp_hook)on_read, a);

    return EVHTP_RES_OK;
}

static void *
loop_main(void * arg)
{
    event_base_dispatch(arg);
    return NULL;
}

static void
fetch(const char * proto, const char * extra, char * out, size_t cap)
{
    char   cmd[512];
    FILE * p;
    size_t n;

    snprintf(cmd, sizeof(cmd), "curl -sS -k --max-time 15 %s %s 'https://127.0.0.1:%d/x' 2>&1",
             proto, extra ? extra : "", PORT);
    p      = popen(cmd, "r");
    n      = fread(out, 1, cap - 1, p);
    out[n] = '\0';
    pclose(p);
}

static void
check(const char * label, const char * extra, const char * want)
{
    char h2[512], h1[512];

    fetch("--http2", extra, h2, sizeof(h2));
    fetch("--http1.1", extra, h1, sizeof(h1));
    printf("  %-34s %s\n", label, h2);
    CHECK(strcmp(h2, want) == 0);
    CHECK(strcmp(h2, h1) == 0);

    if (strcmp(h2, h1) != 0) {
        fprintf(stderr, "    HTTP/1.1 got: %s\n", h1);
    }
}

int
main(int argc, char ** argv)
{
    struct event_base * base;
    evhtp_t           * htp;
    evhtp_callback_t  * cb;
    evhtp_ssl_cfg_t     ssl;
    pthread_t           th;
    char                file[64], want[128];
    unsigned long       sum = 0;
    size_t              len = 3u * 1024 * 1024;

    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 3) {
        fprintf(stderr, "usage: %s <cert.pem> <key.pem>\n", argv[0]);
        return 2;
    }

    /* the upload */
    snprintf(file, sizeof(file), "/tmp/h2r_%d.bin", getpid());
    {
        FILE * f = fopen(file, "wb");

        for (size_t i = 0; i < len; i++) {
            unsigned char c = (unsigned char)(i * 13 + i / 97);

            fputc(c, f);
            sum = sum * 31 + c;
        }

        fclose(f);
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

    cb = evhtp_set_cb(htp, "/x", done_cb, registered_arg);
    evhtp_callback_set_hook(cb, evhtp_hook_on_headers, (evhtp_hook)on_headers, NULL);

    if (evhtp_bind_socket(htp, "127.0.0.1", PORT, 16) != 0) {
        fprintf(stderr, "bind failed\n");
        return 1;
    }

    pthread_create(&th, NULL, loop_main, base);

    puts("the on_headers hook's req->cb / req->cbarg stand:");
    check("GET", NULL, "cbarg=app n=0 sum=0");

    puts("a body taken by an on_read hook keeps flowing:");
    snprintf(want, sizeof(want), "cbarg=app n=%zu sum=%lu", len, sum);
    {
        char extra[128];

        snprintf(extra, sizeof(extra), "--data-binary @%s -H 'Content-Type: application/octet-stream'", file);
        check("POST 3 MB", extra, want);
    }

    event_base_loopbreak(base);
    pthread_join(th, NULL);
    evhtp_unbind_socket(htp);
    evhtp_free(htp);
    event_base_free(base);
    unlink(file);

    printf("%d checks, %d failed\n", passed + failed, failed);
    return failed != 0;
}
