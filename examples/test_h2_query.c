/*
 * test_h2_query.c - a request's path and query string are parsed the same
 * on HTTP/2 as on HTTP/1.1.
 *
 * HTTP/2 carries the request target in the :path pseudo-header; it must be
 * split like the HTTP/1.x parser splits it: uri->path (path, file, full)
 * without the query, uri->query and uri->query_raw from the query string,
 * and - with no query string - an application/x-www-form-urlencoded body as
 * the query (uri->has_query_body).
 *
 * The server answers with what it parsed; every URL is fetched over both
 * protocols and the answers must match, and match what is expected.
 *
 * Usage: test_h2_query <cert.pem> <key.pem>
 * Needs curl with HTTP/2 support on PATH.
 *
 *   openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
 *       -keyout key.pem -out cert.pem
 *   ./test_h2_query cert.pem key.pem
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <evhtp.h>

#define PORT 9445

static int passed, failed;

#define CHECK(c) do {                                                      \
        if (c) { passed++; }                                               \
        else { failed++; fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } \
    } while (0)

static const char *
q(evhtp_request_t * req, const char * k)
{
    const char * v = req->uri->query ? evhtp_kv_find(req->uri->query, k) : NULL;
    return v ? v : "-";
}

/* Answer with what libevhtp parsed out of the request target. */
static void
echo_cb(evhtp_request_t * req, void * arg)
{
    evhtp_path_t * p = req->uri->path;

    (void)arg;
    evbuffer_add_printf(req->buffer_out,
                        "full=%s path=%s file=%s raw=%s query=%s a=%s b=%s z=%s body_q=%d",
                        p->full, p->path, p->file ? p->file : "-",
                        req->uri->query_raw ? (char *)req->uri->query_raw : "-",
                        req->uri->query ? "yes" : "no",
                        q(req, "a"), q(req, "b"), q(req, "z"),
                        req->uri->has_query_body);
    evhtp_send_reply(req, EVHTP_RES_OK);
}

static void *
loop_main(void * arg)
{
    event_base_dispatch(arg);
    return NULL;
}

/* Fetch with curl; the response body into out. */
static void
fetch(const char * proto, const char * target, const char * form, char * out, size_t cap)
{
    char   cmd[512];
    FILE * p;
    size_t n;

    snprintf(cmd, sizeof(cmd),
             "curl -sS -k --max-time 10 %s %s%s%s 'https://127.0.0.1:%d%s' 2>&1",
             proto,
             form ? "-H 'Content-Type: application/x-www-form-urlencoded' --data '" : "",
             form ? form : "", form ? "'" : "",
             PORT, target);
    p      = popen(cmd, "r");
    n      = fread(out, 1, cap - 1, p);
    out[n] = '\0';
    pclose(p);
}

static void
check(const char * target, const char * form, const char * want)
{
    char h2[1024], h1[1024];

    fetch("--http2", target, form, h2, sizeof(h2));
    fetch("--http1.1", target, form, h1, sizeof(h1));
    printf("  %-28s %s%s\n", target, form ? "(form) " : "", h2);
    CHECK(strcmp(h2, h1) == 0);
    CHECK(strcmp(h2, want) == 0);

    if (strcmp(h2, h1) != 0) {
        fprintf(stderr, "    HTTP/1.1 got: %s\n", h1);
    }
    if (strcmp(h2, want) != 0) {
        fprintf(stderr, "    expected:     %s\n", want);
    }
}

int
main(int argc, char ** argv)
{
    struct event_base * base;
    evhtp_t           * htp;
    evhtp_ssl_cfg_t     ssl;
    pthread_t           th;

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

    evhtp_set_gencb(htp, echo_cb, NULL);

    if (evhtp_bind_socket(htp, "127.0.0.1", PORT, 16) != 0) {
        fprintf(stderr, "bind failed\n");
        return 1;
    }

    pthread_create(&th, NULL, loop_main, base);

    puts("HTTP/2 and HTTP/1.1 parse the request target alike:");
    check("/q?a=1&b=two", NULL,
          "full=/q path=/ file=q raw=a=1&b=two query=yes a=1 b=two z=- body_q=0");
    check("/q", NULL,
          "full=/q path=/ file=q raw=- query=no a=- b=- z=- body_q=0");
    check("/dir/file.txt?z=9&a=x%20y", NULL,
          "full=/dir/file.txt path=/dir/ file=file.txt raw=z=9&a=x%20y query=yes a=x%20y b=- z=9 body_q=0");
    check("/dir/?a=1&a=2", NULL,
          "full=/dir/ path=/dir/ file=- raw=a=1&a=2 query=yes a=1 b=- z=- body_q=0");
    check("/q?a", NULL,
          "full=/q path=/ file=q raw=a query=yes a=- b=- z=- body_q=0");
    puts("a form body is the query when there is no query string:");
    check("/form", "a=from-body&b=2",
          "full=/form path=/ file=form raw=a=from-body&b=2 query=yes a=from-body b=2 z=- body_q=1");
    check("/form?a=from-url", "a=from-body&b=2",
          "full=/form path=/ file=form raw=a=from-url query=yes a=from-url b=- z=- body_q=0");

    event_base_loopbreak(base);
    pthread_join(th, NULL);
    evhtp_unbind_socket(htp);
    evhtp_free(htp);
    event_base_free(base);

    printf("%d checks, %d failed\n", passed + failed, failed);
    return failed != 0;
}
