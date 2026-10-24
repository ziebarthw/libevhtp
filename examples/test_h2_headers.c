/*
 * test_h2_headers.c - connection-specific response headers over HTTP/2.
 *
 * RFC 9113 8.2.2: an HTTP/2 message carrying Connection, Keep-Alive,
 * Proxy-Connection, Transfer-Encoding or Upgrade is malformed, and clients
 * reject it (curl: "PROTOCOL_ERROR", Chrome: ERR_HTTP2_PROTOCOL_ERROR).
 * Applications written for HTTP/1.x set such headers routinely, e.g.
 * "Connection: close"; evhtp_h2_send_reply() must leave them out. Over
 * HTTP/1.1 they are sent as before.
 *
 * Usage: test_h2_headers <cert.pem> <key.pem>
 * Needs curl with HTTP/2 support on PATH.
 *
 *   openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
 *       -keyout key.pem -out cert.pem
 *   ./test_h2_headers cert.pem key.pem
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <evhtp.h>

#define PORT 9443

static int passed, failed;

#define CHECK(c) do {                                                      \
        if (c) { passed++; }                                               \
        else { failed++; fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } \
    } while (0)

static void
add(evhtp_request_t * req, const char * k, const char * v)
{
    evhtp_headers_add_header(req->headers_out, evhtp_header_new(k, v, 0, 0));
}

/* A reply as an HTTP/1.x-minded application would write it. */
static void
reply_cb(evhtp_request_t * req, void * arg)
{
    (void)arg;
    add(req, "Connection", "close");
    add(req, "Keep-Alive", "timeout=5");
    add(req, "Proxy-Connection", "keep-alive");
    add(req, "Upgrade", "websocket");
    add(req, "X-Mixed-Case", "kept");
    add(req, "Content-Type", "text/plain");
    evbuffer_add(req->buffer_out, "hello", 5);
    evhtp_send_reply(req, EVHTP_RES_OK);
}

static void *
loop_main(void * arg)
{
    event_base_dispatch(arg);
    return NULL;
}

/* Run curl, return its exit status; |out| gets headers + body. */
static int
run_curl(const char * proto_flag, char * out, size_t cap)
{
    char   cmd[256];
    FILE * p;
    size_t n;

    snprintf(cmd, sizeof(cmd),
             "curl -sS -k --max-time 5 %s -D - https://127.0.0.1:%d/ 2>&1", proto_flag, PORT);
    p        = popen(cmd, "r");
    n        = fread(out, 1, cap - 1, p);
    out[n]   = '\0';

    return WEXITSTATUS(pclose(p));
}

/* Response header present (case-insensitive name at line start)? */
static int
has_header(const char * resp, const char * name)
{
    const char * line = resp;
    size_t       nl   = strlen(name);

    while (line && *line) {
        if (strncasecmp(line, name, nl) == 0 && line[nl] == ':') {
            return 1;
        }

        line = strchr(line, '\n');
        line = line ? line + 1 : NULL;
    }

    return 0;
}

int
main(int argc, char ** argv)
{
    struct event_base * base;
    evhtp_t           * htp;
    evhtp_ssl_cfg_t     ssl;
    pthread_t           th;
    char                out[8192];
    int                 rc;

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

    evhtp_set_gencb(htp, reply_cb, NULL);

    if (evhtp_bind_socket(htp, "127.0.0.1", PORT, 16) != 0) {
        fprintf(stderr, "bind failed\n");
        return 1;
    }

    pthread_create(&th, NULL, loop_main, base);

    puts("HTTP/2: connection-specific headers are left out, the rest kept");
    rc = run_curl("--http2", out, sizeof(out));
    printf("%s\n", out);
    CHECK(rc == 0);
    CHECK(strncmp(out, "HTTP/2 200", 10) == 0);
    CHECK(!has_header(out, "connection"));
    CHECK(!has_header(out, "keep-alive"));
    CHECK(!has_header(out, "proxy-connection"));
    CHECK(!has_header(out, "upgrade"));
    CHECK(!has_header(out, "transfer-encoding"));
    CHECK(has_header(out, "x-mixed-case"));
    CHECK(has_header(out, "content-type"));
    CHECK(strstr(out, "hello") != NULL);

    puts("HTTP/1.1: unchanged, the headers are sent");
    rc = run_curl("--http1.1", out, sizeof(out));
    printf("%s\n", out);
    CHECK(rc == 0);
    CHECK(strncmp(out, "HTTP/1.1 200", 12) == 0);
    CHECK(has_header(out, "connection") && has_header(out, "upgrade"));
    CHECK(strstr(out, "hello") != NULL);

    event_base_loopbreak(base);
    pthread_join(th, NULL);
    evhtp_unbind_socket(htp);
    evhtp_free(htp);
    event_base_free(base);

    printf("%d checks, %d failed\n", passed + failed, failed);
    return failed != 0;
}
