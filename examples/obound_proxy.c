#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
//#include <errno.h>
#include <signal.h>
#include <evhtp.h>
#include <event2/dns.h>

typedef struct evdns_base evdns_t;

typedef struct oproxy_cfg oproxy_cfg_t;
struct oproxy_cfg {
    char* listen_ip;
    short listen_port;
};

typedef struct oproxy oproxy_t;
struct oproxy {
    oproxy_cfg_t cfg;
    evhtp_t* evhtp;
    evdns_t* evdns;
};

static evhtp_res
downstream_request_fini_cb(evhtp_request_t* req, void* arg)
{
    evhtp_request_t* upstream_req = arg;
    evhtp_connection_t* conn = evhtp_request_get_connection(upstream_req);
    evhtp_safe_free(conn, evhtp_connection_free);
    return EVHTP_RES_OK;
}

static int
send_upstream(evhtp_request_t* downstream_req, evdns_t* evdns, const char* const host, const short port,
                evhtp_callback_cb cb, void* arg)
{
    evthr_t* evthr = downstream_req->conn->thread;
    evbase_t* evbase = evthr_get_base(evthr);

    // Create a new connection to the back end server.
    evhtp_connection_t* conn = evhtp_connection_new_dns(evbase, evdns, host, port);
    conn->thread = evthr;

    evhtp_request_t* upstream_req = evhtp_request_new(cb, arg);
    // When the downstream request is finished, we want to clean up the
    // upstream request.
    evhtp_request_set_hook(downstream_req, evhtp_hook_on_request_fini, (evhtp_hook)downstream_request_fini_cb, upstream_req);

    evhtp_headers_add_headers(upstream_req->headers_out, downstream_req->headers_in);

    int rval = evhtp_make_request(conn, upstream_req, downstream_req->method, downstream_req->uri->path->full);
    if (rval != 0)
    {
        return rval;
    }

    return 0;
}

static void
upstream_response_cb(evhtp_request_t* upstream_req, void* arg)
{
    evhtp_request_t* downstream_req = (evhtp_request_t*)arg;

    evhtp_header_rm_and_free(upstream_req->headers_in,
        evhtp_headers_find_header(upstream_req->headers_in, "transfer-encoding"));

    evbuffer_prepend_buffer(downstream_req->buffer_out, upstream_req->buffer_in);
    evhtp_headers_add_headers(downstream_req->headers_out, upstream_req->headers_in);
    evhtp_kv_rm_and_free(downstream_req->headers_out,
        evhtp_headers_find_header(downstream_req->headers_out, "connection"));
    evhtp_headers_add_header(downstream_req->headers_out,
        evhtp_header_new("Connection", "close", 0, 0));

    evhtp_send_reply(downstream_req, EVHTP_RES_OK);
    /* Unpause the downstream request now that the upstream request is complete. */
    evhtp_request_resume(downstream_req);
}

static inline const char*
scheme_val_to_str(htp_scheme scheme)
{
    switch (scheme)
    {
        case htp_scheme_http:
            return "http";
        case htp_scheme_https:
            return "https";
        default:
            return "invalid";
    }
}

static inline const char*
method_val_to_str(htp_method method)
{
    switch (method)
    {
        case htp_method_GET:
            return "GET";
        default:
            return "invalid";
    }
}

/**
 * @brief any IO from a tunnel connection will call this function which just
 *        writes the data back to the downstream.
 *
 * @param bev
 * @param arg
 */
static void
tunnel_upstream_readcb(evbev_t* bev, void* arg)
{
    /* data was read from the tunnel upstream, so we must send this data to the
     * downstream bufferevent.
     */
    evbev_t* downstream_bev = arg;

    bufferevent_write_buffer(downstream_bev, bufferevent_get_input(bev));
}

/**
 * @brief once IO has started on a tunnel, this will read data from the
 *        downstream and pipe it to the newly connected upstream.
 *
 * @param bev
 * @param arg
 */
static void
tunnel_downstream_readcb(evbev_t* bev, void* arg)
{
    evbev_t* upstream_bev = arg;
    /* simply write the buffer from the upstream to the downstream bufferevent.
     */
    bufferevent_write_buffer(upstream_bev, bufferevent_get_input(bev));
}

/**
 * @brief called once a tunnel connection has been established, or if any
 *        error occurs on the upstream socket.
 *
 * @param bev
 * @param events
 * @param arg
 */
static void
tunnel_upstream_eventcb(evbev_t* bev, short events, void* arg)
{
    evbev_t* downstream_bev = arg;

    if (events & BEV_EVENT_CONNECTED)
    {
        const char* resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
        bufferevent_write(downstream_bev, resp, strlen(resp));
        /* we have successfully established a connection to the tunnel host, so
         * we can re-enable the read side of the downstream bufferevent.
         */
        bufferevent_enable(downstream_bev, EV_READ | EV_WRITE);
    }
    else
    {
        bufferevent_free(bev);
        bufferevent_free(downstream_bev);
    }
}

/**
 * @brief called if there is any error on the upstream socket when using the
 *        redirect pipe.
 *
 * @param bev
 * @param events
 * @param arg
 */
static void
tunnel_downstream_eventcb(evbev_t* bev, short events, void* arg)
{
    evbev_t* upstream_bev = arg;
    /* client aborted the connection, free and close both sides of the
     * connection.
     */
    bufferevent_free(upstream_bev);
    bufferevent_free(bev);
}

static void
downstream_request_cb(evhtp_request_t* downstream_req, void* arg)
{
    oproxy_t* self = arg;
    evdns_t* evdns = self->evdns;
    int* aux = (int*)evthr_get_aux(downstream_req->conn->thread);
    int thr = *aux;

    if (downstream_req->method == htp_method_CONNECT)
    {
        evhtp_authority_t* authority = downstream_req->uri->authority;
        evbase_t* evbase = downstream_req->conn->evbase;
        evbev_t* downstream_bev = evhtp_connection_take_ownership(downstream_req->conn);
        evbev_t* upstream_bev = bufferevent_socket_new(evbase, -1, BEV_OPT_CLOSE_ON_FREE);
        /* do not enable read side of the bufferevent yet, we do this once
         * the connection has been established to the redir host.
         */
        bufferevent_disable(downstream_bev, EV_READ);

        bufferevent_socket_connect_hostname(upstream_bev, evdns,
                                            AF_INET, authority->hostname, authority->port);

        bufferevent_setcb(upstream_bev, tunnel_upstream_readcb,
                            NULL, tunnel_upstream_eventcb, downstream_bev);

        bufferevent_enable(upstream_bev, EV_READ|EV_WRITE);

        /* once the connection has been established, these callbacks pipe
         * the IO back and forth.
         */
        bufferevent_setcb(downstream_bev,
                            tunnel_downstream_readcb, NULL,
                            tunnel_downstream_eventcb, upstream_bev);
    }
    else
    {
        evhtp_authority_t* authority = downstream_req->uri->authority;
        evhtp_uri_t* uri = downstream_req->uri;
        const char* scheme = scheme_val_to_str(downstream_req->uri->scheme);
        short port = authority->port ? authority->port : 80;

        /* Pause the frontend request while we run the backend requests. */
        evhtp_request_pause(downstream_req);

        send_upstream(downstream_req, evdns, authority->hostname, port, upstream_response_cb, downstream_req);
    }
}

static void
init_thread_cb(evhtp_t* htp, evthr_t* thr, void* arg)
{
    static int aux = 0;
    evthr_set_aux(thr, &aux);
}

static void
exit_thread_cb(evhtp_t* htp, evthr_t* thr, void* arg)
{
}

static void
evdns_free(void* arg)
{
    evdns_t* evdns = arg;
    evdns_base_free(evdns, true);
}

static void
oproxy_free(oproxy_t* self)
{
    evhtp_t* evhtp = self ? self->evhtp : NULL;
    evdns_t* evdns = self ? self->evdns : NULL;
    evhtp_safe_free(evdns, evdns_free);
    evhtp_safe_free(evhtp, evhtp_free);
    evhtp_safe_free(self, free);
}

oproxy_t*
oproxy_start(evbase_t* evbase, const oproxy_cfg_t* cfg)
{
    oproxy_t* self = calloc(1, sizeof(*self));
    if (!self)
    {
        return NULL;
    }
    self->cfg = *cfg;

    evhtp_t* evhtp = evhtp_new(evbase, self);
    if (!evhtp)
    {
        oproxy_free(self);
        return NULL;
    }
    self->evhtp = evhtp;

    evhtp_set_gencb(evhtp, downstream_request_cb, self);

    evdns_t* evdns = evdns_base_new(evbase, EVDNS_BASE_INITIALIZE_NAMESERVERS);
    if (!evdns)
    {
        oproxy_free(self);
        return NULL;
    }
    self->evdns = evdns;

    evhtp_use_threads_wexit(evhtp, init_thread_cb, exit_thread_cb, 4, self);
    evhtp_bind_socket(evhtp, cfg->listen_ip, cfg->listen_port, 1024);

    return self;
}

void
oproxy_stop(oproxy_t* self)
{
    if (!self)
    {
        return;
    }
    evthr_pool_stop(self->evhtp->thr_pool);
    oproxy_free(self);
}

/* Terminate gracefully on SIGTERM */
static void
sigterm_cb(int fd, short event, void* arg)
{
    printf("\n");

    evbase_t* evbase = (evbase_t*)arg;
    struct timeval tv = {
        .tv_usec = 100000,
        .tv_sec = 0
    }; /* 100 ms */

    event_base_loopexit(evbase, &tv);
}

int
main(int argc, char** argv)
{
    struct event *ev_sigterm;
    evbase_t* evbase = event_base_new();
    oproxy_cfg_t cfg = {
        .listen_ip = "0.0.0.0",
        .listen_port = 8081
    };
    oproxy_t* oproxy = oproxy_start(evbase, &cfg);

#ifndef WIN32
    ev_sigterm = evsignal_new(evbase, /*SIGTERM|*/SIGINT/*|SIGHUP*/, sigterm_cb, evbase);
    evsignal_add(ev_sigterm, NULL);
#endif
    event_base_loop(evbase, 0);

    oproxy_stop(oproxy);

    event_base_free(evbase);

    return 0;
}
