/* evhtp_h2.h — included only from evhtp.c, not installed */
#ifndef EVHTP_H2_H
#define EVHTP_H2_H

#include <nghttp2/nghttp2.h>
#include "evhtp/evhtp.h"

/* Per-connection HTTP/2 context, hung off evhtp_connection_t->h2ctx */
typedef struct evhtp_h2_conn_ctx {
    nghttp2_session * session;
    evhtp_connection_t * conn;
    struct event * flush_ev;
} evhtp_h2_conn_ctx_t;

evhtp_h2_conn_ctx_t * evhtp_h2_conn_ctx_new(evhtp_connection_t * conn,
                                            evhtp_type role);
void                  evhtp_h2_conn_ctx_free(evhtp_h2_conn_ctx_t * ctx);

/* Called from htp__connection_readcb_ when IS_HTTP2 flag is set */
void evhtp_h2_read(evhtp_connection_t * conn, struct evbuffer * input);

/* Called from evhtp_send_reply / evhtp_send_reply_end when IS_HTTP2 */
int  evhtp_h2_send_reply(evhtp_request_t * req, evhtp_res code);
int  evhtp_h2_send_reply_start(evhtp_request_t * req, evhtp_res code);
int  evhtp_h2_send_reply_body(evhtp_request_t * req, struct evbuffer * buf);
int  evhtp_h2_send_reply_end(evhtp_request_t * req);
int  evhtp_h2_reset_stream(evhtp_request_t * req, uint32_t error_code);

#endif
