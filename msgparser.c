/*
 * msgparser.c - HTTP/1.x message parser behind libevhtp's htparser API.
 *
 * Shaped after httpcore5's AbstractMessageParser: the head is read a line
 * at a time - head line, header lines, empty line - and a message is only
 * looked at once a whole line is there. Unlike the Java parser it keeps no
 * line buffer: the caller (evhtp.c) leaves unconsumed bytes in its input
 * buffer and presents them again with more data, so every token handed to
 * a hook points into the caller's buffer (zero copy) and an incomplete line
 * simply ends the run without consuming it.
 *
 *   AbstractMessageParser (Java)        here
 *   ----------------------------------  -----------------------------------
 *   State READ_HEAD_LINE / READ_HEADERS S_HEAD_LINE / S_HEADERS
 *   State COMPLETED                     S_BODY (decoders) -> S_COMPLETE
 *   sessionBuffer.readLine(lineBuf)     take_line(): a complete line, in place
 *   Http1Config maxLineLength,          htp_http1config_t (msgparser.h)
 *     maxHeaderCount, maxEmptyLineCount
 *   parseHeadLine(): empty line ->      S_START skips empty lines, counted
 *     emptyLineCount, else createMessage  against max_empty_line_count
 *   parseHeader(): folding              rejected (allow_folding unsupported)
 *   headerBufs, parsed after COMPLETED  hdr_key/hdr_val hooks per line
 *   ContentLengthStrategy + decoders    framing(): RFC 9112 6.3 order;
 *     (Length/Chunked/Identity)           parse_length/chunked/identity
 *
 * Validation stays minimal: only what decides where a message ends is
 * checked strictly (Content-Length, Transfer-Encoding, chunk sizes, line
 * ends), since a wrong answer there desynchronises the connection and no
 * later layer can repair it. Everything else is for the layer above.
 *
 * Contract with the caller, as parser.c's:
 *   - htparser_run() parses at most one message: it returns after
 *     on_msg_complete, leaving any pipelined bytes unconsumed, and starts
 *     the next message (on_msg_begin) only on a later call.
 *   - A hook that calls htparser_pause() stops the run right after it
 *     returns. htparser_resume() + htparser_run() carry on from there, also
 *     with no new data (len 0), e.g. to complete a bodiless message paused
 *     in on_hdrs_complete.
 *   - A hook returning non-zero fails the message with htparse_error_user.
 */
#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "evhtp/config.h"
#include "htstring/htstring.h"
#include "htstring/tokenizer.h"
#include "htstring/parsed_uri.h"
#include "evhtp/parser.h"
#include "evhtp/msgparser.h"

typedef enum {
    S_START = 0,        /* between messages: skip empty lines             */
    S_HEAD_LINE,        /* request line / status line                     */
    S_HEADERS,
    S_BODY,
    S_TRAILERS,         /* chunked trailer section                        */
    S_COMPLETE,         /* on_msg_complete still to be fired              */
    S_ERROR
} state_t;

typedef enum {
    B_NONE = 0,
    B_LENGTH,           /* Content-Length                                 */
    B_CHUNKED,
    B_IDENTITY          /* response read until the connection closes      */
} body_t;

typedef enum {
    C_SIZE = 0,         /* chunk-size [; ext] CRLF                        */
    C_DATA,
    C_DATA_END          /* the CRLF after chunk-data                      */
} chunk_t;

enum {
    F_HAVE_HOST       = 1u << 0,
    F_HAVE_CL         = 1u << 1,
    F_HAVE_TE         = 1u << 2,
    F_CHUNKED         = 1u << 3,    /* Transfer-Encoding ends in chunked  */
    F_TE_BAD          = 1u << 4,    /* chunked twice, or not last         */
    F_TE_UNKNOWN      = 1u << 5,    /* a coding we do not know            */
    F_HAVE_CT         = 1u << 6,
    F_MULTIPART       = 1u << 7,
    F_CONN_KEEP_ALIVE = 1u << 8,
    F_CONN_CLOSE      = 1u << 9,
    F_SKIP_BODY       = 1u << 10,   /* htparser_set_skip_body()           */
    F_PAUSED          = 1u << 11
};

struct htparser {
    const htp_http1config_t * config;
    void                    * userdata;
    htp_type                  type;

    state_t                   state;
    htpparse_error            error;
    body_t                    body;
    chunk_t                   chunk;

    /* the message */
    htp_method                method;
    htp_scheme                scheme;
    unsigned int              status;
    unsigned char             major;
    unsigned char             minor;
    unsigned int              flags;

    uint64_t                  content_len;       /* body bytes still to come */
    uint64_t                  orig_content_len;  /* Content-Length / chunk   */

    size_t                    header_count;      /* headers or trailers      */
    size_t                    empty_lines;

    uint64_t                  bytes_read;        /* by the last run          */
    uint64_t                  total_bytes_read;
};

static const htp_http1config_t default_config = {
    .max_line_length      = 8192,
    .max_header_count     = 100,
    .max_empty_line_count = 10,
    .allow_folding        = false,  /* folding is never supported */
};

/* Same strings, same order as parser.c (its "PROPATCH" spelling too: a
 * caller may compare against it). */
static const char * const method_strmap[] = {
    "UNKNOWN", "GET",      "HEAD",      "POST",  "PUT",    "DELETE",
    "MKCOL",   "COPY",     "MOVE",      "OPTIONS", "PROPFIND", "PROPATCH",
    "LOCK",    "UNLOCK",   "TRACE",     "CONNECT", "PATCH",
};

static const char * const errstr_map[] = {
    "htparse_error_none",
    "htparse_error_too_big",
    "htparse_error_invalid_method",
    "htparse_error_invalid_requestline",
    "htparse_error_invalid_schema",
    "htparse_error_invalid_protocol",
    "htparse_error_invalid_version",
    "htparse_error_invalid_header",
    "htparse_error_invalid_chunk_size",
    "htparse_error_invalid_chunk",
    "htparse_error_invalid_state",
    "htparse_error_user",
    "htparse_error_status",
    "htparse_error_unknown",
};

/* ------------------------------------------------------------------------ */
/* Hooks: absent hooks succeed; a failing one fails the message.            */
/* ------------------------------------------------------------------------ */

static bool
fail(htparser * p, htpparse_error e)
{
    p->error = e;
    p->state = S_ERROR;
    return false;
}

#define HOOK(p, hooks, name) \
    (!(hooks) || !(hooks)->name || (hooks)->name(p) == 0 || fail((p), htparse_error_user))

#define DHOOK(p, hooks, name, s, n) \
    (!(hooks) || !(hooks)->name || (hooks)->name((p), (s), (n)) == 0 || \
     fail((p), htparse_error_user))

/* ------------------------------------------------------------------------ */
/* Lines (Java: SessionInputBuffer.readLine)                                */
/* ------------------------------------------------------------------------ */

/*
 * A complete line at data: its content (without CRLF or bare LF) in *line,
 * its full length with the line end in *used. Returns 1, 0 if the line is
 * not complete yet, -1 if it is (or is already) longer than allowed.
 */
static int
take_line(htparser * p, const char * data, size_t len, htstring_t * line, size_t * used)
{
    size_t       max = p->config->max_line_length;
    const char * nl  = memchr(data, '\n', len);
    size_t       n;

    if (nl == NULL)
    {
        return max && len > max ? -1 : 0;
    }

    n = (size_t)(nl - data);
    *used = n + 1;

    if (n && data[n - 1] == '\r')
    {
        --n;
    }

    if (max && n > max)
    {
        return -1;
    }

    line->startp = data;
    line->len    = n;
    return 1;
}

/* ------------------------------------------------------------------------ */
/* Small helpers                                                            */
/* ------------------------------------------------------------------------ */

/* Method names by length, most common first within a length. */
static const struct {
    const char * name;
    size_t       len;
    htp_method   method;
} methods[] = {
    { "GET",       3, htp_method_GET },     { "PUT",       3, htp_method_PUT },
    { "POST",      4, htp_method_POST },    { "HEAD",      4, htp_method_HEAD },
    { "COPY",      4, htp_method_COPY },    { "MOVE",      4, htp_method_MOVE },
    { "LOCK",      4, htp_method_LOCK },    { "PATCH",     5, htp_method_PATCH },
    { "TRACE",     5, htp_method_TRACE },   { "MKCOL",     5, htp_method_MKCOL },
    { "DELETE",    6, htp_method_DELETE },  { "UNLOCK",    6, htp_method_UNLOCK },
    { "OPTIONS",   7, htp_method_OPTIONS }, { "CONNECT",   7, htp_method_CONNECT },
    { "PROPFIND",  8, htp_method_PROPFIND },
    { "PROPPATCH", 9, htp_method_PROPPATCH },   /* "PROPATCH" in method_strmap */
};

static htp_method
method_from(const char * m, size_t n)
{
    for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++)
    {
        if (methods[i].len == n && memcmp(methods[i].name, m, n) == 0)
        {
            return methods[i].method;
        }
    }

    return htp_method_UNKNOWN;
}

/* The next SP-delimited token of a start line; *cur moves past it and the
 * spaces that follow. (RFC 9112 separates with SP; extra SPs are allowed.) */
static htstring_t
next_token(htstring_t * cur)
{
    const char * s = cur->startp, * e = s + cur->len;
    const char * t;

    while (s < e && *s == ' ')
    {
        s++;
    }

    if ((t = memchr(s, ' ', (size_t)(e - s))) == NULL)
    {
        t = e;
    }

    htstring_t tok = { .startp = s, .len = (size_t)(t - s) };

    while (t < e && *t == ' ')
    {
        t++;
    }

    cur->startp = t;
    cur->len    = (size_t)(e - t);
    return tok;
}

/* "HTTP/d.d" */
static bool
parse_version(htparser * p, htstring_t v)
{
    const char * s = v.startp;

    if (v.len != 8 || memcmp(s, "HTTP/", 5) != 0 ||
        !isdigit((unsigned char)s[5]) || s[6] != '.' || !isdigit((unsigned char)s[7]) ||
        s[5] == '0')
    {
        return false;
    }

    p->major = (unsigned char)(s[5] - '0');
    p->minor = (unsigned char)(s[7] - '0');
    return true;
}

/* Decimal Content-Length; false on anything else or overflow. */
static bool
parse_u64(htstring_t s, uint64_t * out)
{
    uint64_t v = 0;

    if (s.len == 0)
    {
        return false;
    }

    for (size_t i = 0; i < s.len; i++)
    {
        unsigned d = (unsigned)(s.startp[i] - '0');

        if (d > 9 || v > (UINT64_MAX - d) / 10)
        {
            return false;
        }

        v = v * 10 + d;
    }

    *out = v;
    return true;
}

static int
hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c |= 0x20;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* chunk-size: 1*HEXDIG, at most 15 digits (fits int64 with room). */
static bool
parse_chunk_size(htstring_t s, uint64_t * out)
{
    uint64_t v = 0;
    size_t   n = 0;

    while (n < s.len && hexval((unsigned char)s.startp[n]) >= 0)
    {
        if (n == 15)
        {
            return false;
        }

        v = (v << 4) | (uint64_t)hexval((unsigned char)s.startp[n++]);
    }

    /* digits, then nothing, BWS, or ";" chunk extensions (not validated) */
    if (n == 0)
    {
        return false;
    }

    for (size_t i = n; i < s.len; i++)
    {
        if (s.startp[i] == ';')
        {
            break;
        }

        if (s.startp[i] != ' ' && s.startp[i] != '\t')
        {
            return false;
        }
    }

    *out = v;
    return true;
}

/* ------------------------------------------------------------------------ */
/* Request line: method SP request-target SP HTTP-version                   */
/* ------------------------------------------------------------------------ */

static htp_scheme
scheme_from(htstring_t s)
{
    if (htstring_equalsi(s, HTSTRING_LIT("http")))  return htp_scheme_http;
    if (htstring_equalsi(s, HTSTRING_LIT("https"))) return htp_scheme_https;
    if (htstring_equalsi(s, HTSTRING_LIT("ftp")))   return htp_scheme_ftp;
    if (htstring_equalsi(s, HTSTRING_LIT("nfs")))   return htp_scheme_nfs;
    return htp_scheme_unknown;
}

static bool
emit_host_port(htparser * p, htparse_hooks * hooks, const char * base, struct parsed_uri * u)
{
    htstring_t host = parsed_uri_get_host(base, u);

    if (!DHOOK(p, hooks, host, host.startp, host.len))
    {
        return false;
    }

    if (parsed_uri_has_port(u))
    {
        htstring_t   hp    = parsed_uri_get_host_port(base, u);
        const char * colon = hp.startp + hp.len;

        while (colon > hp.startp && colon[-1] != ':')
        {
            colon--;
        }

        colon = colon > hp.startp ? colon - 1 : NULL;     /* the last ':' */

        if (colon && !DHOOK(p, hooks, port, colon + 1,
                            (size_t)(hp.startp + hp.len - (colon + 1))))
        {
            return false;
        }
    }

    return true;
}

/* Hooks in parser.c's order: scheme, host, port, path, args, uri. */
static bool
emit_target(htparser * p, htparse_hooks * hooks, htstring_t t)
{
    if (t.startp[0] == '/')                         /* origin-form */
    {
        const char * q = memchr(t.startp, '?', t.len);
        size_t       n = q ? (size_t)(q - t.startp) : t.len;

        p->scheme = htp_scheme_none;

        return DHOOK(p, hooks, path, t.startp, n) &&
               (!q || DHOOK(p, hooks, args, q + 1, t.len - n - 1)) &&
               DHOOK(p, hooks, uri, t.startp, t.len);
    }

    if (t.len == 1 && t.startp[0] == '*')           /* asterisk-form */
    {
        p->scheme = htp_scheme_none;
        return DHOOK(p, hooks, path, t.startp, 1) && DHOOK(p, hooks, uri, t.startp, 1);
    }

    struct parsed_uri u = parse_uri_view(t, p->method == htp_method_CONNECT);

    if (parsed_uri_has_error(&u))
    {
        return fail(p, htparse_error_inval_reqline);
    }

    if (parsed_uri_is_authority_form(&u))           /* CONNECT host:port */
    {
        p->scheme = htp_scheme_none;
        return emit_host_port(p, hooks, t.startp, &u) &&
               DHOOK(p, hooks, path, "/", 1) &&
               DHOOK(p, hooks, uri, t.startp, t.len);
    }

    htstring_t scheme = parsed_uri_get_scheme(t.startp, &u);

    if ((p->scheme = scheme_from(scheme)) == htp_scheme_unknown)
    {
        return fail(p, htparse_error_inval_schema);
    }

    htstring_t path = parsed_uri_get_path(t.startp, &u);

    if (!DHOOK(p, hooks, scheme, scheme.startp, scheme.len) ||
        !emit_host_port(p, hooks, t.startp, &u) ||
        !DHOOK(p, hooks, path, path.len ? path.startp : "/", path.len ? path.len : 1))
    {
        return false;
    }

    if (parsed_uri_has_query(&u))
    {
        htstring_t q = parsed_uri_get_query(t.startp, &u);

        if (!DHOOK(p, hooks, args, q.startp, q.len))
        {
            return false;
        }
    }

    return DHOOK(p, hooks, uri, t.startp, t.len);
}

static bool
parse_request_line(htparser * p, htparse_hooks * hooks, htstring_t line)
{
    htstring_t method = next_token(&line);
    htstring_t target = next_token(&line);
    htstring_t ver    = next_token(&line);

    if ((p->method = method_from(method.startp, method.len)) == htp_method_UNKNOWN)
    {
        return fail(p, htparse_error_inval_method);
    }

    if (target.len == 0 || line.len != 0)
    {
        return fail(p, htparse_error_inval_reqline);
    }

    /* the version first, so hooks below can rely on major/minor */
    if (!parse_version(p, ver))
    {
        return fail(p, htparse_error_inval_ver);
    }

    return DHOOK(p, hooks, method, method.startp, method.len) &&
           emit_target(p, hooks, target);
}

/* Status line: HTTP-version SP 3DIGIT SP [reason] */
static bool
parse_status_line(htparser * p, htstring_t line)
{
    const char * s = line.startp;

    if (line.len < 12 || !parse_version(p, (htstring_t){ .startp = s, .len = 8 }))
    {
        return fail(p, htparse_error_inval_ver);
    }

    if (s[8] != ' ' || !isdigit((unsigned char)s[9]) || !isdigit((unsigned char)s[10]) ||
        !isdigit((unsigned char)s[11]) || (line.len > 12 && s[12] != ' '))
    {
        return fail(p, htparse_error_status);
    }

    p->status = (unsigned)((s[9] - '0') * 100 + (s[10] - '0') * 10 + (s[11] - '0'));

    if (p->status < 100)
    {
        return fail(p, htparse_error_status);
    }

    return true;
}

/* ------------------------------------------------------------------------ */
/* Header fields                                                            */
/* ------------------------------------------------------------------------ */

static bool
is_known_coding(htstring_t c)
{
    return htstring_equalsi(c, HTSTRING_LIT("gzip")) ||
           htstring_equalsi(c, HTSTRING_LIT("deflate")) ||
           htstring_equalsi(c, HTSTRING_LIT("compress")) ||
           htstring_equalsi(c, HTSTRING_LIT("x-gzip"));
}

/* Transfer-Encoding, over every such field: only chunked as the last coding
 * frames the body. */
static void
note_transfer_encoding(htparser * p, htstring_t v)
{
    ht_element_iter_t it = ht_element_iter_ctor(v);
    ht_element_t      el;

    p->flags |= F_HAVE_TE;

    while (ht_element_iter_next(&it, &el))
    {
        if (htstring_equalsi(el.name, HTSTRING_LIT("chunked")))
        {
            if (p->flags & F_CHUNKED)
            {
                p->flags |= F_TE_BAD;           /* chunked twice */
            }

            p->flags |= F_CHUNKED;
        }
        else
        {
            if (p->flags & F_CHUNKED)
            {
                p->flags |= F_TE_BAD;           /* a coding after chunked */
            }

            if (!is_known_coding(el.name))
            {
                p->flags |= F_TE_UNKNOWN;
            }
        }
    }
}

/* Connection is a list of tokens, possibly over several fields. */
static void
note_connection(htparser * p, htstring_t v)
{
    ht_element_iter_t it = ht_element_iter_ctor(v);
    ht_element_t      el;

    while (ht_element_iter_next(&it, &el))
    {
        if (htstring_equalsi(el.name, HTSTRING_LIT("close")))
        {
            p->flags |= F_CONN_CLOSE;
        }
        else if (htstring_equalsi(el.name, HTSTRING_LIT("keep-alive")))
        {
            p->flags |= F_CONN_KEEP_ALIVE;
        }
    }
}

/* Content-Length: repeated fields (or "5, 5") must agree. */
static bool
note_content_length(htparser * p, htstring_t v)
{
    ht_element_iter_t it = ht_element_iter_ctor(v);
    ht_element_t      el;
    bool              any = false;

    while (ht_element_iter_next(&it, &el))
    {
        uint64_t n;

        if (!parse_u64(el.name, &n))
        {
            return fail(p, htparse_error_inval_hdr);
        }

        if ((p->flags & F_HAVE_CL) && n != p->orig_content_len)
        {
            return fail(p, htparse_error_inval_hdr);
        }

        p->orig_content_len = n;
        p->flags           |= F_HAVE_CL;
        any                 = true;
    }

    return any || fail(p, htparse_error_inval_hdr);
}

/* name ":" OWS value OWS. Leading whitespace would be obs-fold: refused. */
static bool
parse_header(htparser * p, htparse_hooks * hooks, htstring_t line, bool trailer)
{
    const char * colon = memchr(line.startp, ':', line.len);
    htstring_t   name, value;

    if (line.startp[0] == ' ' || line.startp[0] == '\t' || colon == NULL ||
        colon == line.startp || colon[-1] == ' ' || colon[-1] == '\t')
    {
        return fail(p, htparse_error_inval_hdr);
    }

    name.startp  = line.startp;
    name.len     = (size_t)(colon - line.startp);
    value.startp = colon + 1;
    value.len    = line.len - name.len - 1;

    while (value.len && (value.startp[0] == ' ' || value.startp[0] == '\t'))
    {
        value.startp++;
        value.len--;
    }

    while (value.len && (value.startp[value.len - 1] == ' ' ||
                         value.startp[value.len - 1] == '\t'))
    {
        value.len--;
    }

    /* parser.c reports trailer fields through the same hooks; framing
     * fields among them mean nothing and are not looked at */
    if (!DHOOK(p, hooks, hdr_key, name.startp, name.len))
    {
        return false;
    }

    if (!trailer)
    {
        switch (name.len)
        {
            case 4:
                if (!(p->flags & F_HAVE_HOST) && htstring_equalsi(name, HTSTRING_LIT("Host")))
                {
                    p->flags |= F_HAVE_HOST;

                    if (!DHOOK(p, hooks, hostname, value.startp, value.len))
                    {
                        return false;
                    }
                }
                break;

            case 10:
                if (htstring_equalsi(name, HTSTRING_LIT("Connection")))
                {
                    note_connection(p, value);
                }
                break;

            case 12:
                if (!(p->flags & F_HAVE_CT) && htstring_equalsi(name, HTSTRING_LIT("Content-Type")))
                {
                    p->flags |= F_HAVE_CT;

                    if (value.len >= 9 &&
                        htstring_equalsi((htstring_t){ .startp = value.startp, .len = 9 },
                                         HTSTRING_LIT("multipart")))
                    {
                        p->flags |= F_MULTIPART;
                    }
                }
                break;

            case 14:
                if (htstring_equalsi(name, HTSTRING_LIT("Content-Length")) &&
                    !note_content_length(p, value))
                {
                    return false;
                }
                break;

            case 17:
                if (htstring_equalsi(name, HTSTRING_LIT("Transfer-Encoding")))
                {
                    note_transfer_encoding(p, value);
                }
                break;
        }
    }

    return DHOOK(p, hooks, hdr_val, value.startp, value.len);
}

/* ------------------------------------------------------------------------ */
/* Framing: where does the body end? (RFC 9112 6.3; httpcore5's             */
/* DefaultContentLengthStrategy plus the response rules of its client)      */
/* ------------------------------------------------------------------------ */

static bool
framing(htparser * p)
{
    bool response = p->type == htp_type_response;

    if (p->flags & F_SKIP_BODY)
    {
        p->body = B_NONE;                       /* e.g. a response to HEAD */
    }
    else if (response && (p->status < 200 || p->status == 204 || p->status == 304))
    {
        p->body = B_NONE;                       /* never a body, CL or not */
    }
    else if (p->flags & F_HAVE_TE)
    {
        if (p->flags & F_TE_BAD)
        {
            return fail(p, htparse_error_inval_hdr);
        }

        if (!response && (!(p->flags & F_CHUNKED) || (p->flags & F_TE_UNKNOWN) ||
                          (p->flags & F_HAVE_CL)))
        {
            /* request: the body length can't be determined, or both
             * framings were sent (request smuggling) - 400 */
            return fail(p, htparse_error_inval_hdr);
        }

        /* chunked last: chunked; else the response runs until close */
        p->body = (p->flags & F_CHUNKED) ? B_CHUNKED : B_IDENTITY;
    }
    else if (p->flags & F_HAVE_CL)
    {
        p->body = p->orig_content_len ? B_LENGTH : B_NONE;
    }
    else if (response && (p->major * 10 + p->minor) < 11 && !(p->flags & F_CONN_KEEP_ALIVE))
    {
        p->body = B_IDENTITY;                   /* parser.c's rule, kept */
    }
    else
    {
        p->body = B_NONE;
    }

    p->content_len = p->body == B_LENGTH ? p->orig_content_len : 0;
    p->chunk       = C_SIZE;
    return true;
}

/* ------------------------------------------------------------------------ */
/* Bodies (Java: LengthDelimitedDecoder / ChunkDecoder / IdentityDecoder)   */
/* ------------------------------------------------------------------------ */

static size_t
parse_body(htparser * p, htparse_hooks * hooks, const char * data, size_t len)
{
    size_t off = 0;

    switch (p->body)
    {
        case B_LENGTH:
        case B_IDENTITY:
        {
            size_t n = len;

            if (p->body == B_LENGTH && (uint64_t)n > p->content_len)
            {
                n = (size_t)p->content_len;
            }

            if (n && !DHOOK(p, hooks, body, data, n))
            {
                return n;
            }

            if (p->body == B_LENGTH && (p->content_len -= n) == 0)
            {
                p->state = S_COMPLETE;
            }

            return n;
        }

        case B_CHUNKED:
            /* one step per call; the run loop calls again */
            switch (p->chunk)
            {
                case C_SIZE:
                {
                    htstring_t line;
                    uint64_t   size;
                    int        r = take_line(p, data, len, &line, &off);

                    if (r <= 0)
                    {
                        if (r < 0)
                        {
                            fail(p, htparse_error_too_big);
                        }

                        return 0;
                    }

                    if (!parse_chunk_size(line, &size))
                    {
                        fail(p, htparse_error_inval_chunk_sz);
                        return off;
                    }

                    if (size == 0)
                    {
                        p->state        = S_TRAILERS;
                        p->header_count = 0;
                        (void)HOOK(p, hooks, on_chunks_complete);
                        return off;
                    }

                    p->content_len = p->orig_content_len = size;
                    p->chunk       = C_DATA;
                    (void)HOOK(p, hooks, on_new_chunk);
                    return off;
                }

                case C_DATA:
                {
                    size_t n = (uint64_t)len > p->content_len ? (size_t)p->content_len : len;

                    if (!DHOOK(p, hooks, body, data, n))
                    {
                        return n;
                    }

                    if ((p->content_len -= n) == 0)
                    {
                        p->chunk = C_DATA_END;
                    }

                    return n;
                }

                case C_DATA_END:
                {
                    htstring_t line;
                    int        r = take_line(p, data, len, &line, &off);

                    if (r == 0 && len < 2)
                    {
                        return 0;               /* CRLF not here yet */
                    }

                    if (r <= 0 || line.len != 0)
                    {
                        fail(p, htparse_error_inval_chunk);
                        return 0;
                    }

                    p->chunk = C_SIZE;
                    (void)HOOK(p, hooks, on_chunk_complete);
                    return off;
                }
            }
            break;

        case B_NONE:
            break;
    }

    p->state = S_COMPLETE;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* The run loop (Java: AbstractMessageParser.parse)                         */
/* ------------------------------------------------------------------------ */

/* Message state back to "nothing seen"; the configuration, userdata and
 * byte totals stay. */
static void
message_reset(htparser * p)
{
    p->state            = S_START;
    p->error            = htparse_error_none;
    p->body             = B_NONE;
    p->chunk            = C_SIZE;
    p->method           = htp_method_UNKNOWN;
    p->scheme           = htp_scheme_none;
    p->status           = 0;
    p->major            = 0;
    p->minor            = 0;
    p->flags           &= F_PAUSED;
    p->content_len      = 0;
    p->orig_content_len = 0;
    p->header_count     = 0;
    p->empty_lines      = 0;
}

/* The head of the message (or the trailer section): its lines, for as long
 * as complete ones are there (Java: the parse() loop over readLine()).
 * Returns the bytes consumed; 0 means a line is not complete yet. */
static size_t
parse_head(htparser * p, htparse_hooks * hooks, const char * data, size_t len)
{
    const size_t max_headers = p->config->max_header_count;
    size_t       off         = 0;

    while ((p->state == S_HEAD_LINE || p->state == S_HEADERS || p->state == S_TRAILERS) &&
           !(p->flags & F_PAUSED))
    {
        htstring_t line;
        size_t     used = 0;
        int        r    = take_line(p, data + off, len - off, &line, &used);

        if (r <= 0)
        {
            if (r < 0)
            {
                fail(p, htparse_error_too_big);
            }

            break;
        }

        off += used;

        if (p->state == S_HEAD_LINE)
        {
            bool ok = p->type == htp_type_request ? parse_request_line(p, hooks, line)
                                                  : parse_status_line(p, line);

            if (ok)
            {
                p->state = S_HEADERS;
                (void)HOOK(p, hooks, on_hdrs_begin);
            }
        }
        else if (line.len == 0)                 /* end of the head (or trailers) */
        {
            if (p->state == S_TRAILERS)
            {
                p->state = S_COMPLETE;
            }
            else if (framing(p))
            {
                p->state = p->body == B_NONE ? S_COMPLETE : S_BODY;

                /* callers inspect framing here and may set skip_body or pause */
                if (HOOK(p, hooks, on_hdrs_complete) && (p->flags & F_SKIP_BODY))
                {
                    p->body  = B_NONE;
                    p->state = S_COMPLETE;
                }
            }
        }
        else if (max_headers && p->header_count >= max_headers)
        {
            fail(p, htparse_error_too_big);
        }
        else
        {
            p->header_count++;
            parse_header(p, hooks, line, p->state == S_TRAILERS);
        }
    }

    return off;
}

size_t
htparser_run(htparser * p, htparse_hooks * hooks, const char * data, size_t len)
{
    size_t off = 0;

    p->bytes_read = 0;

    while (p->state != S_ERROR && !(p->flags & F_PAUSED))
    {
        size_t n;

        switch (p->state)
        {
            case S_START:
                /* Java parseHeadLine(): empty lines before a message are
                 * skipped, up to max_empty_line_count of them */
                while (off < len && (data[off] == '\r' || data[off] == '\n'))
                {
                    if (data[off++] == '\n' && p->config->max_empty_line_count &&
                        ++p->empty_lines >= p->config->max_empty_line_count)
                    {
                        fail(p, htparse_error_too_big);
                        goto out;
                    }
                }

                if (off == len)
                {
                    goto out;                   /* begin on the first byte */
                }

                message_reset(p);
                p->state = S_HEAD_LINE;
                (void)HOOK(p, hooks, on_msg_begin);
                continue;

            case S_HEAD_LINE:
            case S_HEADERS:
            case S_TRAILERS:
                n = parse_head(p, hooks, data + off, len - off);
                break;

            case S_BODY:
                if (off == len)
                {
                    goto out;
                }

                n = parse_body(p, hooks, data + off, len - off);
                break;

            case S_COMPLETE:
                /* one message per run: the next begins on a later call */
                p->state  = S_START;
                p->flags &= ~F_SKIP_BODY;       /* it applied to this one */
                (void)HOOK(p, hooks, on_msg_complete);
                goto out;

            default:
                goto out;
        }

        off += n;

        if (n == 0 && (p->state == S_HEAD_LINE || p->state == S_HEADERS ||
                       p->state == S_TRAILERS || p->state == S_BODY))
        {
            goto out;                           /* need more data */
        }
    }

out:
    p->bytes_read        = off;
    p->total_bytes_read += off;
    return off;
}

/* EOF from the peer: it ends a read-until-close response. */
size_t
htparser_run_eof(htparser * p, htparse_hooks * hooks)
{
    if (p->state == S_BODY && p->body == B_IDENTITY)
    {
        p->state = S_START;
        (void)HOOK(p, hooks, on_msg_complete);
    }

    return 0;
}

/* ------------------------------------------------------------------------ */
/* Life cycle and configuration                                             */
/* ------------------------------------------------------------------------ */

htparser *
htparser_new_(const htp_http1config_t * config)
{
    htparser * p = calloc(1, sizeof(*p));

    if (p)
    {
        p->config = config ? config : &default_config;
        message_reset(p);
    }

    return p;
}

htparser *
htparser_new(void)
{
    return htparser_new_(NULL);
}

void
htparser_free(htparser * p)
{
    free(p);
}

/* A fresh parser for type. A configuration set before is kept. */
void
htparser_init(htparser * p, htp_type type)
{
    if (p->config == NULL)
    {
        p->config = &default_config;
    }

    p->type       = type;
    p->flags      = 0;
    p->bytes_read = 0;
    message_reset(p);
}

void
htparser_reset(htparser * p)
{
    if (p)
    {
        unsigned int skip = p->flags & F_SKIP_BODY;

        message_reset(p);
        p->flags = skip;
    }
}

void
htparser_set_http1config(htparser * p, const htp_http1config_t * config)
{
    if (p)
    {
        p->config = config ? config : &default_config;
    }
}

/* ------------------------------------------------------------------------ */
/* Accessors (parser.h)                                                     */
/* ------------------------------------------------------------------------ */

int
htparser_should_keep_alive(htparser * p)
{
    if (p == NULL || (p->flags & F_CONN_CLOSE))
    {
        return 0;
    }

    return p->major * 10 + p->minor >= 11 || (p->flags & F_CONN_KEEP_ALIVE);
}

htp_scheme     htparser_get_scheme(htparser * p)            { return p ? p->scheme : htp_scheme_unknown; }
htp_method     htparser_get_method(htparser * p)            { return p ? p->method : htp_method_UNKNOWN; }
void           htparser_set_method(htparser * p, htp_method m) { if (p) p->method = m; }
const char   * htparser_get_methodstr(htparser * p)         { return p ? htparser_get_methodstr_m(p->method) : NULL; }
void           htparser_set_major(htparser * p, unsigned char v) { if (p) p->major = v; }
void           htparser_set_minor(htparser * p, unsigned char v) { if (p) p->minor = v; }
unsigned char  htparser_get_major(htparser * p)             { return p ? p->major : 0; }
unsigned char  htparser_get_minor(htparser * p)             { return p ? p->minor : 0; }
unsigned char  htparser_get_multipart(htparser * p)         { return p ? !!(p->flags & F_MULTIPART) : 0; }
unsigned int   htparser_get_status(htparser * p)            { return p ? p->status : 0; }
void           htparser_set_status(htparser * p, unsigned int s) { if (p) p->status = s; }
uint64_t       htparser_get_content_length(htparser * p)    { return p ? p->orig_content_len : 0; }
void           htparser_set_content_length(htparser * p, uint64_t n) { if (p) p->orig_content_len = n; }
uint64_t       htparser_get_content_pending(htparser * p)   { return p ? p->content_len : 0; }
uint64_t       htparser_get_bytes_read(htparser * p)        { return p ? p->bytes_read : 0; }
uint64_t       htparser_get_total_bytes_read(htparser * p)  { return p ? p->total_bytes_read : 0; }
htpparse_error htparser_get_error(htparser * p)             { return p ? p->error : htparse_error_user; }
void         * htparser_get_userdata(htparser * p)          { return p ? p->userdata : NULL; }
void           htparser_set_userdata(htparser * p, void * u) { if (p) p->userdata = u; }
int            htparser_is_chunked(htparser * p)            { return p ? !!(p->flags & F_CHUNKED) : 0; }
int            htparser_uses_transfer_encoding(htparser * p) { return p ? !!(p->flags & F_HAVE_TE) : 0; }
int            htparser_is_identity_response(htparser * p)  { return p ? p->body == B_IDENTITY : 0; }
void           htparser_pause(htparser * p)                 { if (p) p->flags |= F_PAUSED; }
void           htparser_resume(htparser * p)                { if (p) p->flags &= ~F_PAUSED; }
int            htparser_is_paused(htparser * p)             { return p ? !!(p->flags & F_PAUSED) : 0; }

/* Valid for parsing: before on_hdrs_complete returns (or before the run
 * that reads the head). Cleared when the message completes. */
void           htparser_set_skip_body(htparser * p)         { if (p) p->flags |= F_SKIP_BODY; }

int
htparser_has_content_length(htparser * p)
{
    return p ? (p->flags & F_HAVE_CL) && !(p->flags & F_CHUNKED) : 0;
}

const char *
htparser_get_methodstr_m(htp_method m)
{
    return (unsigned)m < htp_method_LAST ? method_strmap[m] : NULL;
}

htp_method
htparser_parse_method(htparser * p, const char * m, const size_t n)
{
    p->method = method_from(m, n);
    return p->method;
}

const char *
htparser_get_strerror(htparser * p)
{
    htpparse_error e = htparser_get_error(p);

    return (unsigned)e <= htparse_error_generic ? errstr_map[e] : "htparse_no_such_error";
}
