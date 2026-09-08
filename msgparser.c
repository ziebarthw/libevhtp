
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <strings.h>
#include <time.h>

//#define EVHTP_DEBUG 1
//#define WITH_BULK_TEST

#include "evhtp/config.h"
#include "evhtp/parsed_uri.h"
#include "internal.h"
#include "evhtp/msgparser.h"

#define update_cursor_nread(s, n) do { \
    (s)->len -= (n); \
    (s)->startp += (n);\
} while (0)

#define update_startp(s, l, e) do { \
    (s) += (l); \
    if ((s) < (e)) ++(s); \
} while (0)

#define update_cursor_skip(s, l, e) do { \
    (s)->startp += (l); \
    if ((s)->startp < (e)) ++(s)->startp; \
    (s)->len = (e) - (s)->startp; \
} while (0)

#define MATCHES_NAME(k, n) \
    match_key_name((k)->startp, (k)->len, (n), sizeof(n) - 1)

typedef enum {
    PARSER_START = 0,
    PARSER_READ_HEAD_LINE,
    PARSER_READ_HEADERS,
    PARSER_HEADERS_COMPLETED,
    PARSER_READ_DATA,
    PARSER_COMPLETED,
    PARSER_RESET,
    PARSER_ERROR
} parser_state_e;

static int8_t unhex[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

typedef struct request_line request_line_t;
struct request_line {
    htp_method method;
    htp_scheme scheme;
    htp_string_t uri;
};

typedef struct status_line status_line_t;
struct status_line {
    unsigned int status_code;
    htp_string_t status_text;
};

typedef struct head_line head_line_t;
struct head_line {
    union {
        request_line_t request_line;
        status_line_t status_line;
    };
};

typedef enum {
    CHUNKED_READ_CONTENT,
    CHUNKED_READ_FOOTERS,
    CHUNKED_COMPLETED
} chunked_state_e;

typedef struct chunked_decoder chunked_decoder_t;
struct chunked_decoder {
    chunked_state_e state;
    size_t header_count;
    long chunk_size;
    bool end_of_chunk : 1;
    bool end_of_stream : 1;
};
static inline void
chunked_decoder_init(chunked_decoder_t * self)
{
    self->state = CHUNKED_READ_CONTENT;
    self->header_count = 0;
    self->chunk_size = -1L;
    self->end_of_chunk = false;
    self->end_of_stream = false;
}

typedef size_t (* parse_data_func)(htparser *, const char *, size_t);
typedef struct decoder decoder_t;
struct decoder {
    parse_data_func parse_data;
    union {
        chunked_decoder_t chunked_decoder;
    };
};

struct htparser {
    decoder_t decoder;

    const htp_http1config_t * config;
    htparse_hooks * hooks;

    void * userdata;

    parser_state_e state;
    htpparse_error error;

    htp_type type;

    head_line_t head_line;

    uint64_t content_len;
    uint64_t orig_content_len;

    size_t header_count;
    size_t empty_line_count;

    unsigned char major;
    unsigned char minor;

    #define HAVE_HOST              (1 << 0)
    #define HAVE_CONTENT_LENTH     (1 << 1)
    #define HAVE_CONTENT_TYPE      (1 << 2)
    #define HAVE_TRANSFER_ENCODING (1 << 3)
    #define HAVE_CONNECTION        (1 << 4)
    #define IS_CHUNKED             (1 << 5)
    #define IS_MUTLIPART           (1 << 6)
    #define CONNECTION_KEEP_ALIVE  (1 << 7)
    #define CONNECTION_CLOSE       (1 << 8)
    #define SKIP_BODY              (1 << 9)
    #define PAUSED                 (1 << 10)
    uint16_t flags;
};

static htp_http1config_t default_config = {
    .max_line_length = 8192,
    .max_header_count = 100,
    .max_empty_line_count = 10,
    .allow_folding = false
};

static const char * errstr_map[] = {
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
    "htparse_error_unknown"
};

static const char * method_strmap[] = {
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "MKCOL",
    "COPY",
    "MOVE",
    "OPTIONS",
    "PROPFIND",
    "PROPATCH",
    "LOCK",
    "UNLOCK",
    "TRACE",
    "CONNECT",
    "PATCH",
};

#define __HTPARSE_GENHOOK(__n)                                                    \
    static inline int hook_ ## __n ## _run(htparser * p, htparse_hooks * hooks) { \
        log_debug("enter");                                                       \
        if (hooks && (hooks)->__n)                                                \
        {                                                                         \
            return (hooks)->__n(p);                                               \
        }                                                                         \
                                                                                  \
        return 0;                                                                 \
    }

#define __HTPARSE_GENDHOOK(__n)                                        \
    static inline int hook_ ## __n ## _run(htparser * p,               \
                                           htparse_hooks * hooks,      \
                                           const char * s, size_t l) { \
        log_debug("enter");                                            \
        if (hooks && (hooks)->__n)                                     \
        {                                                              \
            return (hooks)->__n(p, s, l);                              \
        }                                                              \
                                                                       \
        return 0;                                                      \
    }

__HTPARSE_GENHOOK(on_msg_begin)
__HTPARSE_GENHOOK(on_hdrs_begin)
__HTPARSE_GENHOOK(on_hdrs_complete)
__HTPARSE_GENHOOK(on_new_chunk)
__HTPARSE_GENHOOK(on_chunk_complete)
__HTPARSE_GENHOOK(on_chunks_complete)
__HTPARSE_GENHOOK(on_msg_complete)

__HTPARSE_GENDHOOK(method)
__HTPARSE_GENDHOOK(scheme)
__HTPARSE_GENDHOOK(host)
__HTPARSE_GENDHOOK(port)
__HTPARSE_GENDHOOK(path)
__HTPARSE_GENDHOOK(args)
__HTPARSE_GENDHOOK(uri)
__HTPARSE_GENDHOOK(hdr_key)
__HTPARSE_GENDHOOK(hdr_val)
__HTPARSE_GENDHOOK(body)
__HTPARSE_GENDHOOK(hostname)

htparser *
htparser_new_(const htp_http1config_t * config)
{
    log_debug("(%p)", config);

    htparser * self = calloc(1, sizeof(*self));
    if (self)
    {
        self->config = config ? config : &default_config;
        self->state = PARSER_START;
        self->header_count = 0;
        log_debug("self %p, %zu bytes", self, sizeof(*self));
    }
    return self;
}

htparser *
htparser_new(void)
{
    log_debug("()");
    return htparser_new_(NULL);
}

void
htparser_free(htparser * self)
{
    log_debug("(%p)", self);
    if (self)
    {
        free(self);
    }
}

void
htparser_init(htparser * self, htp_type type)
{
    log_debug("(%p, %d)", self, type);
    self->type = type;
    htparser_reset(self);
}

void
htparser_reset(htparser * self)
{
    log_debug("(%p)", self);
    if (self)
    {
        htp_type type = self->type;
        self->state = PARSER_START;
        self->error = htparse_error_none;
        self->flags = 0;
        self->content_len = 0;
        self->orig_content_len = 0;
        self->empty_line_count = 0;
        self->major = 0;
        self->minor = 0;
        self->decoder.parse_data = NULL;
        memset(&self->head_line, 0, sizeof(self->head_line));
    }
}

static inline uint64_t
str_to_uint64(const char * str, size_t n, int * err)
{
    uint64_t value = 0;

    *err = 0;

    /* Trim whitespace after value. */
    while (n && isblank((unsigned char)str[n - 1]))
    {
        n--;
    }

    if (n == 0 || n > 20)
    {
        /* 18446744073709551615 is 20 bytes; also reject empty input */
        *err = 1;
        return 0;
    }

    for (size_t i = 0; i < n; i++, str++)
    {
        if (*str < '0' || *str > '9')
        {
            *err = 1;
            return 0;
        }

        unsigned digit = (unsigned)(*str - '0');

        /* check overflow BEFORE it happens, not after */
        if (value > (UINT64_MAX - digit) / 10)
        {
            *err = 1;
            return 0;
        }

        value = value * 10 + digit;
    }

    return value;
}

static inline int
lc(int c)
{
    return c | 0x20; /* lowercases ASCII letters; harmless on digits/punct here since we control both sides */
}

static inline htp_method
get_method(const htp_string_t * method)
{
    const unsigned char * s = (const unsigned char *)method->startp;
    int c = lc(s[0]);

    switch (method->len)
    {
        case 3:
            if (c == 'g' && lc(s[1]) == 'e' && lc(s[2]) == 't')
                return htp_method_GET;
            if (c == 'p' && lc(s[1]) == 'u' && lc(s[2]) == 't')
                return htp_method_PUT;
            break;

        case 4:
            if (c == 'h' && lc(s[1]) == 'e' && lc(s[2]) == 'a' && lc(s[3]) == 'd')
                return htp_method_HEAD;
            if (c == 'p' && lc(s[1]) == 'o' && lc(s[2]) == 's' && lc(s[3]) == 't')
                return htp_method_POST;
            if (c == 'c' && lc(s[1]) == 'o' && lc(s[2]) == 'p' && lc(s[3]) == 'y')
                return htp_method_COPY;
            if (c == 'm' && lc(s[1]) == 'o' && lc(s[2]) == 'v' && lc(s[3]) == 'e')
                return htp_method_MOVE;
            if (c == 'l' && lc(s[1]) == 'o' && lc(s[2]) == 'c' && lc(s[3]) == 'k')
                return htp_method_LOCK;
            break;

        case 5:
            if (c == 'm' && lc(s[1]) == 'k' && lc(s[2]) == 'c' && lc(s[3]) == 'o' && lc(s[4]) == 'l')
                return htp_method_MKCOL;
            if (c == 't' && lc(s[1]) == 'r' && lc(s[2]) == 'a' && lc(s[3]) == 'c' && lc(s[4]) == 'e')
                return htp_method_TRACE;
            if (c == 'p' && lc(s[1]) == 'a' && lc(s[2]) == 't' && lc(s[3]) == 'c' && lc(s[4]) == 'h')
                return htp_method_PATCH;
            break;

        case 6:
            if (c == 'd' && lc(s[1]) == 'e' && lc(s[2]) == 'l' && lc(s[3]) == 'e' && lc(s[4]) == 't' && lc(s[5]) == 'e')
                return htp_method_DELETE;
            if (c == 'u' && lc(s[1]) == 'n' && lc(s[2]) == 'l' && lc(s[3]) == 'o' && lc(s[4]) == 'c' && lc(s[5]) == 'k')
                return htp_method_UNLOCK;
            break;

        case 7:
            if (c == 'o' && lc(s[1]) == 'p' && lc(s[2]) == 't' && lc(s[3]) == 'i' && lc(s[4]) == 'o' && lc(s[5]) == 'n' && lc(s[6]) == 's')
                return htp_method_OPTIONS;
            if (c == 'c' && lc(s[1]) == 'o' && lc(s[2]) == 'n' && lc(s[3]) == 'n' && lc(s[4]) == 'e' && lc(s[5]) == 'c' && lc(s[6]) == 't')
                return htp_method_CONNECT;
            break;

        case 8:
            if (c == 'p' && lc(s[1]) == 'r' && lc(s[2]) == 'o' && lc(s[3]) == 'p' && lc(s[4]) == 'f' && lc(s[5]) == 'i' && lc(s[6]) == 'n' && lc(s[7]) == 'd')
                return htp_method_PROPFIND;
            break;

        case 9:
            if (c == 'p' && lc(s[1]) == 'r' && lc(s[2]) == 'o' && lc(s[3]) == 'p' && lc(s[4]) == 'p' && lc(s[5]) == 'a' && lc(s[6]) == 't' && lc(s[7]) == 'c' && lc(s[8]) == 'h')
                return htp_method_PROPPATCH;
            break;

        default:
            break;
    }

    return htp_method_UNKNOWN;
}

static inline const char *
skip_white_space(const char * startp, const char * endp)
{
    while (startp < endp && isspace(startp[0])) ++startp;
    return startp;
}

static inline const char *
find_blank(const char * startp, const char * endp)
{
    while (startp < endp && !isblank(startp[0])) ++startp;
    return startp;
}

static inline void
update_cursor_eol(htp_string_t * self, const char ** eol)
{
    const char * eol_ = *eol;
    size_t len = eol_ - self->startp;
    ++eol_; // skip '\n'
    self->len -= eol_ - self->startp;
    self->startp = eol_;
    if (len > 0 && (*eol)[-1] == '\r') --(*eol);
}

static inline htp_string_t
parse_method(htp_string_t * cursor)
{
    log_debug("(%p)", cursor);
    const char * endp = cursor->startp + cursor->len;
    const char * startp = skip_white_space(cursor->startp, endp);
    htp_string_t rval = {
        .startp = startp,
        .len = find_blank(startp, endp) - startp
    };
    update_cursor_skip(cursor, rval.len, endp);
    cursor->len = endp - cursor->startp;
    return rval;
}

static inline htp_string_t
parse_request_uri(htp_string_t * cursor)
{
    log_debug("(%p)", cursor);
    const char * endp = cursor->startp + cursor->len;
    const char * startp = skip_white_space(cursor->startp, endp);
    htp_string_t rval = {
        .startp = startp,
        .len = find_blank(startp, endp) - startp
    };
    update_cursor_skip(cursor, rval.len, endp);
    return rval;
}

static inline htp_string_t
parse_header_key(const char * startp, const char * endp)
{
    log_debug("(%p, %p)", startp, endp);
    startp = skip_white_space(startp, endp);

    const char * colonp = memchr(startp, ':', endp - startp);
    return (htp_string_t){
        .startp = startp,
        .len = colonp ? colonp - startp : 0
    };
}

static inline htp_string_t
parse_header_val(const char * startp, const char * endp)
{
    log_debug("(%p, %p)", startp, endp);
    startp = skip_white_space(startp, endp);
    while (endp > startp && isspace(endp[-1])) --endp;
    return (htp_string_t){
        .startp = startp,
        .len = endp - startp
    };
}

static inline bool
parse_version_number(const htp_string_t * ver, unsigned char * major, unsigned char * minor)
{
    log_debug("(%p(%.*s), %p, %p)", ver, (int)ver->len, ver->startp, major, minor);

    const char * startp = ver->startp;

    if (startp[0] < '1' || startp[0] > '9')
    {
        log_debug("invalid protocol version number");
        return false;
    }

    *major = startp[0] - '0';

    ++startp;

    if (startp[0] != '.')
    {
        log_debug("invalid protocol version number");
        return false;
    }

    ++startp;

    if (startp[0] < '0' || startp[0] > '9')
    {
        log_debug("invalid protocol version number");
        return false;
    }

    *minor = startp[0] - '0';

    return true;
}

static inline htp_string_t
parse_protocol_version(htp_string_t * cursor)
{
    static htp_string_t protoname = {
        .startp = "HTTP",
        .len = 4
    };
    log_debug("(%p)", cursor);

    const char * endp = cursor->startp + cursor->len;
    const char * startp = skip_white_space(cursor->startp, endp);

    htp_string_t ver = {
        .startp = startp,
        .len = 0
    };

    size_t bytes_left = endp - startp;
    if (protoname.len + 4 > bytes_left)
    {
        log_debug("invalid protocol version");
        return ver;
    }

    for (size_t i = 0; i < protoname.len; ++i, ++startp)
    {
        if (startp[0] != protoname.startp[i])
        {
            log_debug("invalid protocol version");
            return ver;
        }
    }

    if (startp[0] != '/')
    {
        log_debug("invalid protocol version");
        return ver;
    }

    ++startp;

    htp_string_t rval = {
        .startp = startp,
        .len = 3
    };

    update_cursor_nread(cursor, startp - cursor->startp);
    cursor->len = endp - cursor->startp;

    return rval;
}

static inline unsigned int
parse_status_code(htp_string_t * cursor)
{
    log_debug("(%p)", cursor);

    const char * endp = cursor->startp + cursor->len;
    const char * startp = skip_white_space(cursor->startp, endp);

    size_t bytes_left = endp - startp;

    if (bytes_left < 3)
    {
        log_debug("invalid status code");
        return 0;
    }

    unsigned int status_code = 0;

    for (int i = 0; i < 3; ++i)
    {
        char c = startp[i];

        if (c < '0' || c > '9')
        {
            log_debug("invalid status code");
            return 0;
        }

        status_code = (status_code * 10) + (unsigned)(c - '0');
    }

    /* reject a 4th digit — status-code is exactly 3 digits per RFC 9112 */
    if (bytes_left > 3 && startp[3] >= '0' && startp[3] <= '9')
    {
        log_debug("invalid status code (too many digits)");
        return 0;
    }

    update_cursor_skip(cursor, 3, endp);

    return status_code;
}

static inline htp_string_t
parse_status_text(htp_string_t * cursor)
{
    log_debug("(%p)", cursor);

    const char * endp = cursor->startp + cursor->len;
    const char * startp = skip_white_space(cursor->startp, endp);

    htp_string_t rval = {
        .startp = startp,
        .len = endp - startp
    };

    update_cursor_skip(cursor, rval.len, endp);

    return rval;
}

static inline bool
is_valid_scheme_start(const char * startp)
{
    log_debug("(%p)", startp);

    unsigned char c = (unsigned char)(startp[0] | 0x20);
    return c >= 'a' && c <= 'z';
}

static inline bool
is_ftp_scheme(const char * startp, size_t len)
{
    return len == 3 &&
            lc(startp[0]) == 'f' &&
            lc(startp[1]) == 't' &&
            lc(startp[2]) == 'p';
}

static inline bool
is_nfs_scheme(const char * startp, size_t len)
{
    return len == 3 &&
            lc(startp[0]) == 'n' &&
            lc(startp[1]) == 'f' &&
            lc(startp[2]) == 's';
}

static inline bool
is_http_scheme(const char * startp, size_t len)
{
    return len == 4 &&
            lc(startp[0]) == 'h' &&
            lc(startp[1]) == 't' &&
            lc(startp[2]) == 't' &&
            lc(startp[3]) == 'p';
}

static inline bool
is_https_scheme(const char * startp, size_t len)
{
    return len == 5 &&
            lc(startp[0]) == 'h' &&
            lc(startp[1]) == 't' &&
            lc(startp[2]) == 't' &&
            lc(startp[3]) == 'p' &&
            lc(startp[4]) == 's';
}

static inline htp_scheme
get_scheme_type(const htp_string_t * scheme)
{
    if (is_http_scheme(scheme->startp, scheme->len))
        return htp_scheme_http;
    else if (is_https_scheme(scheme->startp, scheme->len))
        return htp_scheme_https;
    else if (is_ftp_scheme(scheme->startp, scheme->len))
        return htp_scheme_ftp;
    else if (is_nfs_scheme(scheme->startp, scheme->len))
        return htp_scheme_nfs;
    else
    {
        log_debug("invalid scheme name \"%.*s\"", (int)scheme->len, scheme->startp);
        return htp_scheme_unknown;
    }
}

static bool
consume_uri(htparser * self, request_line_t * request_line, const htp_string_t * uri)
{
    log_debug("(%p, %p, %p(%.*s))", self, request_line, uri, (int)uri->len, uri->startp);

    request_line->scheme = htp_scheme_unknown;

    const char * startp = uri->startp;
    if (startp[0] == '/')
    {
        const char * endp = startp + uri->len;
        const char * curp = memchr(startp, '?', endp - startp);
        const char * args = curp ? curp + 1 : NULL;
        const char * pathendp = curp ? curp : endp;

        if (hook_path_run(self, self->hooks, startp, pathendp - startp) ||
            (args && hook_args_run(self, self->hooks, args, endp - args)))
        {
            self->error = htparse_error_user;
            return false;
        }
    }
    else if (!is_valid_scheme_start(startp))
    {
        log_debug("invalid request line");
        self->error = htparse_error_inval_reqline;
        return false;
    }
    else
    {
        struct parsed_uri u = parse_uri_view(*uri);
        if (parsed_uri_has_error(&u))
        {
            log_debug("parse uri view failed");
            self->error = htparse_error_inval_reqline;
            return false;
        }

        htp_string_t scheme = parsed_uri_get_scheme(startp, &u);
        htp_scheme scheme_type = get_scheme_type(&scheme);
        if (scheme_type == htp_scheme_unknown)
        {
            log_debug("invalid scheme");
            self->error = htparse_error_inval_schema;
            return false;
        }

        if (hook_scheme_run(self, self->hooks, scheme.startp, scheme.len))
        {
            self->error = htparse_error_user;
            return false;
        }

        htp_string_t host = parsed_uri_get_host(startp, &u);
        if (hook_host_run(self, self->hooks, host.startp, host.len))
        {
            self->error = htparse_error_user;
            return false;
        }

        if (parsed_uri_has_port(&u))
        {
            htp_string_t host_port = parsed_uri_get_host_port(startp, &u);
            const char * startp = host_port.startp;
            while (startp[0] != ':') ++startp;
            ++startp;
            update_cursor_nread(&host_port, startp - host_port.startp);
            if (hook_port_run(self, self->hooks, host_port.startp, host_port.len))
            {
                self->error = htparse_error_user;
                return false;
            }
        }

        htp_string_t path = parsed_uri_get_path(startp, &u);
        if (hook_path_run(self, self->hooks, path.startp, path.len))
        {
            self->error = htparse_error_user;
            return false;
        }

        if (parsed_uri_has_query(&u))
        {
            htp_string_t args = parsed_uri_get_query(startp, &u);
            if (hook_args_run(self, self->hooks, args.startp, args.len))
            {
                self->error = htparse_error_user;
                return false;
            }
        }

        if (hook_uri_run(self, self->hooks, uri->startp, uri->len))
        {
            self->error = htparse_error_user;
            return false;
        }
    }

    return true;
}

static inline bool
parse_request_line(htparser * self, const char * startp, const char * endp)
{
    log_debug("(%p, %p, %p)", self, startp, endp);

    request_line_t * request_line = &self->head_line.request_line;

    htp_string_t cursor = {
        .startp = startp,
        .len = endp - startp
    };

    htp_string_t method = parse_method(&cursor);
    htp_method method_num = get_method(&method);
    if (method_num == htp_method_UNKNOWN)
    {
        self->error = htparse_error_inval_method;
        return false;
    }
    request_line->method = method_num;

    if (hook_method_run(self, self->hooks, method.startp, method.len))
    {
        self->error = htparse_error_user;
        return false;
    }

    htp_string_t uri = parse_request_uri(&cursor);
    if (!uri.len)
    {
        self->error = htparse_error_inval_reqline;
        return false;
    }
    if (!consume_uri(self, request_line, &uri))
    {
        log_debug("failed");
        return false;
    }
    request_line->uri = uri;

    htp_string_t ver = parse_protocol_version(&cursor);
    if (!ver.len)
    {
        self->error = htparse_error_inval_ver;
        return false;
    }

    if (!parse_version_number(&ver, &self->major, &self->minor))
    {
        self->error = htparse_error_inval_ver;
        return false;
    }

    return true;
}

static inline bool
parse_status_line(htparser * self, const char * startp, const char * endp)
{
    log_debug("(%p, %p, %p)", self, startp, endp);

    status_line_t * status_line = &self->head_line.status_line;

    htp_string_t cursor = {
        .startp = startp,
        .len = endp - startp
    };

    htp_string_t ver = parse_protocol_version(&cursor);
    if (!ver.len)
    {
        self->error = htparse_error_inval_ver;
        return false;
    }

    if (!parse_version_number(&ver, &self->major, &self->minor))
    {
        self->error = htparse_error_inval_ver;
        return false;
    }

    update_cursor_nread(&cursor, 3);

    unsigned int status_code = parse_status_code(&cursor);
    if (!status_code)
    {
        self->error = htparse_error_status;
        return false;
    }
    status_line->status_code = status_code;

    if (cursor.startp < endp && !isspace(cursor.startp[0]))
    {
        self->error = htparse_error_status;
        return false;
    }

    status_line->status_text = parse_status_text(&cursor);

    return true;
}

static inline bool
parse_head_line(htparser * self, const char * startp, const char * endp)
{
    if (startp == endp)
    {
        ++self->empty_line_count;
        if (self->empty_line_count >= self->config->max_empty_line_count)
        {
            log_debug("maximum empty line limit exceeded");
            self->error = htparse_error_too_big;
            return false;
        }
    }
    return self->type == htp_type_request ?
        parse_request_line(self, startp, endp) :
        parse_status_line(self, startp, endp);
}

static inline int
match_key_name(const char * startp, size_t klen, const char * name, size_t nlen)
{
    if (klen != nlen)
    {
        return 0;
    }

    for (size_t i = 0; i < nlen; i++)
    {
        if ((unsigned char)(startp[i] | 0x20) != (unsigned char)(name[i] | 0x20))
        {
            return 0;
        }
    }

    return 1;
}

static inline bool
consume_header(htparser * self, const htp_string_t * key, const htp_string_t * val)
{
    static const char host_name[] = "Host";
    static const char content_length[] = "Content-length";
    static const char content_type[] = "Content-type";
    static const char transfer_encoding[] = "Transfer-encoding";
    static const char connection[] = "Connection";
    static const char chunked[] = "chunked";
    static const char close[] = "close";
    static const char keep_alive[] = "keep-alive";
    static const char multipart[] = "multipart";

    log_debug("(%p, %p, %p)", self, key, val);

    // Bail out early if this is actually a trailer.
    if (self->state != PARSER_READ_HEADERS)
    {
        log_debug("must be a trailer");
        return true;
    }

    if (hook_hdr_key_run(self, self->hooks, key->startp, key->len))
    {
        self->error = htparse_error_user;
        return false;
    }

    if (!(self->flags & HAVE_HOST) && MATCHES_NAME(key, host_name))
    {
        if (hook_hostname_run(self, self->hooks, val->startp, val->len))
        {
            self->error = htparse_error_user;
            return false;
        }
        self->flags |= HAVE_HOST;
    }
    else if (!(self->flags & HAVE_CONTENT_LENTH) && MATCHES_NAME(key, content_length))
    {
        int err = 0;
        self->content_len = str_to_uint64(val->startp, val->len, &err);
        if (err == 1)
        {
            self->error = htparse_error_too_big;
            return false;
        }
        self->orig_content_len = self->content_len;
        self->flags |= HAVE_CONTENT_LENTH;
    }
    else if (!(self->flags & HAVE_CONTENT_TYPE) && MATCHES_NAME(key, content_type))
    {
        htp_string_t s = *val;
        const char * curp = memchr(s.startp, '/', s.len);
        if (curp)
        {
            log_debug("found slash");
            s.len = curp - s.startp;
        }
        if (MATCHES_NAME(&s, multipart)) self->flags |= IS_MUTLIPART;
    }
    else if (!(self->flags & HAVE_TRANSFER_ENCODING) && MATCHES_NAME(key, transfer_encoding))
    {
        if (MATCHES_NAME(val, chunked)) self->flags |= IS_CHUNKED;
        self->flags |= HAVE_TRANSFER_ENCODING;
    }
    else if (!(self->flags & HAVE_CONNECTION) && MATCHES_NAME(key, connection))
    {
        if (MATCHES_NAME(val, close))
            self->flags |= CONNECTION_CLOSE;
        else if (MATCHES_NAME(val, keep_alive))
            self->flags |= CONNECTION_KEEP_ALIVE;
    }

    if (hook_hdr_val_run(self, self->hooks, val->startp, val->len))
    {
        self->error = htparse_error_user;
        return false;
    }
    return true;
}

static bool
parse_header(htparser * self, const char * startp, const char * endp)
{
    log_debug("(%p, %p, %p)", self, startp, endp);

    if (isblank(startp[0]) && self->header_count > 0)
    {
        if (!self->config->allow_folding)
        {
            log_debug("invalid header folding");
            self->error = htparse_error_inval_hdr;
            return false;
        }
        // Handle folded header line.
    }

    htp_string_t key = parse_header_key(startp, endp);
    if (!key.len || isspace(key.startp[key.len - 1]))
    {
        log_debug("invalid header");
        self->error = htparse_error_inval_hdr;
        return false;
    }

    update_startp(startp, key.len, endp);

    htp_string_t val = parse_header_val(startp, endp);

    if (!consume_header(self, &key, &val))
    {
        log_debug("failed");
        return false;
    }

    return true;
}

static inline long
parse_chunk_size(const char * data, const char * eol)
{
    log_debug("(%p, %p)", data, eol);

    if (data >= eol)
    {
        log_debug("invalid chunk size");
        return -1L;
    }

    unsigned long size = 0UL;

    for (const char * curp = data; curp < eol; ++curp)
    {
        int c = unhex[(unsigned char)curp[0]];

        if (c < 0)
        {
            log_debug("invalid character in chunk size");
            return -1L;
        }

        /* overflow check before shifting */
        if (size > (ULONG_MAX >> 4))
        {
            log_debug("chunk size overflow");
            return -1L;
        }

        size = (size << 4) | (unsigned)c;
    }

    return (long)size;
}

static size_t
parse_chunk_head(htparser * self, chunked_decoder_t * decoder, const char * data, size_t len)
{
    log_debug("(%p, %p, %p, %zu)", self, decoder, data, len);

    htp_string_t cursor = {
        .startp = data,
        .len = len
    };

    if (decoder->end_of_chunk)
    {
        const char * startp = cursor.startp;
        const char * eol = memchr(startp, '\n', cursor.len);
        if (!eol)
        {
            if (cursor.len > 1)
            {
                log_debug("CRLF expected at end of chunk");
                self->error = htparse_error_inval_chunk;
            }
            return 0;
        }
        else if (eol - startp != 1)
        {
            log_debug("CRLF expected at end of chunk (%zu,\"%.*s\")", eol - startp, (int)(eol - startp), startp);
            self->error = htparse_error_inval_chunk;
            return 0;
        }
        else if (eol[-1] != '\r')
        {
            log_debug("CRLF expected at end of chunk");
            self->error = htparse_error_inval_chunk;
            return 0;
        }
        decoder->end_of_chunk = false;
        update_cursor_eol(&cursor, &eol);
    }

    const char * startp = cursor.startp;
    const char * eol = memchr(startp, '\n', cursor.len);
    size_t max_line_length = self->config->max_line_length;

    if (max_line_length > 0 &&
        ((!eol && cursor.len > max_line_length) || (eol && (eol - startp > max_line_length))))
    {
        log_debug("Maximum line length limit exceeded");
        self->error = htparse_error_too_big;
        return len - cursor.len;
    }

    if (!eol)
    {
        log_debug("no end of line");
        return len - cursor.len;
    }

    update_cursor_eol(&cursor, &eol);

    const char * separator = memchr(startp, ';', eol - startp);
    decoder->chunk_size = parse_chunk_size(startp, separator ? separator : eol);
    if (decoder->chunk_size == -1L)
    {
        log_debug("Bad chunk header");
        self->error = htparse_error_inval_chunk_sz;
        return len - cursor.len;
    }

    self->content_len = decoder->chunk_size;

    return len - cursor.len;
}

static size_t
parse_chunked(htparser * self, const char * data, size_t len)
{
    log_debug("(%p, %p, %zu)", self, data, len);

    chunked_decoder_t * decoder = &self->decoder.chunked_decoder;
    htp_string_t cursor = {
        .startp = data,
        .len = len
    };

    while (decoder->state != CHUNKED_COMPLETED)
    {
        switch (decoder->state)
        {
            case CHUNKED_READ_CONTENT:
            {
                if (decoder->chunk_size == -1L)
                {
                    size_t nread = parse_chunk_head(self, decoder, cursor.startp, cursor.len);
                    update_cursor_nread(&cursor, nread);
                    if (decoder->chunk_size == -1L)
                        return len - cursor.len;
                    if (decoder->chunk_size == 0L)
                    {
                        decoder->chunk_size = -1L;
                        decoder->state = CHUNKED_READ_FOOTERS;
                        if (hook_on_chunks_complete_run(self, self->hooks))
                        {
                            self->error = htparse_error_user;
                            return len - cursor.len;
                        }
                        break;
                    }
                    if (hook_on_new_chunk_run(self, self->hooks))
                    {
                        self->error = htparse_error_user;
                        return len - cursor.len;
                    }
                }
                size_t nread = self->content_len > cursor.len ? cursor.len : self->content_len;
                if (nread > 0 &&
                    hook_body_run(self, self->hooks, cursor.startp, nread))
                {
                    self->error = htparse_error_user;
                    return len - cursor.len;
                }
                self->content_len -= nread;
                update_cursor_nread(&cursor, nread);
                if (!self->content_len)
                {
                    decoder->chunk_size = -1L;
                    decoder->end_of_chunk = true;
                    if (hook_on_chunk_complete_run(self, self->hooks))
                    {
                        self->error = htparse_error_user;
                        return len - cursor.len;
                    }
                    break;
                }
                return len - cursor.len;
            }
            case CHUNKED_READ_FOOTERS:
            {
                const char * startp = cursor.startp;
                const char * eol = memchr(startp, '\n', cursor.len);

                if (!eol)
                {
                    log_debug("no eol");
                    return len - cursor.len;
                }
                update_cursor_eol(&cursor, &eol);
                if (eol - startp > 0)
                {
                    size_t max_header_count = self->config->max_header_count;
                    if (max_header_count > 0 && decoder->header_count >= max_header_count)
                    {
                        log_debug("Maximum header count exceeded");
                        self->error = htparse_error_too_big;
                        return len - cursor.len;
                    }
                    if (!parse_header(self, startp, eol))
                    {
                        log_debug("failed");
                        self->error = htparse_error_inval_hdr;
                        return len - cursor.len;
                    }
                }
                else
                {
                    decoder->state = CHUNKED_COMPLETED;
                    //process_footers();
                }
                break;
            }
            default:
                break;
        }
    }

    if (decoder->state == CHUNKED_COMPLETED)
    {
        log_debug("completed");
        self->state = PARSER_COMPLETED;
    }

    return len - cursor.len;
}

static size_t
parse_length(htparser * self, const char * data, size_t len)
{
    log_debug("(%p, %p, %zu)", self, data, len);

    size_t chunk = len > self->content_len ? self->content_len : len;
    log_debug("\"%.*s\"", (int)chunk, data);
    if (chunk > 0 &&
        hook_body_run(self, self->hooks, data, chunk))
    {
        self->error = htparse_error_user;
    }
    self->content_len -= chunk;
    if (!self->content_len)
    {
        log_debug("done");
        self->state = PARSER_COMPLETED;
    }
    else
    {
        log_debug("need %zu more bytes", self->content_len);
    }
    return chunk;
}

static size_t
parse_identity(htparser * self, const char * data, size_t len)
{
    log_debug("(%p, %p, %zu)", self, data, len);

    self->content_len = len;
    if (len > 0 &&
        hook_body_run(self, self->hooks, data, len))
    {
        self->error = htparse_error_user;
    }
    self->content_len = 0;
    return len;
}

static inline bool
is_identity(htparser * self)
{
    log_debug("(%p)", self);
    if (self->type != htp_type_response)
    {
        log_debug("not response");
        return false;
    }
    if (htparser_should_keep_alive(self))
    {
        log_debug("keep-alive conn");
        return false;
    }
    if (!(self->major == 1 && self->minor == 0))
    {
        log_debug("not 1.0");
        return false;
    }
    return true;
}

static inline void
content_length_strategy(htparser * self)
{
    log_debug("(%p)", self);

#ifdef WITH_BULK_TEST
//ONLY FOR BULK TESTING!!!!
self->state = PARSER_COMPLETED;
return;
#endif

    if (self->flags & IS_CHUNKED)
    {
        self->decoder.parse_data = parse_chunked;
        chunked_decoder_init(&self->decoder.chunked_decoder);
    }
    else if (self->content_len > 0)
        self->decoder.parse_data = parse_length;
    else if (is_identity(self))
        self->decoder.parse_data = parse_identity;
    else
        self->state = PARSER_COMPLETED;
}

static size_t
parse_head(htparser * self, htparse_hooks * hooks, const char * data, size_t len)
{
    log_debug("(%p, %p, %p, %zu)", self, hooks, data, len);

    htp_string_t cursor = {
        .startp = data,
        .len = len
    };

    while (self->state != PARSER_HEADERS_COMPLETED)
    {
        const char * startp = cursor.startp;
        const char * eol = memchr(startp, '\n', cursor.len);
        size_t max_line_length = self->config->max_line_length;

        if (max_line_length > 0 &&
            ((!eol && cursor.len > max_line_length) || (eol && (eol - startp > max_line_length))))
        {
            self->error = htparse_error_too_big;
            return len - cursor.len;
        }

        if (!eol)
        {
            log_debug("no end of line");
            return len - cursor.len;
        }

        update_cursor_eol(&cursor, &eol);

        switch (self->state)
        {
            case PARSER_READ_HEAD_LINE:
                if (!parse_head_line(self, startp, eol))
                {
                    log_debug("invalid head line, %d", self->error);
                    return len - cursor.len;
                }
                self->state = PARSER_READ_HEADERS;
                if (hook_on_hdrs_begin_run(self, hooks))
                {
                    self->error = htparse_error_user;
                    return len - cursor.len;
                }
                break;

            case PARSER_READ_HEADERS:
                if ((eol - startp) > 0)
                {
                    if (!parse_header(self, startp, eol))
                    {
                        log_debug("invalid header");
                        return len - cursor.len;
                    }
                }
                else
                {
                    log_debug("done");
                    self->state = PARSER_HEADERS_COMPLETED;
                }
                break;

            default:
                break;
        }
    }

    return len - cursor.len;
}

size_t
htparser_run(htparser * self, htparse_hooks * hooks, const char * data, size_t len)
{
    log_debug("(%p, %p, %p, %zu)", self, hooks, data, len);

    self->hooks = hooks;
    htp_string_t cursor = {
        .startp = data,
        .len = len
    };

    while (1)
    {
        parser_state_e prev_state = self->state;
        size_t nread;

        switch (self->state)
        {
            case PARSER_START:
                self->state = PARSER_READ_HEAD_LINE;
                hook_on_msg_begin_run(self, hooks);
                continue; // Re-evaluate state immediately

            case PARSER_HEADERS_COMPLETED:
                self->state = PARSER_READ_DATA;

                content_length_strategy(self);

                if (hook_on_hdrs_complete_run(self, hooks))
                {
                    self->error = htparse_error_user;
                    self->state = PARSER_ERROR;
                }
                continue;

            case PARSER_COMPLETED:
                if (hook_on_msg_complete_run(self, hooks))
                {
                    self->error = htparse_error_user;
                    self->state = PARSER_ERROR;
                }
                else {
                    self->state = PARSER_RESET;
                }
                continue;

            case PARSER_RESET:
                htparser_reset(self);
                continue;

            case PARSER_ERROR:
                return len - cursor.len;

            case PARSER_READ_DATA:
                // Only enter if we have data
                if (cursor.len == 0) goto exit_loop;
                nread = self->decoder.parse_data(self, cursor.startp, cursor.len);
                break;

            default: // READ_HEAD_LINE, READ_HEADERS
                // Only enter if we have data
                if (cursor.len == 0) goto exit_loop;
                nread = parse_head(self, hooks, cursor.startp, cursor.len);
                break;
        }

        update_cursor_nread(&cursor, nread);

        // Progress check: if we didn't advance state AND didn't consume data,
        // we are blocked
        if (nread == 0 && self->state == prev_state)
            break;
    }

exit_loop:
    return len - cursor.len;
}

int
htparser_should_keep_alive(htparser * self)
{
    log_debug("(%p)", self);
    return self &&
            (self->flags & CONNECTION_KEEP_ALIVE) ||
                ((self->major > 0 && self->minor > 0) && !(self->flags & CONNECTION_CLOSE));
}

void *
htparser_get_userdata(htparser * p)
{
    return p ? p->userdata : NULL;
}

void
htparser_set_userdata(htparser * p, void * ud)
{
    if (p) p->userdata = ud;
}

void
htparser_set_http1config(htparser * p, const htp_http1config_t * config)
{
    if (p) p->config = config;
}

htp_scheme
htparser_get_scheme(htparser * p)
{
    return p ? p->head_line.request_line.scheme : htp_scheme_unknown;
}

htp_method
htparser_get_method(htparser * p)
{
    return p ? p->head_line.request_line.method : htp_method_UNKNOWN;
}

void
htparser_set_method(htparser * p, htp_method meth)
{
    if (p) p->head_line.request_line.method = meth;
}

const char *
htparser_get_methodstr_m(htp_method meth)
{
    return meth < htp_method_UNKNOWN ? method_strmap[meth] : NULL;
}

const char *
htparser_get_methodstr(htparser * p)
{
    return p ? htparser_get_methodstr_m(p->head_line.request_line.method) : NULL;
}

uint64_t
htparser_get_content_pending(htparser * p)
{
    return p ? p->content_len : 0;
}

uint64_t
htparser_get_content_length(htparser * p)
{
    return p ? p->orig_content_len : 0;
}

void
htparser_set_content_length(htparser * p, uint64_t len)
{
    if (p) p->orig_content_len = len;
}

int
htparser_is_chunked(htparser * p)
{
    return p ? !!(p->flags & IS_CHUNKED) : 0;
}

/*
 * No Content-Length and no chunked Transfer-Encoding.
 * For responses this may be an identity (read-until-
 * connection-close) body.  Detect by checking:
 *   - parser type is response
 *   - status code implies a body (not 1xx/204/304)
 *   - connection is not keep-alive (implicit close)
 *     OR Connection: close was explicitly set
 *
 * Mirroring the logic in nodejs/http-parser.
 */
static inline bool
is_identity_response(htparser * p)
{
    return (p->type == htp_type_response
            && p->head_line.status_line.status_code != 0
            && !(p->head_line.status_line.status_code >= 100 && p->head_line.status_line.status_code <= 199)
            && p->head_line.status_line.status_code != 204
            && p->head_line.status_line.status_code != 304
            && !(p->flags & SKIP_BODY));
}

int
htparser_is_identity_response(htparser * p)
{
    return p ? is_identity_response(p) : false;
}

void
htparser_set_major(htparser * p, unsigned char major)
{
    if (p) p->major = major;
}

void
htparser_set_minor(htparser * p, unsigned char minor)
{
    if (p) p->minor = minor;
}

unsigned char
htparser_get_major(htparser * p)
{
    return p ? p->major : 0;
}

unsigned char
htparser_get_minor(htparser * p)
{
    return p ? p->minor : 0;
}

unsigned char
htparser_get_multipart(htparser * p)
{
    return p ? !!(p->flags & IS_MUTLIPART) : 0;
}

htpparse_error
htparser_get_error(htparser * p)
{
    return p ? p->error : htparse_error_user;
}

const char *
htparser_get_strerror(htparser * p)
{
    htpparse_error e = htparser_get_error(p);

    if (e > htparse_error_generic)
    {
        return "htparse_no_such_error";
    }

    return errstr_map[e];
}

unsigned int
htparser_get_status(htparser * p)
{
    return p ? p->head_line.status_line.status_code : 0;
}

void
htparser_set_status(htparser * p, unsigned int status)
{
    if (p) p->head_line.status_line.status_code = status;
}

void
htparser_pause(htparser * p)
{
    if (p) p->flags |= PAUSED;
}

void
htparser_resume(htparser * p)
{
    if (p) p->flags &= ~PAUSED;
}

int
htparser_is_paused(htparser * p)
{
    return p ? !!(p->flags & PAUSED) : 0;
}

/**
 * htparser_set_skip_body - tell the parser to skip body for this message.
 *
 * Must be called after htparser_run() returns for the on_hdrs_complete hook
 * (i.e. before body data arrives).  Typically used for HEAD responses or
 * CONNECT tunnels where the server sends headers but no body.
 */
void
htparser_set_skip_body(htparser * p)
{
    if (p) p->flags |= SKIP_BODY;
}

htp_method
htparser_parse_method(htparser * p, const char * m, const size_t sz)
{
    htp_string_t s = {
        .startp = m,
        .len = sz
    };
    p->head_line.request_line.method = get_method(&s);
    return p->head_line.request_line.method;
}

/**
 * htparser_run_eof - signal EOF (connection close) to the parser.
 *
 * For identity (read-until-close) responses the body length is unknown until
 * the underlying connection is closed by the peer.  The caller must invoke
 * this function after the last htparser_run() call (i.e. when it detects
 * EOF on the socket) so the parser can fire on_body / on_msg_complete for
 * any buffered identity-encoded data.
 *
 * Returns the number of bytes consumed (always 0 on entry, kept for
 * symmetry with htparser_run).
 */
size_t
htparser_run_eof(htparser * p, htparse_hooks * hooks)
{
    int res = 0;

    p->error = htparse_error_none;

    if (p->decoder.parse_data != parse_identity)
    {
        log_debug("not identity");
    }
    else if (hook_on_msg_complete_run(p, hooks))
    {
        p->error = htparse_error_user;
    }
    return 0;
}


//#define WITH_HTPARSER_TEST
#ifdef WITH_HTPARSER_TEST
static int
htp__request_parse_start_(htparser * p)
{
    log_debug("(%p)", p);
    return 0;
}

static int
htp__request_parse_scheme_(htparser * p, const char * data, size_t len)
{
    log_debug("(%p, %p(%.*s), %zu)", p, data, (int)len, data, len);
    return 0;
}

static int
htp__request_parse_host_(htparser * p, const char * data, size_t len)
{
    log_debug("(%p, %p(%.*s), %zu)", p, data, (int)len, data, len);
    return 0;
}

static int
htp__request_parse_port_(htparser * p, const char * data, size_t len)
{
    log_debug("(%p, %p(%.*s), %zu)", p, data, (int)len, data, len);
    return 0;
}

static int
htp__request_parse_path_(htparser * p, const char * data, size_t len)
{
    log_debug("(%p, %p(%.*s), %zu)", p, data, (int)len, data, len);
    return 0;
}     /* htp__request_parse_path_ */

static int
htp__request_parse_args_(htparser * p, const char * data, size_t len)
{
    log_debug("(%p, %p(%.*s), %zu)", p, data, (int)len, data, len);
    return 0;
}     /* htp__request_parse_args_ */

static int
htp__request_parse_uri_(htparser * p, const char * data, size_t len)
{
    log_debug("(%p, %p(%.*s), %zu)", p, data, (int)len, data, len);
    return 0;
}     /* htp__request_parse_uri_ */

static int
htp__request_parse_method_(htparser * p, const char * data, size_t len)
{
    log_debug("(%p, %p(%.*s), %zu)", p, data, (int)len, data, len);
    return 0;
}

static int
htp__request_parse_headers_start_(htparser * p)
{
    log_debug("(%p)", p);

    request_line_t * r = &p->head_line.request_line;
    log_debug("\"%s\", \"%.*s\", HTTP/%d.%d", htparser_get_methodstr_m(r->method), (int)r->uri.len, r->uri.startp, p->major, p->minor);
    return 0;
}

static int
htp__response_parse_headers_start_(htparser * p)
{
    log_debug("(%p)", p);

    status_line_t * s = &p->head_line.status_line;
    log_debug("HTTP/%d.%d %d \"%.*s\"", p->major, p->minor, s->status_code, (int)s->status_text.len, s->status_text.startp);
    return 0;
}

static int
htp__request_parse_header_key_(htparser * p, const char * data, size_t len)
{
    log_debug("(%p, %p(%.*s), %zu)", p, data, (int)len, data, len);
    return 0;
}

static int
htp__request_parse_header_val_(htparser * p, const char * data, size_t len)
{
    log_debug("(%p, %p(%.*s), %zu)", p, data, (int)len, data, len);
    return 0;
}

static int
htp__request_parse_headers_(htparser * p)
{
    log_debug("(%p)", p);
    return 0;
}

static int
htp__request_parse_hostname_(htparser * p, const char * data, size_t len)
{
    log_debug("(%p, %p(%.*s), %zu)", p, data, (int)len, data, len);
    return 0;
} /* htp__request_parse_hostname_ */

static int
htp__request_parse_body_(htparser * p, const char * data, size_t len)
{
    log_debug("(%p, %p(%.*s), %zu)", p, data, (int)len, data, len);
log_debug("content len %zu", p->content_len);
    return 0;
}

static int
htp__request_parse_chunk_new_(htparser * p)
{
    log_debug("(%p)", p);
    return 0;
}

static int
htp__request_parse_chunk_fini_(htparser * p)
{
    log_debug("(%p)", p);
    return 0;
}

static long num_chunked = 0;

static int
htp__request_parse_chunks_fini_(htparser * p)
{
    log_debug("(%p)", p);
++num_chunked;
    return 0;
}

static long num_parsed = 0L;

static int
htp__request_parse_fini_(htparser * p)
{
++num_parsed;
    log_debug("(%p) %ld", p, num_parsed);
    return 0;
} /* htp__request_parse_fini_ */

static htparse_hooks request_psets = {
    .on_msg_begin       = htp__request_parse_start_,
    .method             = htp__request_parse_method_,
    .scheme             = htp__request_parse_scheme_,
    .host               = htp__request_parse_host_,
    .port               = htp__request_parse_port_,
    .path               = htp__request_parse_path_,
    .args               = htp__request_parse_args_,
    .uri                = htp__request_parse_uri_,
    .on_hdrs_begin      = htp__request_parse_headers_start_,
    .hdr_key            = htp__request_parse_header_key_,
    .hdr_val            = htp__request_parse_header_val_,
    .hostname           = htp__request_parse_hostname_,
    .on_hdrs_complete   = htp__request_parse_headers_,
    .on_new_chunk       = htp__request_parse_chunk_new_,
    .on_chunk_complete  = htp__request_parse_chunk_fini_,
    .on_chunks_complete = htp__request_parse_chunks_fini_,
    .body               = htp__request_parse_body_,
    .on_msg_complete    = htp__request_parse_fini_
};
static htparse_hooks response_psets = {
    .on_msg_begin       = htp__request_parse_start_,
    .method             = NULL,
    .scheme             = NULL,
    .host               = NULL,
    .port               = NULL,
    .path               = NULL,
    .args               = NULL,
    .uri                = NULL,
    .on_hdrs_begin      = htp__response_parse_headers_start_,
    .hdr_key            = htp__request_parse_header_key_,
    .hdr_val            = htp__request_parse_header_val_,
    .hostname           = htp__request_parse_hostname_,
    .on_hdrs_complete   = htp__request_parse_headers_,
    .on_new_chunk       = htp__request_parse_chunk_new_,
    .on_chunk_complete  = htp__request_parse_chunk_fini_,
    .on_chunks_complete = htp__request_parse_chunks_fini_,
    .body               = htp__request_parse_body_,
    .on_msg_complete    = htp__request_parse_fini_
};

#define TO_MSECS(u) ((u) / 1000)
#define TO_SECS(u) (TO_MSECS(u) / 1000)

static int64_t
get_monotonic_time_usec(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    {
        return -1; /* or handle error as appropriate */
    }

    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static void
test_request_parsing(htparser * parser)
{
    log_debug("(%p)", parser);

#ifndef WITH_BULK_TEST
    static const char msg[] =
        "POST /test-chunked-php/abc?abc=123 HTTP/1.1\r\n"
        "Content-type: text/plain\r\n"
        "Transfer-encoding: chunked\r\n"
        "\r\n"
        "7\r\n"
        "Welcome\r\n"
        "1c\r\n"
        "to Mozilla Developer Network\r\n"
        "0\r\n"
        "\r\n"
        "POST /this/is/the/path?this=is&the=query HTTP/1.1\r\n"
        "Host: www.thehost.com\r\n"
        "Content-length: 10\r\n"
        "\r\n"
        "12345=6789"
        "GET http://www.thehost.com:8080/images/test-image.gif?abc=123 HTTP/1.1\r\n"
        "Host: www.thehost.com\r\n"
        "\r\n"
        "GET /images/test-image-2.gif HTTP/1.1\r\n"
        "Host: www.thehost.com\r\n"
        "Accept: image/gif\r\n"
        "\r\n"
    ;

    const char * curp = msg;
    size_t len = sizeof(msg) - 1;
    size_t avail = 1; // Read msg[] one byte at a time to test all boundaries.
//    size_t avail = len; // Read msg[] in one pass to test pipelining.
    int64_t start_us = get_monotonic_time_usec();

    htparser_init(parser, htp_type_request);

    while (len > 0)
    {
        size_t nread = htparser_run(parser, &request_psets, curp, avail);
        log_debug("read %zu of %zu bytes", nread, avail);
        if (parser->error != htparse_error_none)
        {
            log_debug("failed");
            break;
        }
        avail -= nread;
        if (nread == 0 || avail == 0) ++avail;
        len -= nread;
        curp += nread;
    }

    int64_t total_us = get_monotonic_time_usec() - start_us;

    evhtp_assert(len == 0L);
    evhtp_assert(num_parsed == 4L);
    evhtp_assert(num_chunked == 1L);

    printf("parsed %ld requests, %zu chunked\n", num_parsed, num_chunked);
    printf("%ld usecs\n", total_us);
    printf("%.3f/us\n", (double)num_parsed/total_us);
    printf("%.3f/ms\n", (double)num_parsed/TO_MSECS((double)total_us));
    printf("%.3f/s\n\n", (double)num_parsed/TO_SECS((double)total_us));

#else

    FILE * fp = fopen("/home/parallels/projects/RProxy-htm8/tmp/requests_only.log", "rt");
    char buf[parser->config->max_line_length * 2];
    size_t bufsize = sizeof(buf);
    char * bufp = buf;
    char * readp = buf;
    char * endp = buf + bufsize;
    size_t readlen = bufsize;

    int64_t start_us = get_monotonic_time_usec();

    size_t avail;
    while ((avail = fread(bufp, 1, readlen, fp)) > 0)
    {
//        log_debug("avail %zu\n\"%.*s\"", avail, (int)avail, buf);

        avail += bufp - buf;
        bufp = buf;

        // htparser_run() will consume all bytes it can use to move forward.
        // It will not return until it has consumed all useable bytes.
        size_t nread = htparser_run(parser, &request_psets, buf, avail);
        log_debug("read %zu of %zu bytes", nread, avail);
        if (parser->error != htparse_error_none)
        {
            log_debug("failed");
            break;
        }

        avail -= nread;
        bufp += nread;

        memmove(buf, bufp, avail);
        bufp = buf + avail;
        readlen = bufsize - avail;
    }

    int64_t total_us = get_monotonic_time_usec() - start_us;

    if (feof(fp))
    {
        printf("read entire file\n");
        printf("parsed %ld requests\n", num_parsed);
    }

    printf("%ld usecs\n", total_us);
    printf("%.3f/us\n", (double)num_parsed/total_us);
    printf("%.3f/ms\n", (double)num_parsed/TO_MSECS((double)total_us));
    printf("%.3f/s\n\n", (double)num_parsed/TO_SECS((double)total_us));

    fclose(fp);

#endif//WITH_BULK_TEST
}

static void
test_response_parsing(htparser * parser)
{
    log_debug("(%p)", parser);
    static const char msg[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-type: text/html\r\n"
        "Transfer-encoding: chunked\r\n"
        "\r\n"
        "8\r\n"
        "<Welcome\r\n"
        "1c\r\n"
        "to>Mozilla Developer Network\r\n"
        "0\r\n"
        "\r\n"
        "HTTP/1.1 200 OK\r\n"
        "Content-type: text/plain\r\n"
        "Content-length: 10\r\n"
        "\r\n"
        "1234567890"
    ;
    const char * curp = msg;
    size_t len = sizeof(msg) - 1;
    size_t avail = 84/*1*/;
//size_t avail = len;
    htparser_init(parser, htp_type_response);
    while (len > 0)
    {
        size_t nread = htparser_run(parser, &response_psets, curp, avail);
        log_debug("read %zu of %zu bytes", nread, avail);
        if (parser->error != htparse_error_none)
        {
            log_debug("failed");
            break;
        }
        avail -= nread;
        if (nread == 0 || avail == 0)
        {
//            ++avail; // 1 byte at a time.
            avail += 9; // arbitrary.
            if (avail > len) avail = len;
        }
        len -= nread;
        curp += nread;
    }

    evhtp_assert(len == 0);
    evhtp_assert(parser->error == htparse_error_none);
}

int main(int argc, char ** argv)
{
    htparser * parser = htparser_new();
log_debug("parser %p, %zu bytes", parser, sizeof(*parser));
    test_request_parsing(parser);
#ifndef WITH_BULK_TEST
    test_response_parsing(parser);
#endif
    htparser_free(parser);
    log_debug("done");
    return 0;
}
#endif//WITH_HTPARSER_TEST
