
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct htp_string htp_string_t;
struct htp_string {
    const char * startp;
    size_t len;
};

typedef struct uri_field_data uri_field_data_t;
struct uri_field_data {
    uint16_t off;
    uint16_t len;
};

enum url_fields {
    URI_SCHEME = 0,
    URI_USERINFO,
    URI_HOST,
    URI_PORT,
    URI_PATH,
    URI_QUERY,
    URI_FRAGMENT,
    URI_FIELD_COUNT
};

struct parsed_uri {
    uri_field_data_t fields[URI_FIELD_COUNT];
    uint16_t port_num;
    #define URI_HAS_SCHEME        (1u << 0)
    #define URI_HAS_USERINFO      (1u << 1)
    #define URI_HAS_HOST          (1u << 2)
    #define URI_HAS_PORT          (1u << 3)
    #define URI_HAS_PATH          (1u << 4)
    #define URI_HAS_QUERY         (1u << 5)
    #define URI_HAS_FRAGMENT      (1u << 6)
    #define URI_HAS_ERROR         (1u << 7)
    #define URI_IS_IPV6           (1u << 8)
    #define URI_IS_AUTHORITY_FORM (1u << 9)
    uint16_t flags;
};

struct parsed_uri parse_uri_view(const htp_string_t uri_string, bool is_connect);

/**
 * Get the |authority| (section that comes after the scheme and before the path.
 * It may have up to three parts: user information, host, and port:
 *
 * [userinfo@]host[:port]
 */
htp_string_t parsed_uri_get_authority(const char* p,
                                        const struct parsed_uri* u);

/**
 * Get the "host" and optional "port" component of the uri:
 *
 * host[:port]
 */
htp_string_t parsed_uri_get_host_port(const char* p,
                                                const struct parsed_uri* u);
char* parsed_uri_join(const htp_string_t scheme,
                        const htp_string_t userinfo,
                        const htp_string_t host_port,
                        const htp_string_t path,
                        const htp_string_t query,
                        const htp_string_t fragment);
char* parsed_uri_to_cstr(const char* p, const struct parsed_uri* u);

static inline bool
parsed_uri_has_scheme(const struct parsed_uri* u)
{
    return u ? !!(u->flags & URI_HAS_SCHEME) : false;
}

static inline bool
parsed_uri_has_host(const struct parsed_uri* u)
{
    return u ? !!(u->flags & URI_HAS_HOST) : false;
}

static inline bool
parsed_uri_has_port(const struct parsed_uri* u)
{
    return u ? !!(u->flags & URI_HAS_PORT) : false;
}

static inline bool
parsed_uri_has_user_info(const struct parsed_uri* u)
{
    return u ? !!(u->flags & URI_HAS_USERINFO) : false;
}

static inline bool
parsed_uri_has_path(const struct parsed_uri* u)
{
    return u ? !!(u->flags & URI_HAS_PATH) : false;
}

static inline bool
parsed_uri_has_query(const struct parsed_uri* u)
{
    return u ? !!(u->flags & URI_HAS_QUERY) : false;
}

static inline bool
parsed_uri_has_fragment(const struct parsed_uri* u)
{
    return u ? !!(u->flags & URI_HAS_FRAGMENT) : false;
}

static inline bool
parsed_uri_has_error(const struct parsed_uri* u)
{
    return u ? !!(u->flags & URI_HAS_ERROR) : false;
}

static inline bool
parsed_uri_is_authority_form(const struct parsed_uri* u)
{
    return u ? !!(u->flags & URI_IS_AUTHORITY_FORM) : false;
}

static inline htp_string_t
parsed_uri_get_scheme(const char* p, const struct parsed_uri* u)
{
    htp_string_t rval = {
        .startp = p,
        .len = 0
    };
    if (p && parsed_uri_has_scheme(u))
    {
        rval.startp = p + u->fields[URI_SCHEME].off;
        rval.len = u->fields[URI_SCHEME].len;
    }
    return rval;
}

/**
 * Get the host name component (name or IP address) - NOT including the port.
 */
static inline htp_string_t
parsed_uri_get_host(const char* p, const struct parsed_uri* u)
{
    htp_string_t rval = {
        .startp = p,
        .len = 0
    };
    if (p)
    {
        rval.startp = p + u->fields[URI_HOST].off;
        rval.len = u->fields[URI_HOST].len;
    }
    return rval;
}

static inline int
parsed_uri_get_port(const char* p, const struct parsed_uri* u)
{
    return parsed_uri_has_port(u) ? (int)u->port_num : -1;
}

static inline htp_string_t
parsed_uri_get_user_info(const char* p, const struct parsed_uri* u)
{
    htp_string_t rval = {
        .startp = p,
        .len = 0
    };
    if (p && parsed_uri_has_user_info(u))
    {
        rval.startp = p + u->fields[URI_USERINFO].off;
        rval.len = u->fields[URI_USERINFO].len;
    }
    return rval;
}

static inline htp_string_t
parsed_uri_get_path(const char* p, const struct parsed_uri* u)
{
    htp_string_t rval = {
        .startp = p,
        .len = 0
    };
    if (p && parsed_uri_has_path(u))
    {
        rval.startp = p + u->fields[URI_PATH].off;
        rval.len = u->fields[URI_PATH].len;
    }
    return rval;
}

static inline htp_string_t
parsed_uri_get_query(const char* p, const struct parsed_uri* u)
{
    htp_string_t rval = {
        .startp = p,
        .len = 0
    };
    if (p && parsed_uri_has_query(u))
    {
        rval.startp = p + u->fields[URI_QUERY].off;
        rval.len = u->fields[URI_QUERY].len;
    }
    return rval;
}

static inline htp_string_t
parsed_uri_get_fragment(const char* p, const struct parsed_uri* u)
{
    htp_string_t rval = {
        .startp = p,
        .len = 0
    };
    if (p && parsed_uri_has_fragment(u))
    {
        rval.startp = p + u->fields[URI_FRAGMENT].off;
        rval.len = u->fields[URI_FRAGMENT].len;
    }
    return rval;
}
