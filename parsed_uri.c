
#include <string.h>
#include "evhtp/parsed_uri.h"

#define SET_FIELD(view, id, start_ptr, end_ptr, base_ptr) \
do { \
    (view)->fields[(id)].off = (uint16_t)((start_ptr) - (base_ptr)); \
    (view)->fields[(id)].len = (uint16_t)((end_ptr) - (start_ptr));  \
} while(0)

static inline bool
parse_uri_view_internal(const char *url, size_t len, struct parsed_uri *out)
{
    if (__builtin_expect(url == NULL || len == 0 || len > 65535, 0))
        return false;

    memset(out, 0, sizeof(*out));
    const char *p = url;
    const char *end = url + len;

    // =========================================================================
    // PHASE 1: Scheme (scan for ':' before '/', '?', or '#')
    // =========================================================================
    const char *colon = memchr(p, ':', len);
    const char *slash = memchr(p, '/', len);
    const char *qmark = memchr(p, '?', len);

    // If ':' comes before '/', '?', and '#', it's a valid scheme
    if (colon && (!slash || colon < slash) && (!qmark || colon < qmark))
    {
        SET_FIELD(out, URI_SCHEME, p, colon, url);
        out->flags |= URI_HAS_SCHEME;
        p = colon + 1; // Advance past ':'
    }

    // =========================================================================
    // PHASE 2: Authority (starts with "//")
    // =========================================================================
    if ((end - p) >= 2 && p[0] == '/' && p[1] == '/')
    {
        p += 2;
        const char *auth_start = p;
        // Authority ends at next '/', '?', '#', or end of string
        const char *auth_end = p;
        while (auth_end < end && *auth_end != '/' && *auth_end != '?' && *auth_end != '#')
        {
            auth_end++;
        }

        const char *cursor = auth_start;

        // 2a. Userinfo check (look for '@' inside authority)
        const char *at = memchr(cursor, '@', (size_t)(auth_end - cursor));
        if (at)
        {
            SET_FIELD(out, URI_USERINFO, cursor, at, url);
            out->flags |= URI_HAS_USERINFO;
            cursor = at + 1;
        }

        // 2b. Host & Port (Handle IPv6 "[...]" or standard host:port)
        if (cursor < auth_end && *cursor == '[')
        {
            // IPv6 host
            const char *close_bracket = memchr(cursor, ']', (size_t)(auth_end - cursor));
            if (!close_bracket) return false; // Malformed IPv6
            SET_FIELD(out, URI_HOST, cursor + 1, close_bracket, url);
            out->flags |= URI_IS_IPV6;
            out->flags |= URI_HAS_HOST;
            cursor = close_bracket + 1;
        }
        else
        {
            // IPv4 or DNS Host (find optional ':')
            const char *port_sep = memchr(cursor, ':', (size_t)(auth_end - cursor));
            const char *host_end = port_sep ? port_sep : auth_end;
            SET_FIELD(out, URI_HOST, cursor, host_end, url);
            out->flags |= URI_HAS_HOST;
            cursor = host_end;
        }

        // 2c. Port parsing
        if (cursor < auth_end && *cursor == ':')
        {
            cursor++;
            SET_FIELD(out, URI_PORT, cursor, auth_end, url);
            out->flags |= URI_HAS_PORT;

            // Fast integer conversion for port
            uint32_t port = 0;
            for (const char *d = cursor; d < auth_end; d++)
            {
                if (*d < '0' || *d > '9') return false; // Invalid port char
                port = port * 10 + (uint32_t)(*d - '0');
            }
            if (port > 65535) return false;
            out->port_num = (uint16_t)port;
        }

        p = auth_end;
    }

    // =========================================================================
    // PHASE 3: Path (runs until '?' or '#')
    // =========================================================================
    const char *path_start = p;
    while (p < end && *p != '?' && *p != '#') p++;
    SET_FIELD(out, URI_PATH, path_start, p, url);
    out->flags |= URI_HAS_PATH;

    // =========================================================================
    // PHASE 4: Query (runs from '?' until '#')
    // =========================================================================
    if (p < end && *p == '?')
    {
        p++; // Skip '?'
        const char *query_start = p;
        while (p < end && *p != '#') p++;
        SET_FIELD(out, URI_QUERY, query_start, p, url);
        out->flags |= URI_HAS_QUERY;
    }

    // =========================================================================
    // PHASE 5: Fragment (everything after '#')
    // =========================================================================
    if (p < end && *p == '#')
    {
        p++; // Skip '#'
        SET_FIELD(out, URI_FRAGMENT, p, end, url);
        out->flags |= URI_HAS_FRAGMENT;
    }

    return true;
}

htp_string_t
parsed_uri_get_authority(const char* p, const struct parsed_uri* u)
{
    htp_string_t rval = {
        .startp = p,
        .len = 0
    };

    if (__builtin_expect(p == NULL || u == NULL, 0))
        return rval;

    if (parsed_uri_has_user_info(u))
    {
        rval = parsed_uri_get_user_info(p, u);
        ++rval.len; // include '@'
        if (rval.startp[rval.len] == '[')
            rval.len += 2;
        rval.len += u->fields[URI_HOST].len;
    }
    else
    {
        rval = parsed_uri_get_host(p, u);
        if (rval.startp[-1] == '[')
        {
            --rval.startp;
            rval.len += 2;
        }
    }

    if (parsed_uri_has_port(u))
    {
        ++rval.len; // include ':'
        rval.len += u->fields[URI_PORT].len;
    }

    return rval;
}

// Get the "host" and optional "port" component of the uri (host[:port]).
htp_string_t
parsed_uri_get_host_port(const char* p, const struct parsed_uri* u)
{
    htp_string_t rval = {
        .startp = p,
        .len = 0
    };

    if (__builtin_expect(p == NULL || u == NULL, 0))
        return rval;

    rval = parsed_uri_get_host(p, u);
    if (rval.startp[-1] == '[')
    {
        --rval.startp;
        rval.len += 2;
    }

    if (parsed_uri_has_port(u))
    {
        ++rval.len; // include ':'
        rval.len += u->fields[URI_PORT].len;
    }

    return rval;
}

static char *
append_field(const htp_string_t* field, char * dest)
{
    if (field->len)
    {
        memcpy(dest, field->startp, field->len);
        return dest + field->len;
    }
    return dest;
}

char*
parsed_uri_join(const htp_string_t scheme, const htp_string_t userinfo, const htp_string_t host_port,
                const htp_string_t path, const htp_string_t query, const htp_string_t fragment)
{
    htp_string_t scheme_sep = {
        .startp = "://",
        .len = 3
    };
    htp_string_t userinfo_sep = {
        .startp = "@",
        .len = userinfo.len ? 1 : 0
    };
    htp_string_t query_sep = {
        .startp = "?",
        .len = query.len ? 1 : 0
    };
    htp_string_t frag_sep = {
        .startp = "#",
        .len = fragment.len ? 1 : 0
    };
    size_t len = scheme.len + scheme_sep.len +
                    userinfo.len + userinfo_sep.len +
                    host_port.len + path.len +
                    query_sep.len + query.len +
                    frag_sep.len + fragment.len;
    char* rval = malloc(++len);
    if (rval)
    {
        char * dest = append_field(&scheme, rval);
        dest = append_field(&scheme_sep, dest);
        dest = append_field(&userinfo, dest);
        dest = append_field(&userinfo_sep, dest);
        dest = append_field(&host_port, dest);
        dest = append_field(&path, dest);
        dest = append_field(&query_sep, dest);
        dest = append_field(&query, dest);
        dest = append_field(&frag_sep, dest);
        dest = append_field(&fragment, dest);
        *dest = '\0';
    }
    return rval;
}

char*
parsed_uri_to_cstr(const char* p, const struct parsed_uri* u)
{
    if (__builtin_expect(p == NULL || u == NULL, 0))
        return NULL;

    return parsed_uri_join(parsed_uri_get_scheme(p, u),
                            parsed_uri_get_user_info(p, u),
                            parsed_uri_get_host_port(p, u),
                            parsed_uri_get_path(p, u),
                            parsed_uri_get_query(p, u),
                            parsed_uri_get_fragment(p, u));
}

struct parsed_uri
parse_uri_view(const htp_string_t uri_string)
{
    struct parsed_uri out = {0};
    if (!parse_uri_view_internal(uri_string.startp, uri_string.len, &out))
        out.flags |= URI_HAS_ERROR;
    return out;
}
