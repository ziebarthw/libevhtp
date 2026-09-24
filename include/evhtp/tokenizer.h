
#pragma once

#include <stdio.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "evhtp/string.h"

typedef struct ht_delim_policy ht_delim_policy_t;
struct ht_delim_policy {
    unsigned char map[256];
    char single_delim;
    bool is_single;
};

static inline struct ht_delim_policy
ht_delim_policy_ctor(const char * delims)
{
    struct ht_delim_policy self = {0};
    memset(&self.map, 0, sizeof(self.map));
    if (delims[0] != '\0' && delims[1] == '\0') {
        self.is_single = true;
        self.single_delim = delims[0];
    }
    else {
        self.is_single = false;
        for (const char * curp = delims; curp[0]; ++curp) {
            self.map[(unsigned char)curp[0]] = 1;
        }
    }
    return self;
}

typedef struct httokenizer httokenizer_t;
struct httokenizer {
    htstring_t remaining;
    char last_delim; // Stores delimited that ended the last token.
};

/* Initialize with a string of delimiters (e.g., ";,") */
static inline void
httokenizer_init(httokenizer_t * t, htstring_t input/*, const char * delims*/)
{
    t->remaining = input;
    t->last_delim = 0;
}

static inline httokenizer_t
httokenizer_ctor(htstring_t input/*, const char * delims*/)
{
    httokenizer_t t;
    httokenizer_init(&t, input/*, delims*/);
    return t;
}

/* Returns true if a token was found, false if exhausted */
static inline bool
httokenizer_next(httokenizer_t * t, const ht_delim_policy_t * policy, htstring_t * out)
{
    htstring_ltrim(&t->remaining);

    if (t->remaining.len == 0) {
        t->last_delim = 0;
        return false;
    }

    const char * startp = t->remaining.startp;
    const char * hit = NULL;

    if (policy->is_single) {
        hit = (const char*)memchr(startp, policy->single_delim, t->remaining.len);
        if (hit) t->last_delim = policy->single_delim;
    } else {
        /* Map-based scan */
        for (size_t i = 0; i < t->remaining.len; ++i) {
            if (policy->map[(unsigned char)startp[i]]) {
                hit = &startp[i];
                t->last_delim = startp[i]; // Capture the specific delim.
                break;
            }
        }
    }

    size_t token_len;
    if (hit) {
        token_len = (size_t)(hit - startp);
    }
    else {
        token_len = t->remaining.len;
        t->last_delim = 0;
    }

    out->startp = startp;
    out->len = token_len;

//    htstring_rtrim(out);

    if (hit) {
        /* Advance remaining: skip the token AND the delimiter */
        size_t consumed = (size_t)(hit - startp) + 1;
        t->remaining.startp += consumed;
        t->remaining.len -= consumed;
    } else {
        /* Last token (no delimiter found) */
        t->remaining.startp += t->remaining.len;
        t->remaining.len = 0;
        t->last_delim = 0;
    }

    return true;
}

static inline char
httokenizer_get_last_delim(httokenizer_t * t)
{
    return t ? t->last_delim : 0;
}

#define HT_MAX_PARAMS 16

typedef struct {
    htstring_t name;
    htstring_t value; /* value.data == NULL if bare token, no '=' */
} ht_kv_t;

typedef struct {
    htstring_t name;  /* primary value, e.g. "Google Chrome" (or quoted form) */
    ht_kv_t params[HT_MAX_PARAMS];
    size_t param_count;
} ht_element_t;

static inline htstring_t
ht_element_get_parameter_by_name(const ht_element_t * self, const htstring_t name)
{
    if (self)
    {
        for (size_t i = 0; i < self->param_count; ++i)
        {
            if (htstring_equalsi(self->params[i].name, name))
                return self->params[i].value;
        }
    }
    return (htstring_t){
        .startp = "",
        .len = 0
    };
}

/* Callback signature for the user to process the parsed element */
typedef int (*element_handler_t)(ht_element_t *element, void *ctx);

bool parse_parameterized_header(htstring_t header_value, element_handler_t handler, void * ctx);

typedef struct { httokenizer_t tok; } ht_param_iter_t;

static inline void
ht_param_iter_init(ht_param_iter_t *it, htstring_t item)
{
    httokenizer_init(&it->tok, item);
}

static inline ht_param_iter_t
ht_param_iter_ctor(htstring_t item)
{
    ht_param_iter_t it;
    ht_param_iter_init(&it, item);
    return it;
}

/* Pre-defined policies for performance */
static const ht_delim_policy_t p_comma = { .is_single = true, .single_delim = ',' };
static const ht_delim_policy_t p_semi  = { .is_single = true, .single_delim = ';' };
static const ht_delim_policy_t p_eq    = { .is_single = true, .single_delim = '=' };

static inline bool
ht_param_iter_next(ht_param_iter_t * it, htstring_t * key, htstring_t * val)
{
    htstring_t part;
    if (!httokenizer_next(&it->tok, &p_eq, &part))
        return false;

    const char * eq = memchr(part.startp, '=', part.len);
    if (!eq) {            /* bare token, no value */
        *key = part;
        val->startp = NULL;
        return true;
    }
    key->startp = part.startp;
    key->len = (size_t)(eq - part.startp);
    val->startp = eq + 1;
    val->len = part.len - key->len - 1;
    return true;
}

/* element-level: iterate comma list, expose the first segment as the
 * name and let the caller open a param iterator over the rest */
typedef struct { httokenizer_t tok; } ht_element_iter_t;

static inline void
ht_element_iter_init(ht_element_iter_t * it, htstring_t header_value)
{
    httokenizer_init(&it->tok, header_value);
    /* pre-condition: header_value points at the bytes AFTER "Header-Name:",
     * already stripped of the leading space. trimming inside the tokenizer
     * handles the rest. */
}

static inline ht_element_iter_t
ht_element_iter_ctor(htstring_t header_value)
{
    ht_element_iter_t it;
    ht_element_iter_init(&it, header_value);
    return it;
}

static inline bool
ht_element_iter_next(ht_element_iter_t * it, ht_element_t * el)
{
    /* --- level 1: comma-separated elements --- */
    htstring_t item;
    if (!httokenizer_next(&it->tok, &p_comma, &item))
        return false;                       /* list exhausted */

    /* --- level 2: within an element, semicolon splits name from params --- */
    httokenizer_t tseg = httokenizer_ctor(item);

    htstring_t seg;
    if (!httokenizer_next(&tseg, &p_semi, &seg)) {
        /* element was empty/whitespace-only, e.g. "a, , b" — treat as
         * malformed rather than fabricating an empty-name element */
        el->name.startp = NULL;
        el->name.len    = 0;
        el->param_count = 0;
        return true;                        /* caller inspects and decides */
    }
    el->name = seg;
    el->param_count = 0;

    /* --- level 3: each remaining segment is k=v or bare token --- */
    while (httokenizer_next(&tseg, &p_semi, &seg))
    {
        if (!(el->param_count < HT_MAX_PARAMS)) {
            return false;
        }

        ht_kv_t * kv = &el->params[el->param_count];

        const char * eq = memchr(seg.startp, '=', seg.len);
        if (eq) {
            kv->name.startp  = seg.startp;
            kv->name.len     = (size_t)(eq - seg.startp);
            kv->value.startp = eq + 1;
            kv->value.len    = seg.len - kv->name.len - 1;
        } else {
            kv->name         = seg;                /* e.g. "secure"-style flag */
            kv->value.startp = NULL;
            kv->value.len    = 0;
        }
        el->param_count++;
    }
    /* If there were more than HT_MAX_PARAMS segments, the while stopped
     * early and the remainder of THIS element is silently dropped.
     * The iterator itself stays valid — the next call resumes at the
     * next comma-separated element. For a security proxy you may prefer
     * to signal truncation; see note below. */
    return true;
}

typedef struct {
    htstring_t name;    /* "expires", "path", "secure", ... */
    htstring_t value;   /* may be empty for flag attributes */
    bool has_value;
} ht_cookie_av_t;

typedef struct {
    htstring_t name;    /* "_fbp" */
    htstring_t value;   /* "fb.1.1...AQECAQIB" */
    ht_cookie_av_t attrs[HT_MAX_PARAMS];
    size_t attr_count;
} ht_cookie_t;

typedef int (*cookie_handler_t)(const ht_cookie_t *, void *);

bool parse_set_cookie(htstring_t value, cookie_handler_t handler, void * ctx);

typedef struct {
    htstring_t name;
    htstring_t value;   /* empty string if component had no '=' */
} ht_cookie_pair_t;

typedef int (*cookie_pair_handler_t)(const ht_cookie_pair_t * pair, void * ctx);

bool parse_cookie(htstring_t value, cookie_pair_handler_t handler, void * ctx);

typedef struct {
    httokenizer_t tok;        /* the whole iterator is the tokenizer + nothing */
} ht_cookie_iter_t;

static inline void
ht_cookie_iter_init(ht_cookie_iter_t * it, htstring_t value)
{
    httokenizer_init(&it->tok, value);
}

static inline ht_cookie_iter_t
ht_cookie_iter_ctor(htstring_t value)
{
    ht_cookie_iter_t it;
    ht_cookie_iter_init(&it, value);
    return it;
}

/* Returns true and fills *out; returns false when the header is exhausted.
 * If the component had no '=', out->value.data is NULL. */
static inline bool
ht_cookie_iter_next(ht_cookie_iter_t * it, ht_cookie_pair_t * out)
{
    htstring_t part;
    if (!httokenizer_next(&it->tok, &p_semi, &part))
        return false;

    const char * eq = memchr(part.startp, '=', part.len);
    if (eq) {
        out->name.startp  = part.startp;
        out->name.len     = (size_t)(eq - part.startp);
        out->value.startp = eq + 1;
        out->value.len    = part.len - out->name.len - 1;
    } else {
        out->name         = part;
        out->value.startp = NULL;
        out->value.len    = 0;
    }
    return true;
}
