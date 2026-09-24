
#include <stdio.h>

//#define EVHTP_DEBUG 1

#include "evhtp/config.h"
#include "internal.h"
#include "evhtp/tokenizer.h"


bool
parse_parameterized_header(htstring_t header_value, element_handler_t handler, void * ctx)
{
    log_debug("(\"%.*s\", %p, %p)", (int)header_value.len, header_value.startp, handler, ctx);

    httokenizer_t t_elements = httokenizer_ctor(header_value);

    htstring_t element_raw;
    while (httokenizer_next(&t_elements, &p_comma, &element_raw)) {
        ht_element_t element = {0};
        httokenizer_t t_params = httokenizer_ctor(element_raw);

        htstring_t part;
        bool is_first = true;

        while (httokenizer_next(&t_params, &p_semi, &part)) {
            if (is_first) {
                // The first part is the primary value
                element.name = part;
                is_first = false;
            } else if (element.param_count < HT_MAX_PARAMS) {
                // Subsequent parts are parameters (key=value)
                httokenizer_t t_kv = httokenizer_ctor(part);

                htstring_t key, val;
                if (httokenizer_next(&t_kv, &p_eq, &key) &&
                    httokenizer_next(&t_kv, &p_eq, &val)) {

                    element.params[element.param_count].name = key;
                    element.params[element.param_count].value = val;
                    element.param_count++;
                }
            } else {
                log_info("exceeded %u params", HT_MAX_PARAMS);
                return false;
            }
        }

        // Dispatch to the user's logic
        if (element.name.len > 0) {
            if (handler(&element, ctx) != 0) {
                log_debug("breaking");
                break;
            }
        }
    }
    return true;
}

bool
parse_set_cookie(htstring_t value, cookie_handler_t handler, void *ctx)
{
    log_debug("(\"%.*s\", %p, %p)", (int)value.len, value.startp, handler, ctx);

    httokenizer_t t = httokenizer_ctor(value);

    ht_cookie_t cookie = {0};
    htstring_t part;
    bool first = true;

    while (httokenizer_next(&t, &p_semi, &part)) {
        if (first) {
            /* cookie-pair: split on FIRST '=' only — values may contain '=' */
            const char * eq = memchr(part.startp, '=', part.len);
            if (!eq) {
                log_info("missing equals sign");
                return false;              /* malformed: no '=' in pair */
            }
            cookie.name.startp  = part.startp;
            cookie.name.len   = (size_t)(eq - part.startp);
            cookie.value.startp = eq + 1;
            cookie.value.len  = (size_t)(part.startp + part.len - cookie.value.startp);/*part.len - cookie.name.len - 1;*/
            first = false;
        } else if (cookie.attr_count < HT_MAX_PARAMS) {
            /* cookie-av: attribute, optionally = value */
            const char * eq = memchr(part.startp, '=', part.len);
            ht_cookie_av_t *av = &cookie.attrs[cookie.attr_count];
            if (eq) {
                av->name.startp  = part.startp;
                av->name.len   = (size_t)(eq - part.startp);
                av->value.startp = eq + 1;
                av->value.len  = part.len - av->name.len - 1;
                av->has_value  = true;
            } else {
                av->name  = part;               /* flag: "secure", "HttpOnly" */
                av->has_value = false;
            }
            cookie.attr_count++;
        }
        else {
            log_info("exceeded %u params", HT_MAX_PARAMS);
            return false;
        }
    }

    if (cookie.name.len > 0)
        handler(&cookie, ctx);
    return true;
}

bool
parse_cookie(htstring_t value, cookie_pair_handler_t handler, void * ctx)
{
    log_debug("(\"%.*s\", %p, %p)", (int)value.len, value.startp, handler, ctx);

    httokenizer_t t = httokenizer_ctor(value);

    htstring_t part;
    while (httokenizer_next(&t, &p_semi, &part)) {
        ht_cookie_pair_t pair;

        const char * eq = memchr(part.startp, '=', part.len);
        if (eq) {
            pair.name.startp  = part.startp;
            pair.name.len   = (size_t)(eq - part.startp);
            pair.value.startp = eq + 1;
            pair.value.len  = part.len - pair.name.len - 1;
        } else {
            pair.name  = part;
            pair.value.startp = NULL;
            pair.value.len  = 0;
        }

        if (handler(&pair, ctx) != 0) {
            log_debug("breaking");
            break;
        }
    }
    return true;
}

//#define WITH_TOKENIZER_TEST
#ifdef WITH_TOKENIZER_TEST

static int
cookie_handler(const ht_cookie_t * cookie, void * ctx)
{
    log_debug("(%p, %p)", cookie, ctx);
    log_debug("Cookie: %.*s=\"%.*s\"", (int)cookie->name.len, cookie->name.startp, (int)cookie->value.len, cookie->value.startp);
    for (size_t i = 0; i < cookie->attr_count; ++i) {
        log_debug(" Attr %zu) %.*s=%.*s",
            i,
            (int)cookie->attrs[i].name.len, cookie->attrs[i].name.startp,
            (int)cookie->attrs[i].value.len, cookie->attrs[i].value.startp);
htstring_t expires = htstring_ctor("expires", 7);
if (htstring_strcasecmp(&cookie->attrs[i].name, &expires) == 0) {
    log_debug("found expires with value \"%.*s\"", (int)cookie->attrs[i].value.len, cookie->attrs[i].value.startp);
}
    }
    return 0;
}

static int
cookie_pair_handler(const ht_cookie_pair_t * pair, void * ctx)
{
    log_debug("(%p, %p)", pair, ctx);
    log_debug("Cookie: %.*s=\"%.*s\"", (int)pair->name.len, pair->name.startp, (int)pair->value.len, pair->value.startp);
    return htstring_strcmp_(&pair->name, "_ga") == 0 ? -1 : 0;
}

static int
my_processor(ht_element_t * el, void * ctx)
{
    htstring_t * s = htstring_trim_ltgt(&el->name);
    log_debug("Element: \"%.*s\"", (int)s->len, s->startp);
    for (size_t i = 0; i < el->param_count; i++) {
        htstring_trim_quotes(&el->params[i].value);
        log_debug("  Param %zu) %.*s=%.*s",
            i,
            (int)el->params[i].name.len, el->params[i].name.startp,
            (int)el->params[i].value.len, el->params[i].value.startp);
    }
    return 0;
}

static inline bool
is_known_coding(const htstring_t * coding)
{
    return htstring_strcasecmp_(coding, "compress") == 0 ||
            htstring_strcasecmp_(coding, "deflate") == 0 ||
            htstring_strcasecmp_(coding, "gzip") == 0;
}

/* returns 0 = valid framing, non-zero = reject (400) */
static int
validate_transfer_encoding(htstring_t header_value, bool * unknown_coding)
{
    log_debug("(\"%.*s\", %p)", (int)STRLEN(&header_value), STRPTR(&header_value), unknown_coding);

    ht_element_iter_t it = ht_element_iter_ctor(header_value);

    ht_element_t el, last;
    unsigned count = 0, chunked_count = 0;

    while (ht_element_iter_next(&it, &el)) {
        count++;
        if (htstring_strcasecmp_(&el.name, "chunked") == 0) {
            chunked_count++;
            log_debug("chunked count %u", chunked_count);
        }
        else if (!is_known_coding(&el.name)) {
            *unknown_coding = true;         /* caller maps to 501 */
            log_debug("unknown coding \"%.*s\"", (int)STRLEN(&el.name), STRPTR(&el.name));
        }
        last = el;
    }

    if (count == 0)                     return -1;   /* empty list */
    if (chunked_count > 1)              return -2;   /* repeated chunked */
    if (chunked_count == 1 &&
        htstring_strcasecmp_(&last.name, "chunked") != 0)
                                        return -3;   /* chunked not final — smuggling config */
    return 0;
}

#if 0
// If you ever need true lookahead mid-loop (not just "last"),
// copy the iterator — it's one struct assignment:
ht_element_iter_t probe = it;                    /* cheap struct copy */
ht_element_t next_el;
if (ht_element_iter_next(&probe, &next_el)) {    /* does a successor exist? */
    /* decide something about the pair (el, next_el) */
}
/* `it` is untouched; loop continues from el's successor normally */
#endif//0

int main(int argc, char ** argv)
{
//    char buf[] = "\"Google Chrome\";v=\"153\", \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"153\"";
//    char buf[] = "text/html; charset=UTF-8";
//    char buf[] = "cache,platform=wordpress";
//    char buf[] = "<https://freethepeople.org/wp-json/>; rel=\"https://api.w.org/\"";
//    char buf[] = "_fbp=fb.1.1.78955792607E%2B12.1083807214.AQECAQIB; __cf_bm=X31Gqjh.kI9JQh1L9JhxD0dVjGY1xWIHPgbU2eUsBMM-1789558446.7346056-1.0.1.1-q_1w2KOvAaYXCOxYSMikVXn.K3.a.CSrT22auTWxumQqLVcl4vcH38z3falV1MSjcRqxI1LZSzxJyofayAAgNBXBNwhzGkdqMDLrFkIkiSfigzmBin6jJjorbO9uMuFX";
//    char buf[] = "_gcl_au=1.1.733836047.1789558451; ac_enable_tracking=1; _ga=GA1.1.1046736607.1789558451; givecloud_utms=[object%20Object]; _fbp=fb.1.1789558450899.206205448277802318.AQEAAQIB; PHPSESSID=ba099338fdd53bdfb303c369a24b2d30; _ga_EY5V1TV53H=GS2.1.s1789558450$o1$g1$t1789558454$j56$l0$h0; __cf_bm=9JVI5ENLRkdFEgSq_HdQ8Jv_f40BM3xXiTrlPjVbmsw-1789558455.1169415-1.0.1.1-yXELafA7u9ve3BsgVJaFBPiaJoCV.wHj3INzs_b86mDopzwL30A1Nf2EObyEYq1nzKfRx14Eo54qxyj8znrk3KZBXF_Yyi_hGpWRDaFE3x38XD1k1rUmavpXJ628t9c1";
//    char buf[] = "<https://freethepeople.org/wp-json/wp/v2/pages/14044>; rel=\"alternate\"; title=\"JSON\"; type=\"application/json\"";
//    char buf[] = "_fbp=fb.1.1.78947505464E%2B12.1170290678.AQECAQIB; expires=Mon, 14 Dec 2026 12:24:14 GMT; Max-Age=7776000; path=/; domain=freethepeople.org; secure; SameSite=Lax";
//    char buf[] = "h3=\":443\"; ma=86400";
//    char buf[] = "HIT: 7";
//    char buf[] = "Accept-Encoding,Cookie";
    char buf[] = "gzip, unknown, chunked, compress, chunked";
    htstring_t val = htstring_ctor(buf, sizeof(buf) - 1);
    if (!parse_parameterized_header(val, my_processor, NULL))
        log_info("failed");
//if (!parse_set_cookie(val, cookie_handler, NULL))
//    log_info("failed");
//if (!parse_cookie(val, cookie_pair_handler, NULL))
//    log_info("failed");

#if 0
ht_cookie_iter_t iter = ht_cookie_iter_ctor(val);
ht_cookie_pair_t pair;
while (ht_cookie_iter_next(&iter, &pair)) {
    log_debug("%.*s=\"%.*s\"", (int)STRLEN(&pair.name), STRPTR(&pair.name), (int)STRLEN(&pair.value), STRPTR(&pair.value));
    if (htstring_strcmp_(&pair.name, "_ga1") == 0) {
        log_debug("breaking");
        break;
    }
}
#endif//0
ht_element_iter_t iter = ht_element_iter_ctor(val);
ht_element_t el;
while (ht_element_iter_next(&iter, &el)) {
    log_debug("\"%.*s\"", (int)STRLEN(&el.name), STRPTR(&el.name));
    for (size_t i = 0; i < el.param_count; ++i) {
        htstring_t * val = htstring_trim_quotes(&el.params[i].value);
        log_debug("%.*s=\"%.*s\"", (int)STRLEN(&el.params[i].name), STRPTR(&el.params[i].name), (int)STRLEN(val), STRPTR(val));
    }
}
bool unknown_coding = false;
int rval = validate_transfer_encoding(val, &unknown_coding);
if (rval != 0) {
    log_debug("failed %d, unknown coding %u", rval, unknown_coding);
}
    log_debug("done");
    return 0;
}
#endif//WITH_TOKENIZER_TEST
