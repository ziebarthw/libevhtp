
#pragma once

#include <stdbool.h>
#include <stdlib.h>
#include "parser.h"

typedef struct htp_http1config htp_http1config_t;

struct htp_http1config {
    size_t max_line_length;
    size_t max_header_count;
    size_t max_empty_line_count;
    bool allow_folding;
};

EVHTP_EXPORT htparser * htparser_new_(const htp_http1config_t * config);
EVHTP_EXPORT void htparser_reset(htparser * self);
EVHTP_EXPORT void htparser_set_http1config(htparser * self, const htp_http1config_t * config);
