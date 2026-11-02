# -DEVHTP_DISABLE_SSL=ON
option (EVHTP_DISABLE_SSL   "Disable ssl support"          OFF)

# -DEVHTP_DISABLE_H2=ON
option(EVHTP_DISABLE_H2 "Disable HTTP/2 support via nghttp2" OFF)

# -DEVHTP_DISABLE_UPSTREAM_H2=OFF: client TLS connections offer h2 in ALPN
# too (ON: http/1.1 only, as before this option existed)
option(EVHTP_DISABLE_UPSTREAM_H2 "Offer only http/1.1 on client TLS connections" ON)

# -DEVHTP_DISABLE_EVTHR=ON
option (EVHTP_DISABLE_EVTHR "Disable evthread support"     OFF)

# -DEVHTP_DISABLE_REGEX=ON
find_package(Oniguruma)
option (EVHTP_DISABLE_REGEX "Disable regex support"        OFF)

# -DEVHTP_DEBUG=ON
option (EVHTP_DEBUG         "Enable verbose debug logging"     OFF)

# can be overwritten by new set_alloc functions
set(EVHTP_ALLOCATOR CACHE STRING "Allocator library")
set_property(CACHE EVHTP_ALLOCATOR PROPERTY STRINGS "jemalloc;tcmalloc")

# disable ability to wrap memory functions
option (EVHTP_DISABLE_MEMFUNCTIONS "Disable custom allocators" OFF)
