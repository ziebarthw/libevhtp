add_custom_target(examples)

#add_executable(test_extensive EXCLUDE_FROM_ALL test.c)
add_executable(test_basic EXCLUDE_FROM_ALL test_basic.c)
add_executable(test_vhost EXCLUDE_FROM_ALL test_vhost.c)
#add_executable(test_client EXCLUDE_FROM_ALL test_client.c)
add_executable(test_query EXCLUDE_FROM_ALL test_query.c)
add_executable(test_perf EXCLUDE_FROM_ALL test_perf.c)
add_executable(example_vhost EXCLUDE_FROM_ALL example_vhost.c)
add_executable(example_pause EXCLUDE_FROM_ALL example_pause.c)
#add_executable(example_chunked EXCLUDE_FROM_ALL example_chunked.c)
#add_executable(example_request_fini EXCLUDE_FROM_ALL example_request_fini.c)
add_executable(example_basic EXCLUDE_FROM_ALL example_basic.c)

if(NOT EVHTP_DISABLE_EVTHR)
    if ("${CMAKE_SYSTEM}" MATCHES "Linux")
        add_executable(example_locality EXCLUDE_FROM_ALL example_locality.c)
        target_link_libraries(example_locality evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})

        add_executable(reuse_thread_svr EXCLUDE_FROM_ALL reuse_thread_svr.c)
        target_link_libraries(reuse_thread_svr evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})

        add_dependencies(examples example_locality reuse_thread_svr)
    endif()

	add_executable(test_proxy EXCLUDE_FROM_ALL test_proxy.c)
	target_link_libraries(test_proxy evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
	add_executable(obound_proxy EXCLUDE_FROM_ALL obound_proxy.c)
	target_link_libraries(obound_proxy evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})

	add_dependencies(examples test_proxy)
	add_dependencies(examples obound_proxy)
endif()

#target_link_libraries(test_extensive evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(test_basic   evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(test_vhost   evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
#target_link_libraries(test_client  evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(test_query   evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(test_perf    evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(example_vhost evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(example_pause evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
#target_link_libraries(example_chunked evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
#target_link_libraries(example_request_fini evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(example_basic evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})

if(NOT EVHTP_DISABLE_SSL)
    file(COPY
         https/etc/ca.cnf
         https/etc/client1.cnf
         https/etc/client2.cnf
         https/etc/server.cnf
         DESTINATION https/etc/)

    configure_file(https/bin/generate.sh.in https/bin/generate.sh @ONLY)

    add_executable(example_https_server EXCLUDE_FROM_ALL https/example_https_server.c)
    target_link_libraries(example_https_server evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})

    add_executable(example_https_client EXCLUDE_FROM_ALL https/example_https_client.c)
    target_link_libraries(example_https_client evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})

    add_dependencies(examples example_https_server example_https_client)

    if(NOT EVHTP_DISABLE_H2)
        # HTTP/2 responses leave out connection-specific headers (needs curl)
        add_executable(test_h2_headers EXCLUDE_FROM_ALL test_h2_headers.c)
        target_link_libraries(test_h2_headers evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
        add_dependencies(examples test_h2_headers)

        # streaming replies over HTTP/2 and HTTP/1.1 (needs curl)
        add_executable(test_h2_streaming EXCLUDE_FROM_ALL test_h2_streaming.c)
        target_link_libraries(test_h2_streaming evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
        add_dependencies(examples test_h2_streaming)

        # request target parsing (path, query) over HTTP/2 and HTTP/1.1
        add_executable(test_h2_query EXCLUDE_FROM_ALL test_h2_query.c)
        target_link_libraries(test_h2_query evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
        add_dependencies(examples test_h2_query)

        # receiving requests over HTTP/2: hook-set callbacks, flow control
        add_executable(test_h2_request EXCLUDE_FROM_ALL test_h2_request.c)
        target_link_libraries(test_h2_request evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
        add_dependencies(examples test_h2_request)
    endif()
endif()

add_dependencies(examples
  example_pause
  example_vhost
  test_basic
  test_vhost
  test_query
  test_perf
  example_basic)
