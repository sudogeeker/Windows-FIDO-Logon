# Reuse the port pinned by vcpkg.json's builtin baseline, changing only the
# OpenSSL Configure options. Keeping the upstream port contents in the pinned
# vcpkg checkout avoids maintaining a divergent copy of its Windows patches.
set(upstream_port "${VCPKG_ROOT_DIR}/ports/openssl")
if(NOT EXISTS "${upstream_port}/portfile.cmake")
    message(FATAL_ERROR "Pinned upstream OpenSSL port was not found: ${upstream_port}")
endif()

set(local_port "${CURRENT_BUILDTREES_DIR}/wfl-openssl-port")
file(REMOVE_RECURSE "${local_port}")
file(COPY "${upstream_port}/" DESTINATION "${local_port}")

set(local_portfile "${local_port}/portfile.cmake")
file(READ "${local_portfile}" port_contents)
set(options_marker "vcpkg_list(SET CONFIGURE_OPTIONS\n")
string(FIND "${port_contents}" "${options_marker}" marker_offset)
if(marker_offset EQUAL -1)
    message(FATAL_ERROR "Pinned upstream OpenSSL port layout changed; refusing an unverified build")
endif()
string(REPLACE
    "${options_marker}"
    "${options_marker}    no-sock\n"
    port_contents
    "${port_contents}")
file(WRITE "${local_portfile}" "${port_contents}")

set(original_current_port_dir "${CURRENT_PORT_DIR}")
set(CURRENT_PORT_DIR "${local_port}")
include("${local_portfile}")
set(CURRENT_PORT_DIR "${original_current_port_dir}")
