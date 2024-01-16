cmake_minimum_required(VERSION 3.0.0)
project(kcoidc-test VERSION 0.1.0 LANGUAGES C)

include(CTest)
enable_testing()

if (KC_VERBOSE)
        add_definitions(-DKC_VERBOSE)
endif()

unset(CMAKE_SHARED_LIBRARY_PREFIX)
unset(CMAKE_SHARED_LIBRARY_SUFFIX)

add_library(kcoidc SHARED assertion.c oidc_client.c base64util.c uidmapper.c config.c)
set_target_properties(kcoidc PROPERTIES OUTPUT_NAME "libkcoidc.so")
target_link_libraries(kcoidc ssl3 crypto uuid curl json-c z)

add_library(nss_kcoidc SHARED nss.c)
set_target_properties(nss_kcoidc PROPERTIES OUTPUT_NAME "libnss_kcoidc.so.2")
target_link_libraries(nss_kcoidc kcoidc)

add_library(pam_kcoidc SHARED pam.c)
set_target_properties(pam_kcoidc PROPERTIES OUTPUT_NAME "pam_kcoidc.so")
target_link_libraries(pam_kcoidc kcoidc)

add_executable(kcoidc-test main.c)
target_link_libraries(kcoidc-test nss_kcoidc)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
