cmake_minimum_required(VERSION 3.0.0)
project(keycloak-auth-client-test VERSION 0.1.0 LANGUAGES C)

include(CTest)
enable_testing()

add_executable(keycloak-auth-client-test main.c assertion.c httpclient.c base64util.c)
target_link_libraries(keycloak-auth-client-test ssl3 crypto uuid curl json-c)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
