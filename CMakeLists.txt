cmake_minimum_required(VERSION 3.0.0)
project(liboidc VERSION 0.1.0 LANGUAGES C)

include(CTest)
enable_testing()

add_executable(liboidc main.c assertion.c)
target_link_libraries(liboidc ssl3 crypto uuid)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
