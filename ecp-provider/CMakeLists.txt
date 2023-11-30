# ~~~
# Copyright 2023 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ~~~

cmake_minimum_required(VERSION 3.10)

project(EcpProvider VERSION 0.1)

set(C_STANDARD 11)
SET(CMAKE_SKIP_BUILD_RPATH  FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_BUILD_RPATH_USE_ORIGIN TRUE)
SET(CMAKE_INSTALL_RPATH "$\{ORIGIN\}")

find_package(OpenSSL REQUIRED)
add_library(ecp SHARED IMPORTED)
if(APPLE)
set_target_properties(ecp PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../bin/libecp.dylib
       BUILD_WITH_INSTALL_RPATH TRUE
       INSTALL_RPATH "\$ORIGIN"
   )
elseif(WIN32)
set_target_properties(ecp PROPERTIES
       IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../bin/libecp.dll
       IMPORTED_IMPLIB   ${CMAKE_CURRENT_SOURCE_DIR}/../bin/libecp.lib
       BUILD_WITH_INSTALL_RPATH TRUE
       INSTALL_RPATH "\$ORIGIN"
   )
else()
set_target_properties(ecp PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../bin/libecp.so
       BUILD_WITH_INSTALL_RPATH TRUE
       INSTALL_RPATH "\$ORIGIN"
   )
endif()

add_library(ecp_provider SHARED
  provider.c
)


if (UNIX)
  target_compile_options(ecp_provider PRIVATE -Wall -Wextra -Werror)
    if (CMAKE_COMPILER_IS_CLANG)
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
          target_compile_options(ecp_provider PRIVATE -fsanitize=address -fsanitize=leak -fsanitize=undefined -fsanitize=memory)
        endif()
    endif()
endif()

target_link_libraries(ecp_provider PRIVATE ecp)
target_link_libraries(ecp_provider PRIVATE OpenSSL::Crypto OpenSSL::SSL)

