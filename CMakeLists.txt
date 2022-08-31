# ~~~
# Copyright 2022 Google Inc.
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

project(GoogleEnterpriseCertificateOffload VERSION 0.1)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(OpenSSL 1.1.1 EXACT REQUIRED)

add_library(certificate_offload SHARED
  src/offload.cpp
)

target_link_libraries(certificate_offload OpenSSL::Crypto OpenSSL::SSL)

if (ENABLE_UNIT_TESTS)
  include(FetchContent)
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1
  )
  FetchContent_MakeAvailable(googletest)

  enable_testing()

  add_executable(
    offload_unit_test
    tests/unit/offload_test.cpp
  )

  target_link_libraries(
    offload_unit_test
    GTest::gtest_main
    certificate_offload
  )

  include(GoogleTest)
  gtest_discover_tests(offload_unit_test)
endif()
