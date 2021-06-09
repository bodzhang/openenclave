# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../SampleAppZeroBase.edl)

add_custom_command(
  OUTPUT SampleAppZeroBase_t.h SampleAppZeroBase_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  SampleAppZeroBase
  UUID
  25419627-14f6-4625-9329-cf5f10a57fea
  SOURCES
  SampleAppZeroBase.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/SampleAppZeroBase_t.c)

enclave_include_directories(
  SampleAppZeroBase PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})
enclave_link_libraries(SampleAppZeroBase oelibc)
