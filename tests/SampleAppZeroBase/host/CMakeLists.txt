# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../SampleAppZeroBase.edl)

add_custom_command(
  OUTPUT SampleAppZeroBase_u.h SampleAppZeroBase_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(SampleAppZeroBaseHost SampleAppZeroBaseHost.cpp
                                     SampleAppZeroBase_u.c)

target_include_directories(
  SampleAppZeroBaseHost PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                ${CMAKE_CURRENT_SOURCE_DIR})

# TODO: Need to find a way around hard-coding th host application base address
# on the application CMakeList.txt.
target_link_libraries(SampleAppZeroBaseHost oehost -fpie
                      -Wl,-Ttext-segment,0x10000000)

target_link_libraries(SampleAppZeroBaseHost oehost)
