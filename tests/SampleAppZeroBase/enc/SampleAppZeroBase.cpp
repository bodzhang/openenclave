// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
/*
 * The enclave is created with base address = start address by default.
 * To create enclave at zero base address, uncomment the lines below.
 * NOTE: SGX_ENCLAVE_ZERO_BASE has to be defined before including headers.
 */
#ifndef SGX_ENCLAVE_ZERO_BASE
#define SGX_ENCLAVE_ZERO_BASE
#endif
/*
 * Optionally provide an enclave start address by defining
 * SGX_ENCLAVE_START_ADDR. The start address must be a multiple of
 * SE_PAGE_SIZE 0x1000 and greater than or equal to
 * /proc/sys/vm/mmap_min_addr. The default start address is 0x20000.
 *
 * NOTE: Start address can be provided only when SGX_ENCLAVE_ZERO_BASE
 * is set. SGX_ENCLAVE_START_ADDR has to be defined before
 * including headers.
 */
#ifndef SGX_ENCLAVE_START_ADDR
#define SGX_ENCLAVE_START_ADDR 0x21000
#endif

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include "SampleAppZeroBase_t.h"

const char* ProtectedMessage = "Hello world from Enclave\n\0";

int secure_str_patching(const char* src, char* dst, size_t dst_length)
{
    const char* running_src = src;
    size_t running_length = dst_length;
    while (running_length > 0 && *running_src != '\0')
    {
        *dst = *running_src;
        running_length--;
        running_src++;
        dst++;
    }
    const char* ptr = ProtectedMessage;
    while (running_length > 0 && *ptr != '\0')
    {
        *dst = *ptr;
        running_length--;
        ptr++;
        dst++;
    }
    if (running_length < 1)
    {
        return -1;
    }
    *dst = '\0';
    int rval = -1;
    OE_TEST(unsecure_str_patching(&rval, src, dst, dst_length) == OE_OK);
    return rval;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    256,  /* NumStackPages */
    4);   /* NumTCS */
