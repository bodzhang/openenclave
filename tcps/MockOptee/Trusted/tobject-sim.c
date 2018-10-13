/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <windows.h>
#include <tee_api.h>
#include <tcps_t.h>

TEE_Result TEE_OpenPersistentObject(
    _In_ uint32_t storageID,
    _In_reads_bytes_(objectIDLen) void* objectID,
    _In_ size_t objectIDLen,
    _In_ uint32_t flags,
    _Out_ TEE_ObjectHandle* object)
{
    char fileName[MAX_PATH];

    *object = (TEE_ObjectHandle)INVALID_HANDLE_VALUE;

    if (objectIDLen >= sizeof(fileName)) {
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    strncpy_s(fileName, sizeof(fileName), objectID, objectIDLen);
    fileName[objectIDLen] = 0;

    DWORD dwFlags = 0;
    DWORD dwSharing = 0;

    if (flags & TEE_DATA_FLAG_ACCESS_READ) {
        dwFlags |= GENERIC_READ;
    }
    if (flags & TEE_DATA_FLAG_ACCESS_WRITE) {
        dwFlags |= GENERIC_WRITE;
    }
    if (flags & TEE_DATA_FLAG_ACCESS_WRITE_META) {
        dwFlags |= GENERIC_WRITE;
    }
    if (flags & TEE_DATA_FLAG_SHARE_READ) {
        dwSharing |= FILE_SHARE_READ;
    }
    if (flags & TEE_DATA_FLAG_SHARE_WRITE) {
        dwSharing |= FILE_SHARE_WRITE;
    }

    HANDLE hFile = CreateFileA(
        fileName,
        dwFlags,
        dwSharing,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    *object = (TEE_ObjectHandle)hFile;

    return (hFile == INVALID_HANDLE_VALUE) ? TEE_ERROR_ITEM_NOT_FOUND : TEE_SUCCESS;
}

TEE_Result TEE_CreatePersistentObject(
    _In_ uint32_t storageID,
    _In_reads_bytes_(objectIDLen) void* objectID,
    _In_ size_t objectIDLen,
    _In_ uint32_t flags,
    _In_ TEE_ObjectHandle attributes,
    _In_reads_bytes_(initialDataLen) void* initialData,
    _In_ size_t initialDataLen,
    _Out_ TEE_ObjectHandle* object)
{
    /* Support for InitialData is not implemented. */
    TCPS_ASSERT(initialData == NULL);
    TCPS_ASSERT(initialDataLen == 0);

    *object = (TEE_ObjectHandle)INVALID_HANDLE_VALUE;

    char fileName[MAX_PATH];
    if (objectIDLen >= sizeof(fileName)) {
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    strncpy_s(fileName, sizeof(fileName), objectID, objectIDLen);
    fileName[objectIDLen] = 0;

    DWORD dwFlags = 0;
    DWORD dwSharing = 0;

    if (flags & TEE_DATA_FLAG_ACCESS_READ) {
        dwFlags |= GENERIC_READ;
    }
    if (flags & TEE_DATA_FLAG_ACCESS_WRITE) {
        dwFlags |= GENERIC_WRITE;
    }
    if (flags & TEE_DATA_FLAG_ACCESS_WRITE_META) {
        dwFlags |= GENERIC_WRITE;
    }
    if (flags & TEE_DATA_FLAG_SHARE_READ) {
        dwSharing |= FILE_SHARE_READ;
    }
    if (flags & TEE_DATA_FLAG_SHARE_WRITE) {
        dwSharing |= FILE_SHARE_WRITE;
    }

    HANDLE hFile = CreateFileA(
        fileName,
        dwFlags,
        dwSharing,
        NULL,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    *object = (TEE_ObjectHandle)hFile;

    return (hFile == INVALID_HANDLE_VALUE) ? TEE_ERROR_ITEM_NOT_FOUND : TEE_SUCCESS;
}

TEE_Result TEE_SeekObjectData(
    _In_ TEE_ObjectHandle object,
    _In_ int32_t offset,
    _In_ TEE_Whence whence)
{
    HANDLE hFile = (HANDLE)object;
    DWORD result = SetFilePointer(hFile, offset, NULL, whence);
    return (result == INVALID_SET_FILE_POINTER) ? TEE_ERROR_STORAGE_NOT_AVAILABLE : TEE_SUCCESS;
}

TEE_Result TEE_ReadObjectData(
    _In_ TEE_ObjectHandle object,
    _Out_writes_bytes_to_(size, *count) void* buffer,
    _In_ size_t size,
    _Out_ uint32_t* count)
{
    HANDLE hFile = (HANDLE)object;
    BOOL ok = ReadFile(hFile, buffer, size, count, NULL);
    return (ok) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

TEE_Result TEE_WriteObjectData(
    _In_ TEE_ObjectHandle object,
    _In_reads_bytes_(size) void* buffer,
    _In_ size_t size)
{
    HANDLE hFile = (HANDLE)object;
    DWORD bytesWritten;
    BOOL ok = WriteFile(hFile, buffer, size, &bytesWritten, NULL);
    return (ok && bytesWritten == size) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

TEE_Result TEE_GetObjectInfo1(
    _In_ TEE_ObjectHandle object,
    _Out_ TEE_ObjectInfo* objectInfo)
{
    HANDLE hFile = (HANDLE)object;
    BY_HANDLE_FILE_INFORMATION info = { 0 };
    BOOL ok = GetFileInformationByHandle(hFile, &info);
    if (!ok) {
        return TEE_ERROR_GENERIC;
    }
    objectInfo->dataSize = info.nFileSizeLow;

    // We don't yet support the other fields.

    return TEE_SUCCESS;
}

void TEE_CloseObject(
    _In_ TEE_ObjectHandle object)
{
    HANDLE hFile = (HANDLE)object;
    CloseHandle(hFile);
}

TEE_Result TEE_CloseAndDeletePersistentObject1(
    _In_ TEE_ObjectHandle object)
{
    HANDLE hFile = (HANDLE)object;

    // Get the filename.
    char fileName[MAX_PATH];
    DWORD result = GetFinalPathNameByHandleA(
        hFile,
        fileName,
        sizeof(fileName),
        FILE_NAME_NORMALIZED);
    CloseHandle(hFile);
    if (result == 0) {
        return TEE_ERROR_GENERIC;
    }

    // Delee the file.
    BOOL ok = DeleteFileA(fileName);
    return (ok) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}