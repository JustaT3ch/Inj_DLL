#pragma once

#include "pch.h"

#define MAX_PATH 255

typedef unsigned char BYTE;

#define BUFFER_SIZE (sizeof(UNICODE_STRING) + (MAX_PATH + 1) * sizeof(WCHAR))

extern NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);

extern  NTSTATUS ZwQueryInformationProcess
(
	IN HANDLE ProcessHandle,
	IN  PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

NTSYSAPI PVOID NTAPI RtlImageDirectoryEntryToData(_In_ PVOID BaseOfImage, _In_ BOOLEAN MappedAsImage, _In_ USHORT DirectoryEntry, _Out_ PULONG Size);

PVOID KernelGetProcAddress(PVOID p_module_base, PCHAR p_function_name);

int proc_check(HANDLE proc_id, PUNICODE_STRING target_process);