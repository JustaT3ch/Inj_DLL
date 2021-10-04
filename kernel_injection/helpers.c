#include "helpers.h"


// Main use here is to find the LdrLoadDll from the export table of the mapped ntdll module.
// Can be used to retrieve any function specified by name from the specified module.

PVOID KernelGetProcAddress(PVOID p_module_base, PCHAR p_function_name)
{

	PULONG NameTable;

	PUSHORT OrdinalTable;

	PIMAGE_EXPORT_DIRECTORY ExportDirectory;

	LONG Low = 0, High, Ret;

	USHORT Ordinal;

	PVOID Function;

	ULONG ExportSize;

	PULONG ExportTable;


	ExportDirectory = RtlImageDirectoryEntryToData(p_module_base, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &ExportSize);

	if (!ExportDirectory)
	{
		return NULL;
	}

	NameTable = (PULONG)((ULONG_PTR)p_module_base + ExportDirectory->AddressOfNames);

	OrdinalTable = (PUSHORT)((ULONG_PTR)p_module_base + ExportDirectory->AddressOfNameOrdinals);


	High = ExportDirectory->NumberOfNames - 1;

	for (Low = 0; Low <= High; Low++)
	{
		Ret = strcmp(p_function_name, (PCHAR)p_module_base + NameTable[Low]);
		if (Ret == 0)
			break;
	}

	if (High < Low)
		return NULL;

	Ordinal = OrdinalTable[Low];

	if (Ordinal >= ExportDirectory->NumberOfFunctions)
		return NULL;

	ExportTable = (PULONG)((ULONG_PTR)p_module_base + ExportDirectory->AddressOfFunctions);

	Function = (PVOID)((ULONG_PTR)p_module_base + ExportTable[Ordinal]);

	DbgPrint("[+] LdrLoadDll address : 0x%llx\n", Function);

	return Function;

}


// check for target process
int proc_check(HANDLE proc_id, PUNICODE_STRING target_process)
{

	NTSTATUS status = 0;

	// find the eprocess stracture of the target process

	PEPROCESS eprocess;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(proc_id, &eprocess)))
		return -1;

	// get a handle to the process

	HANDLE proc_h;

	if (!NT_SUCCESS(ObOpenObjectByPointer(eprocess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &proc_h)))
		return -1;

	// set up a buffer to store the information of ProcessImageFileName

	WCHAR buff[BUFFER_SIZE];

	UNICODE_STRING* ProcessImageFileName_data = (UNICODE_STRING*)buff;

	PWCH pBuff = (PWCH)((BYTE*)buff + sizeof(UNICODE_STRING));

	ProcessImageFileName_data->Length = 0;

	ProcessImageFileName_data->MaximumLength = (USHORT)(sizeof(buff) - sizeof(UNICODE_STRING));

	ProcessImageFileName_data->Buffer = pBuff;

	status = ZwQueryInformationProcess(proc_h, ProcessImageFileName, ProcessImageFileName_data, sizeof(buff), NULL);

	if (!NT_SUCCESS(status))
		return -1;


	if (_wcsicmp(target_process->Buffer, pBuff) == 0)
	{

		return 0;

	}

	// Close the process	
	
	ZwClose(proc_h);

	// Dereference process object back
	
	ObDereferenceObject(eprocess);

	return -1;

}