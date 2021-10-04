#include "apc_functions.h"


void NTAPI kernel_routine_stub(PKAPC apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2)
{
	UNREFERENCED_PARAMETER(SystemArgument1);

	UNREFERENCED_PARAMETER(SystemArgument2);

	UNREFERENCED_PARAMETER(NormalRoutine);

	UNREFERENCED_PARAMETER(NormalContext);

	ExFreePool(apc);
}

//VOID InjectorAPCNormalRoutine(PVOID Context, PVOID SysArg1, PVOID SysArg2)
//{
//
//	UNREFERENCED_PARAMETER(SysArg1);
//
//	UNREFERENCED_PARAMETER(SysArg2);
//
//	PKINJECT InjectionInfo = (PKINJECT)Context;
//	
//	InjectionInfo->LdrLoadDll(NULL, NULL, &InjectionInfo->DllName, &InjectionInfo->DllBase);
//
//	HANDLE h_mod;
//
//	InjectionInfo->LdrLoadDll(NULL, NULL, &InjectionInfo->DllName, &h_mod);
//
//	InjectionInfo->Executed = TRUE;
//	
//}
