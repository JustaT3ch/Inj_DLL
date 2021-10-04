#pragma once

#include "pch.h"

void NTAPI kernel_routine_stub(PKAPC apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);

EXTERN_C VOID InjectorAPCNormalRoutine(PVOID Context, PVOID SysArg1, PVOID SysArg2);