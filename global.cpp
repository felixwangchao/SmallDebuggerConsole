#include "stdafx.h"
#include "global.h"

cs_opt_mem memop;
csh handle;
DEBUG_EVENT de = { 0 };
DWORD	dwReturnCode = DBG_CONTINUE;

CONTEXT ct;

HANDLE g_WaitRun = 0;
HANDLE g_WaitStop = 0;

HANDLE hProcess = 0;
DWORD dwPid = 0;

DWORD dwBaseOfImage = 0;

bool bIsMM = false;
bool bNeedStop = false;
bool bIsTF = false;
bool bCdBrNotTrigged = false;

EXCEPTION_REGISTRATION_RECORD* GetThreadSEHAddress(HANDLE hThread)
{
	bool loadedManually = false;
	HMODULE module = GetModuleHandle(L"ntdll.dll");

	if (!module)
	{
		module = LoadLibrary(L"ntdll.dll");
		loadedManually = true;
	}

	NTSTATUS(__stdcall *NtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
	NtQueryInformationThread = reinterpret_cast<decltype(NtQueryInformationThread)>(GetProcAddress(module, "NtQueryInformationThread"));

	if (NtQueryInformationThread)
	{
		NT_TIB tib = { 0 };
		THREAD_BASIC_INFORMATION tbi = { 0 };

		NTSTATUS status = NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
		if (status >= 0)
		{
			ReadProcessMemory(hProcess, tbi.TebBaseAddress, &tib, sizeof(tbi), nullptr);

			if (loadedManually)
			{
				FreeLibrary(module);
			}
			return tib.ExceptionList;
		}
	}

	if (loadedManually)
	{
		FreeLibrary(module);
	}

	return nullptr;
}