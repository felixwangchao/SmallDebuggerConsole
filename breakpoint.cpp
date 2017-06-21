#include "stdafx.h"
#include "breakpoint.h"

bool bp_int3::install()
{
	DWORD dwSize = 0;
	char cc = '\xcc';
	if (!WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, FALSE, de.dwProcessId), this->address, &cc, 1, &dwSize))
	{
		printf("Cant't write to this address: %08x", this->address);
		return false;
	}
	return true;
}

void bp_int3::repair()
{
	DWORD dwSize = 0;
	WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, FALSE, de.dwProcessId), this->address, &(this->oldbyte), 1, &dwSize);
}
bool bp_int3::isCurrent(LPVOID br)
{
	if (br == this->address)
	{
		return true;
	}
	else
	{
		return false;
	}
}
void bp_int3::show()
{
	DWORD addr = (DWORD)(this->address);
	printf("软件断点：%08x",addr);
	if (description.size() > 0)
	{
		printf("  描述信息:%s", description.c_str());

		if (this->type == CONDITION_BREAKPOINT)
		{
			printf("  %s\n", condition.c_str());
		}
		else
		{
			printf("\n");
		}
	}
	else
	{
		printf("\n");
	}
}

void bp_int3::setOldType()
{
	DWORD dwSize = 0;
	if (!ReadProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, FALSE, de.dwProcessId), this->address, &(this->oldbyte), 1, &dwSize))
	{
		printf("Can't read this address: %08x\n", this->address);
		return;
	}
}

void setBreakpoint_tf()
{
	PREG_EFLAGS pEflags = (PREG_EFLAGS)&ct.EFlags;
	pEflags->TF = 1;
	SetThreadContext(OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId), &ct);
}

void disableBreakpoint_tf()
{
	PREG_EFLAGS pEflags = (PREG_EFLAGS)&ct.EFlags;
	pEflags->TF = 0;
	SetThreadContext(OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId), &ct);
}

bool bp_hdr::install()
{
	if (bIsInDr == true)
	{
		return true;
	}
	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
	if (pDr7->L0 == 0)
	{
		printf("install dr0\n");
		ct.Dr0 = (DWORD)(this->address);
		pDr7->RW0 = 0;
		pDr7->LEN0 = 0;
		pDr7->L0 = 1;
	}
	else if (pDr7->L1 == 0)
	{
		printf("install dr1\n");
		ct.Dr1 = (DWORD)(this->address);
		pDr7->RW1 = 0;
		pDr7->LEN1 = 0;
		pDr7->L1 = 1;
	}
	else if (pDr7->L2 == 0)
	{
		printf("install dr2\n");
		ct.Dr2 = (DWORD)(this->address);
		pDr7->RW2 = 0;
		pDr7->LEN2 = 0;
		pDr7->L2 = 1;
	}
	else if (pDr7->L3 == 0)
	{
		printf("install dr3\n");
		ct.Dr3 = (DWORD)(this->address);
		pDr7->RW3 = 0;
		pDr7->LEN3 = 0;
		pDr7->L3 = 1;
	}
	else
	{
		return FALSE;
	}
	SetThreadContext(OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId), &ct);
	bIsInDr = true;
	return true;
}

void bp_hdr::repair()
{

	if (bIsInDr == false)
	{
		return;
	}

	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
	if (pDr7->L0 == 1 && ct.Dr0 == (DWORD)(this->address))
	{
		printf("clear dr0\n");
		ct.Dr0 = (DWORD)(nullptr);
		pDr7->RW0 = 0;
		pDr7->LEN0 = 0;
		pDr7->L0 = 0;
	}
	else if (pDr7->L1 == 1 && ct.Dr1 == (DWORD)(this->address))
	{
		printf("clear dr1\n");
		ct.Dr1 = (DWORD)(nullptr);
		pDr7->RW1 = 0;
		pDr7->LEN1 = 0;
		pDr7->L1 = 0;
	}
	else if (pDr7->L2 == 1 && ct.Dr2 == (DWORD)(this->address))
	{
		printf("clear dr2\n");
		ct.Dr2 = (DWORD)(nullptr);
		pDr7->RW2 = 0;
		pDr7->LEN2 = 0;
		pDr7->L2 = 0;
	}
	else if (pDr7->L3 == 1 && ct.Dr3 == (DWORD)(this->address))
	{
		printf("clear dr3\n");
		ct.Dr3 = (DWORD)(nullptr);
		pDr7->RW3 = 0;
		pDr7->LEN3 = 0;
		pDr7->L3 = 0;
	}
	SetThreadContext(OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId), &ct);
	bIsInDr = false;
}

bool bp_hdr::isCurrent(LPVOID br)
{
	if (br == this->address)
	{
		return true;
	}
	else
	{
		return false;
	}
}

void bp_hdr::show()
{
	DWORD addr = (DWORD)(this->address);
	printf("硬件断点：%08x\n", addr);
}


bool bp_hdr_rw::install()
{

	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
	if (pDr7->L0 == 0)
	{
		printf("dr0\n");
		ct.Dr0 = (DWORD)(this->address);
		pDr7->RW0 = 3;
		pDr7->LEN0 = dwLen;
		pDr7->L0 = 1;
	}
	else if (pDr7->L1 == 0)
	{
		printf("dr1\n");
		ct.Dr1 = (DWORD)(this->address);
		pDr7->RW1 = 3;
		pDr7->LEN1 = dwLen;
		pDr7->L1 = 1;
	}
	else if (pDr7->L2 == 0)
	{
		printf("dr2\n");
		ct.Dr2 = (DWORD)(this->address);
		pDr7->RW2 = 3;
		pDr7->LEN2 = dwLen;
		pDr7->L2 = 1;
	}
	else if (pDr7->L3 == 0)
	{
		printf("dr3\n");
		ct.Dr3 = (DWORD)(this->address);
		pDr7->RW3 = 3;
		pDr7->LEN3 = dwLen;
		pDr7->L3 = 1;
	}
	else
	{
		return FALSE;
	}
	SetThreadContext(OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId), &ct);
	return true;
}
void bp_hdr_rw::repair()
{
	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
	if (pDr7->L0 == 1 && ct.Dr0 == (DWORD)(this->address))
	{
		ct.Dr0 = (DWORD)(nullptr);
		pDr7->RW0 = 0;
		pDr7->LEN0 = 0;
		pDr7->L0 = 0;
	}
	if (pDr7->L1 == 1 && ct.Dr1 == (DWORD)(this->address))
	{
		ct.Dr1 = (DWORD)(nullptr);
		pDr7->RW1 = 0;
		pDr7->LEN1 = 0;
		pDr7->L1 = 0;
	}
	if (pDr7->L2 == 1 && ct.Dr2 == (DWORD)(this->address))
	{
		ct.Dr2 = (DWORD)(nullptr);
		pDr7->RW2 = 0;
		pDr7->LEN2 = 0;
		pDr7->L2 = 0;
	}
	if (pDr7->L3 == 1 && ct.Dr3 == (DWORD)(this->address))
	{
		ct.Dr3 = (DWORD)(nullptr);
		pDr7->RW3 = 0;
		pDr7->LEN3 = 0;
		pDr7->L3 = 0;
	}
	SetThreadContext(OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId), &ct);
}
bool bp_hdr_rw::isCurrent(LPVOID br)
{
	if (br == this->address)
	{
		return true;
	}
	else
	{
		return false;
	}
}
void bp_hdr_rw::show()
{
	DWORD addr = (DWORD)(this->address);
	printf("硬件读写断点：%08x\n", addr);
}


bool bp_mm::install()
{
	DWORD dwBase;
	DWORD dwSize;
	DWORD dwAddr = (DWORD)(this->address);
	bool bRet;
	MEMORY_BASIC_INFORMATION mbi = { 0 };

	bRet = VirtualQueryEx(hProcess, (LPCVOID)dwAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

	if (!bRet)
	{
		return false;
	}
	//PAGE_NO_ACCESS
	dwBase = (DWORD)mbi.BaseAddress;
	this->dwBase = dwBase;
	dwSize = (DWORD)mbi.RegionSize;
	this->dwRegion = dwSize;
	bRet = VirtualProtectEx(hProcess, (LPVOID)dwBase, dwSize,PAGE_NOACCESS, &(this->OldProtect));
	if (!bRet)
	{
		return false;
	}
	return true;
}
void bp_mm::repair()
{
	DWORD dwBase;
	DWORD dwSize;
	DWORD dwAddr = (DWORD)(this->address);
	bool bRet;
	MEMORY_BASIC_INFORMATION mbi = { 0 };

	bRet = VirtualQueryEx(hProcess, (LPCVOID)dwAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

	dwBase = (DWORD)mbi.BaseAddress;
	dwSize = (DWORD)mbi.RegionSize;
	DWORD dwTemp;
	VirtualProtectEx(hProcess, (LPVOID)dwBase, dwSize, this->OldProtect, &(dwTemp));
}

void bp_mm::cancel()
{
	DWORD dwBase;
	DWORD dwSize;
	DWORD dwAddr = (DWORD)(this->address);
	bool bRet;
	MEMORY_BASIC_INFORMATION mbi = { 0 };

	bRet = VirtualQueryEx(hProcess, (LPCVOID)dwAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

	dwBase = (DWORD)mbi.BaseAddress;
	dwSize = (DWORD)mbi.RegionSize;
	DWORD dwTemp;
	VirtualProtectEx(hProcess, (LPVOID)dwBase, dwSize, this->OldProtect, &(dwTemp));
}

bool bp_mm::isCurrent(LPVOID br)
{
	DWORD b = (DWORD)br;

	if ((b <= dwRegion + dwBase) && (b>= dwBase))
	{
		return true;
	}
	else
	{
		return false;
	}
}
void bp_mm::show()
{
	DWORD addr = (DWORD)(this->address);
	printf("内存断点：%08x\n", addr);
}