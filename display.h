#pragma once
#include "stdafx.h"
#include "global.h"

//
// 打印当前寄存器信息
//
void displayRegisters(const CONTEXT &ct)
{
	cout << "寄存器信息：" << endl;
	printf("eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x\n", ct.Eax, ct.Ebx, ct.Ecx, ct.Edx, ct.Esi, ct.Edi);
	printf("eip=%08x esp=%08x ebp=%08x\n", ct.Eip, ct.Esp, ct.Ebp);
	printf("cs=%04x ss=%04x ds=%04x es=%04x fs=%04x gs=%04x efl=%08x\n", ct.SegCs, ct.SegSs, ct.SegDs, ct.SegEs, ct.SegFs, ct.SegGs, ct.EFlags);
}

//
// 打印栈信息
//
void displayStack(DEBUG_EVENT de, const CONTEXT &ct, DWORD num=10)
{
	DWORD size = num * 8;
	char* buff = new char[size];

	// 读取栈信息
	DWORD dwRead = 0;
	ReadProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, FALSE, de.dwProcessId),
		(LPVOID)ct.Esp,
		buff,
		size,
		&dwRead
		);

	cout << "栈信息" << endl;
	DWORD esp = ct.Esp;
	for (int i = 0; i < num; ++i)
	{
		printf("%08x  |  %08x \n", esp + 8*i, ((DWORD*)buff)[i]);
	}

	delete[] buff;
}