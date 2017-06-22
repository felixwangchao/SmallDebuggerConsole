#pragma once
#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include "include/capstone.h"
#pragma comment(lib,"capstone_x86.lib")
#include "keystone/keystone.h"
#pragma comment(lib,"keystone_x86.lib")
#include <Dbghelp.h>
#pragma comment(lib, "Dbghelp.lib")
#include <process.h>
#include<tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <sstream>
using namespace std;
using std::vector;



#ifdef _DEBUG
#define DEBUG(str) cout << __FILE__<<" " << __FUNCTION__ <<" "<< __LINE__<<"行 : "<<str
#else
#define DEBUG(str) 
#endif // _DEBUG

#define PATH L"E:\\hellocpp.exe"
#define PDB_PATH "E:\\"

#define SOFTWARE_BREAKPOINT			0x1
#define HARDWARE_BREAKPOINT			0x2
#define HARDWARE_RW_BREAKPOINT		0x3
#define CONDITION_BREAKPOINT		0x4
#define MEMORY_BREAKPOINT			0x5

// 调试相关的全局变量
extern cs_opt_mem memop;
extern csh handle;
extern DEBUG_EVENT de ;
extern DWORD	dwReturnCode;

// 当前环境
extern CONTEXT ct;

// 事件
extern HANDLE g_WaitRun;
extern HANDLE g_WaitStop;

// 进程
extern DWORD dwPid;
extern HANDLE hProcess;

// 内存断点
extern bool bIsMM;

// 内存判断时触发了其他断点
extern bool bNeedStop;

// 真单步断点
extern bool bIsTF;

// 是否触发条件断点
extern bool bCdBrNotTrigged;

// 模块基址
extern DWORD dwBaseOfImage;



// eflags结构体
typedef struct _EFLAGS
{
	unsigned CF : 1;
	unsigned Reserve1 : 1;
	unsigned PF : 1;
	unsigned Reserve2 : 1;
	unsigned AF : 1;
	unsigned Reserve3 : 1;
	unsigned ZF : 1;
	unsigned SF : 1;
	unsigned TF : 1;
	unsigned IF : 1;
	unsigned DF : 1;
	unsigned OF : 1;
	unsigned IOPL : 2;
	unsigned NT : 1;
	unsigned Reserve4 : 1;
	unsigned RF : 1;
	unsigned VM : 1;
	unsigned AC : 1;
	unsigned VIF : 1;
	unsigned VIP : 1;
	unsigned ID : 1;
	unsigned Reserve5 : 10;
}REG_EFLAGS, *PREG_EFLAGS;

typedef struct _DBG_REG7{
	unsigned L0 : 1;
	unsigned G0 : 1;
	unsigned L1 : 1;
	unsigned G1 : 1;
	unsigned L2 : 1;
	unsigned G2 : 1;
	unsigned L3 : 1;
	unsigned G3 : 1;

	unsigned LE : 1;
	unsigned GE : 1;
	unsigned Reserve1 : 3;

	unsigned GD : 1;
	unsigned Reserve2 : 2;

	unsigned RW0 : 2;
	unsigned LEN0 : 2;
	unsigned RW1 : 2;
	unsigned LEN1 : 2;
	unsigned RW2 : 2;
	unsigned LEN2 : 2;
	unsigned RW3 : 2;
	unsigned LEN3 : 2;
}DBG_REG7, *PDBG_REG7;


