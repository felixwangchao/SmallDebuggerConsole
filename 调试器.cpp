#include "stdafx.h"
#include "global.h"
#include "display.h"
#include "breakpoint.h"

vector <breakpoint*> bpList;

int HrdBpCount();
void Assembler(string,LPVOID);
void RepairMemory();
void ReinstallBp();
breakpoint* findHdrBp(LPVOID addr);
bp_mm* findMMBp(LPVOID addr);
bool isBreakpoint(LPVOID addr);
void editMemoryByte(LPVOID addr, byte b);
void editMemoryDword(LPVOID, DWORD);
void displayMemory(LPVOID addr, int mode);
void disassembly(LPVOID addr, int nNum = 7);
unsigned int CALLBACK threadProc(void *pArg);


// 记录当前断点

typedef struct _CURRENT_BP
{
	breakpoint* currentbp;
	bool flag;
	int time;
}CURRENT_BP;

CURRENT_BP cur = CURRENT_BP{ nullptr, false };

// 记录当前指令
string cmd="";

// 处理入口点的断点
DWORD dwOEp;
bp_int3 bp;

// 处理当前内存断点的结构体
bp_mm * current_mm;
bp_mm * current_mm_copy;

int _tmain(int argc, _TCHAR* argv[])
{
	// 1. 创建调试会话
	//	1.1 创建一个尚未运行的进程.以进行调试
	STARTUPINFO si = { sizeof( STARTUPINFO ) };
	PROCESS_INFORMATION pi = { 0 };
	BOOL bRet = FALSE;
	bRet = CreateProcess( PATH ,
						  NULL ,
						  NULL ,
						  NULL ,
						  FALSE ,
						  DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE ,
						  NULL ,
						  NULL ,
						  &si ,
						  &pi
						  );
	if( bRet == FALSE ) {
		//DEBUG("创建进程失败");
		return 0;
	}

	// 创建等待事件
	g_WaitStop = CreateEvent(NULL,  /*安全描述符*/
		FALSE, /*是否设置手动状态*/
		FALSE, /*是否有信号*/
		NULL); /*事件对象的名字*/

	g_WaitRun = CreateEvent(NULL,  /*安全描述符*/
		FALSE, /*是否设置手动状态*/
		FALSE, /*是否有信号*/
		NULL); /*事件对象的名字*/

	// 创建用户输入线程
	uintptr_t uThread = _beginthreadex(0, 0, threadProc, 0, 0, 0);

	// 定义结构体, 配置堆空间的回调函数
	//cs_opt_mem memop;
	memop.calloc = calloc;
	memop.free = free;
	memop.malloc = malloc;
	memop.realloc = realloc;
	memop.vsnprintf = (cs_vsnprintf_t)vsprintf_s;
	// 注册堆空间管理组函数
	cs_option( 0 , CS_OPT_MEM , (size_t)&memop );

	//csh handle;
	cs_open( CS_ARCH_X86 ,
			 CS_MODE_32 ,
			 &handle
			 );

	//  1.2 附加一个已经运行的进程,以进行调试.
	//DebugActiveProcess( );
	// 停止调试回话.
	//DebugActiveProcessStop( );

	// 2. 等待调试事件
	//DEBUG_EVENT de = { 0 };
	//DWORD		dwReturnCode = DBG_CONTINUE;
	// 3. 处理调试事件


	// 初始化汇编器


	while( true ) {

		dwReturnCode = DBG_EXCEPTION_NOT_HANDLED;// DBG_CONTINUE;

		WaitForDebugEvent( &de , -1 );

		switch( de.dwDebugEventCode ) {

			case EXCEPTION_DEBUG_EVENT:
			{
				//ypedef struct _EXCEPTION_DEBUG_INFO {
				//	EXCEPTION_RECORD ExceptionRecord;// 异常记录:异常的地址,异常代码,异常的附加信息
				//	DWORD dwFirstChance;// 该异常是正在进行第一次分发,还是第二次分发
				//} EXCEPTION_DEBUG_INFO , *LPEXCEPTION_DEBUG_INFO;
				// 1. 将反汇编信息输出, 准备和用户进行交互
				// 2. 获取OPCODE
				ct = { CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS }; 

				GetThreadContext( OpenThread( THREAD_ALL_ACCESS , FALSE , de.dwThreadId ) , &ct );

				if (de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
				{
					static bool bHdrBp = false;
					static breakpoint* pHdrBp;
					breakpoint* tmp;

					if (bHdrBp == true)
					{
						bHdrBp = false;
						pHdrBp->install();
						pHdrBp = nullptr;
						dwReturnCode = DBG_EXCEPTION_HANDLED;

						break;
					}

					tmp = findHdrBp((LPVOID)(ct.Eip));
					if (tmp != nullptr)
					{
						// 说明当前除了是单步，还是一个硬件断点
						RepairMemory();
					}

					if (bIsMM)
					{

						/* 如果这是内存断点造成的进入单步，则判断是否命中，如果不是则继续执行
						printf("++++++++++++++\n current_mm = %x  Eip = %x  exception type : %d Exception address: %x\n+++++++++++++++\n", 
							current_mm, 
							ct.Eip, 
							de.u.Exception.ExceptionRecord.ExceptionInformation[0],
							de.u.Exception.ExceptionRecord.ExceptionInformation[1]);

						disassembly((LPVOID)ct.Eip);

						//printf("+++++++++++++++++++++++++++++++++++++++\n");*/


						if (current_mm == nullptr)
						{
							current_mm = current_mm_copy;
						}
						bool bIsCurrentMM = (current_mm->address == (LPVOID)ct.Eip);
						if (!bIsCurrentMM)
							current_mm->install();

						current_mm = nullptr;

						if (bIsTF == false && !bIsCurrentMM)
						{
							dwReturnCode = DBG_EXCEPTION_HANDLED;
							break;
						}
					}
					
					bIsTF = false;
					disassembly((LPVOID)ct.Eip);
					ReinstallBp();
					SetEvent(g_WaitStop);
					WaitForSingleObject(g_WaitRun, -1);

					if (tmp != nullptr)
					{
						bHdrBp = true;
						pHdrBp = tmp;
						tmp->repair();
						setBreakpoint_tf();
					}
				}

				else if (de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
				{
					static bool bFirst = true;
					if (bFirst)
					{
						bFirst = false;
						bp = bp_int3((LPVOID)dwOEp);
						bp.install();
						break;
					}
					bp.repair();
					ct.Eip = ct.Eip - 1;
					SetThreadContext(OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId), &ct);

					RepairMemory();
					printf("current address:%x\n", ct.Eip);
					setBreakpoint_tf();

				}
				else if (de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
				{
					bp_mm* bm;

					bm = findMMBp((LPVOID)ct.Eip);
					if (bm == NULL)
					{
						dwReturnCode = DBG_EXCEPTION_NOT_HANDLED;
						break;
					}
					bm->cancel();
					current_mm = bm;
					current_mm_copy = bm;
					bIsMM = true;
					setBreakpoint_tf();
				}
			}
			dwReturnCode = DBG_EXCEPTION_HANDLED;
			break;

			case CREATE_PROCESS_DEBUG_EVENT:
				dwOEp = (DWORD)de.u.CreateProcessInfo.lpStartAddress;
				hProcess = (HANDLE)de.u.CreateProcessInfo.hProcess;
				//ypedef struct _CREATE_PROCESS_DEBUG_INFO {
				//	HANDLE hFile;  // 被创建进程的可执行文件的文件句柄
				//	HANDLE hProcess;// 被创建进程的进程句柄
				//	HANDLE hThread;
				//	LPVOID lpBaseOfImage;// 进程的加载基址
				//	DWORD dwDebugInfoFileOffset;
				//	DWORD nDebugInfoSize;
				//	LPVOID lpThreadLocalBase;
				//	LPTHREAD_START_ROUTINE lpStartAddress; // OEP 程序入口点
				//	LPVOID lpImageName;
				//	WORD fUnicode;
				// CREATE_PROCESS_DEBUG_INFO , *LPCREATE_PROCESS_DEBUG_INFO;
				//DEBUG( "进程创建调试事件\n" );
				break;
			case CREATE_THREAD_DEBUG_EVENT:

				//typedef struct _CREATE_THREAD_DEBUG_INFO {
				//	HANDLE hThread;
				//	LPVOID lpThreadLocalBase;
				//	LPTHREAD_START_ROUTINE lpStartAddress;// 线程回调函数的地址
				//} CREATE_THREAD_DEBUG_INFO , *LPCREATE_THREAD_DEBUG_INFO;
				//DEBUG( "线程创建调试事件\n" );
				break;
			case EXIT_PROCESS_DEBUG_EVENT:
				//DEBUG( "进程退出事件\n" );
				break;
			case EXIT_THREAD_DEBUG_EVENT:
				//DEBUG( "线程退出事件\n" );
				break;
			case LOAD_DLL_DEBUG_EVENT:
				//typedef struct _LOAD_DLL_DEBUG_INFO {
				//	HANDLE hFile; // dll的文件句柄
				//	LPVOID lpBaseOfDll;// dll加载基址
				//	DWORD dwDebugInfoFileOffset;
				//	DWORD nDebugInfoSize;
				//	LPVOID lpImageName;
				//	WORD fUnicode;
				//} LOAD_DLL_DEBUG_INFO , *LPLOAD_DLL_DEBUG_INFO;
				//DEBUG( "DLL加载事件\n" );
				break;
			case OUTPUT_DEBUG_STRING_EVENT:
				//DEBUG( "调试信息输出\n" );
				break;
			case RIP_EVENT:
				break;
			case UNLOAD_DLL_DEBUG_EVENT:
				//DEBUG( "DLL卸载事件\n" );
				break;
		}

		// 4. 回复调试子系统
		ContinueDebugEvent( de.dwProcessId ,
							de.dwThreadId ,
							dwReturnCode );

		// 5. 重复执行第2步.
	}
	
	return 0;
}

bool setCurrentBp()
{
	cur.currentbp = nullptr;
	cur.flag = false;
	cur.time = 0;

	vector <breakpoint*>::iterator iter;
	for (iter = bpList.begin(); iter != bpList.end(); ++iter)
	{
		if ((*iter)->isCurrent((LPVOID)(ct.Eip - 1)))
		{
			cur.currentbp = *iter;
			cur.flag = true;
			cur.time = 0;
			return true;
		}
	}
	return false;
}

void displayBPList()
{
	vector <breakpoint*>::iterator iter;
	for (iter = bpList.begin(); iter != bpList.end(); ++iter)
	{
		(*iter)->show();
	}
}


unsigned int CALLBACK threadProc(void *pArg)
{
	string operation, address, size;
	string buff;
	bool currentbp_flag;
	while (true)
	{
		WaitForSingleObject(g_WaitStop,-1);

		currentbp_flag = setCurrentBp();

		while (true) {
			operation.clear();
			address.clear();
			size.clear();

			cout << "debugger> ";
			getline(cin, buff);

			if (buff.compare("") == 0)
			{
				buff = cmd;
			}
			else
			{
				cmd = buff;
			}

			istringstream is(buff);
			is >> operation>> address >> size;

			if (operation.compare("p") == 0)
			{
				bIsTF = true;
				setBreakpoint_tf();
				SetEvent(g_WaitRun);
				break;
			}
			else if (operation.compare("g") == 0)
			{
				SetEvent(g_WaitRun);
				break;
			}

			//
			//	软件断点
			//
			else if (operation.compare("bp") == 0)
			{
				LPVOID addr = (LPVOID)(std::stoi(address,nullptr,16));

				if (isBreakpoint(addr))
				{
					printf("该地址已经存在断点！\n");
					break;
				}

				breakpoint *bp = new bp_int3(addr);

				if (bp->install())
				{
					bpList.push_back(bp);
				}
			}
			else if (operation.compare("r") == 0)
			{
				displayRegisters(ct);
			}
			else if (operation.compare("s") == 0)
			{
				displayStack(de,ct, stoi(address,nullptr,16));
			}
			else if (operation.compare("bl") == 0)
			{
				displayBPList();
			}
			else if (operation.compare("u") == 0)
			{
				if (size.length()!=0)
					disassembly((LPVOID)stoi(address, nullptr, 16), stoi(size, nullptr, 16));
				else
					disassembly((LPVOID)stoi(address, nullptr, 16));
			}

			else if (operation.compare("eb") == 0)
			{
				byte b = (byte)stoi(size, nullptr, 16);
				if (size.length() == 1 || size.length() == 2)
				{
					editMemoryByte((LPVOID)stoi(address, nullptr, 16), b);
				}
				else
				{
					cout << "请输入一个有效的值！";
				}
			}

			else if (operation.compare("ed") == 0)
			{
				if (size.length() > 0 && size.length() <= 8)
				{
					editMemoryDword((LPVOID)stoi(address, nullptr, 16), stoi(size, nullptr, 16));
				}
				else
				{
					cout << "请输入一个有效的值！";
				}
			}

			else if (operation.compare("a") == 0)
			{
				if (address.size() > 0 && address.size() <= 8)
				{
					LPVOID addr = (LPVOID)(std::stoi(address, nullptr, 16));
					printf("请输入汇编指令 > ");
					string cmd;
					getline(cin, cmd);
					Assembler(cmd,addr);
				}
				else
				{
					printf("请输入一个有效的地址\n");
				}
			}

			else if (operation.compare("dd") == 0)
			{
				LPVOID addr = (LPVOID)(std::stoi(address, nullptr, 16));
				displayMemory(addr, 1);
			}

			else if (operation.compare("db") == 0)
			{
				LPVOID addr = (LPVOID)(std::stoi(address, nullptr, 16));
				displayMemory(addr, 0);
			}
		
			else if (operation.compare("da") == 0)
			{
				LPVOID addr = (LPVOID)(std::stoi(address, nullptr, 16));
				displayMemory(addr, 2);
			}
			else if (operation.compare("bm") == 0)
			{
				LPVOID addr = (LPVOID)(std::stoi(address, nullptr, 16));
				breakpoint* bm = new bp_mm(addr);
				if (bm->install())
				{
					bpList.push_back(bm);
				}
			}

			//
			//	硬件断点
			//
			else if (operation.compare("ba") == 0)
			{
				if (address.length() != 0)
				{
					if (HrdBpCount() < 4)
					{
						LPVOID addr = (LPVOID)(std::stoi(address, nullptr, 16));
						breakpoint *ba = new bp_hdr(addr);
						if (ba->install())
						{
							bpList.push_back(ba);
						}
					}
					else
					{
						printf("只能设置四个硬件断点\n");
					}
				}
				else
				{
					printf("请输入一个合法的地址！\n");
				}
			}
		}
	}
	return 0;
}

bp_mm* findMMBp(LPVOID addr)
{
	vector <breakpoint*>::iterator iter;
	for (iter = bpList.begin(); iter != bpList.end(); ++iter)
	{
		if ((*iter)->type == MEMORY_BREAKPOINT && (*iter)->isCurrent(addr))
			return (bp_mm*)(*iter);
	}
	return nullptr;
}

breakpoint* findHdrBp(LPVOID addr)
{
	vector <breakpoint*>::iterator iter;
	for (iter = bpList.begin(); iter != bpList.end(); ++iter)
	{
		if ((*iter)->address == addr && (*iter)->type == HARDWARE_BREAKPOINT)
			return (*iter);
	}
	return nullptr;
}

int HrdBpCount()
{
	int count = 0;
	vector <breakpoint*>::iterator iter;
	for (iter = bpList.begin(); iter != bpList.end(); ++iter)
	{
		if ((*iter)->type == HARDWARE_BREAKPOINT)
			count++;
	}
	return count;
}


void RepairMemory()
{
	vector <breakpoint*>::iterator iter;
	for (iter = bpList.begin(); iter != bpList.end(); ++iter)
	{
		(*iter)->repair();
	}
}

void ReinstallBp()
{
	vector <breakpoint*>::iterator iter;
	for (iter = bpList.begin(); iter != bpList.end(); ++iter)
	{
		(*iter)->install();
	}
}

bool isBreakpoint(LPVOID addr)
{
	vector <breakpoint*>::iterator iter;
	for (iter = bpList.begin(); iter != bpList.end(); ++iter)
	{
		if ((*iter)->address == addr)
		{
			return true;
		}
	}
	return false;
}

void displayModeByte(LPVOID addr, char* buff)
{
	DWORD address = (DWORD)addr;
	for (int i = 0; i < 4; i++)
	{
		printf("%08x|", address + 16*i);
		for (int j = 0; j < 16; j++)
		{
			byte c = (byte)buff[i * 16 + j];
			printf("%02x ",unsigned int(c));
		}

		printf("\n");
	}
	delete[] buff;
}

void displayModeDword(LPVOID addr, char* buff)
{
	DWORD address = (DWORD)addr;
	for (int i = 0; i < 4; i++)
	{
		printf("%08x|", address + 16 * i);
		for (int j = 0; j < 4; j++)
		{
			for (int k = 0; k < 4; k++)
			{
				byte c = (byte)buff[16 * i + 4 * j + (3 - k)];
				printf("%x", unsigned int(c));
			}
			printf(" ");
		}
		printf("\n");
	}
	delete[] buff;
}

void displayModeAscii(LPVOID addr, char* buff)
{
	printf("%08x|", addr);
	for (int i = 0; i < strlen(buff); i++)
	{
		if (buff[i] < 127 && buff[i]>31)
			printf("%c", buff[i]);
		else
		{
			printf("\n");
			break;
		}
	}
	delete[] buff;
}

void displayMemory(LPVOID addr, int mode = 0)
{
	//
	// mode = 0   ---> bb
	// mode = 1   ---> bd
	// mode = 2   ---> ba
	//

	char* buff = new char[65];
	ZeroMemory(buff, 65);
	cout << "地址    |      内容       " << endl;
	DWORD dwWrite = 0;
	ReadProcessMemory(hProcess,
		addr,
		buff,
		64,
		&dwWrite
		);

	switch (mode)
	{
	case 1:
		displayModeDword(addr, buff);
		break;
	case 2:
		displayModeAscii(addr, buff);
		break;
	default:
		displayModeByte(addr, buff);
		break;
	}
}

void editMemoryByte(LPVOID addr, byte b)
{
	DWORD dwSize = 0;
	byte localByte = b;
	WriteProcessMemory(hProcess, addr, &localByte, 1, &dwSize);
}

void editMemoryDword(LPVOID addr, DWORD dw)
{
	DWORD dwSize = 0;
	DWORD localDword = dw;
	WriteProcessMemory(hProcess, addr, &localDword, 4, &dwSize);
}

void disassembly(LPVOID addr, int nNum)
{
	char buff[500];
	int total = 0;

	// 打印代码信息
	cout << "地  址   | " << "             机器码             | " << "指令\n";

	// 读取指令信息
	while (total < nNum)
	{
		DWORD dwWrite = 0;
		ReadProcessMemory(hProcess,
			addr,
			buff,
			500,
			&dwWrite
			);

		// 反汇编代码
		cs_insn* ins = nullptr;

		int count = 0;
		count = cs_disasm(handle,
			(uint8_t*)buff,
			120,
			(DWORD)addr,
			0,
			&ins
			);
		
		int printNum;
		if (count < nNum - total)
		{
			printNum = count;
		}
		else
		{
				printNum = nNum - total;
		}

		for (int i = 0; i <= printNum; ++i)
		{
			printf("%08X | ", ins[i].address);

			for (int j = 0; j < 16; j += 2)
			{
				if (ins[i].bytes[j] == 0xcd)
				{
					printf("  ");
				}
				else
					printf("%02x", ins[i].bytes[j]);

				if (ins[i].bytes[j+1] == 0xcd)
				{
					printf("  ");
				}
				else
					printf("%02x",  ins[i].bytes[j + 1]);
			}

			printf("|");

			printf("%s %s\n", ins[i].mnemonic, ins[i].op_str);
		}

		total += count;

		cs_free(ins, count);
	}
}

void Assembler(string instruction, LPVOID addr)
{

	const char* cmd = instruction.c_str();
	DWORD address = (DWORD)addr;
	ks_engine *ks;
	ks_err err;
	size_t count;
	unsigned char *encode;
	size_t size;

	err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
	if (err != KS_ERR_OK) {
		printf("ERROR: failed on ks_open(), quit\n");
		return ;
	}

	if (ks_asm(ks, cmd, 0, &encode, &size, &count) != KS_ERR_OK) {
		printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
			count, ks_errno(ks));
	}
	else {
		size_t i;

		printf("%s = ", cmd);
		for (i = 0; i < size; i++) {
			printf("%02x ", encode[i]);
			byte c = (byte)encode[i];
			editMemoryByte((LPVOID)(address + i), c);
		}
		printf("\n");
		printf("Compiled: %lu bytes, statements: %lu\n", size, count);
	}

	// NOTE: free encode after usage to avoid leaking memory
	ks_free(encode);

	// close Keystone instance when done
	ks_close(ks);
}