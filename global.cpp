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