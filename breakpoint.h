#pragma once
#include "stdafx.h"
#include "global.h"


class breakpoint
{
public:
	LPVOID address;
	char oldbyte;
	int type;
public:
	breakpoint(LPVOID address) :address(address){}
	breakpoint(){}
	virtual ~breakpoint(){};
	virtual bool install()=0;
	virtual void repair()=0;
	virtual bool isCurrent(LPVOID br)=0;
	virtual void show()=0;
};

class bp_int3 : public breakpoint
{
public:
	bp_int3(){}
	bp_int3(LPVOID address) :breakpoint(address)
	{
		this->type = SOFTWARE_BREAKPOINT;
		setOldType();
	}
	~bp_int3(){}
	bool install();
	void repair();
	bool isCurrent(LPVOID br);
	void show();
	void setOldType();
};

class bp_hdr : public breakpoint
{
public:
	bp_hdr(LPVOID address) : breakpoint(address)
	{
		this->type = HARDWARE_BREAKPOINT;
	}
	~bp_hdr(){}
	bool install();
	void repair();
	bool isCurrent(LPVOID br);
	void show();
};

class bp_hdr_rw : public breakpoint
{
public:
	bp_hdr_rw(LPVOID address, DWORD dwLen) :breakpoint(address), dwLen(dwLen)
	{
		this->type = HARDWARE_RW_BREAKPOINT;
		DWORD addr = (DWORD)(this->address);
		if (this->dwLen == 1)
		{
			(this->address) = (LPVOID)(addr - addr % 2);
		}
		else if (dwLen == 3)
		{
			(this->address) = (LPVOID)(addr - addr % 4);
		}
		else
		{
			this->dwLen = 0;
		}
	}
	~bp_hdr_rw(){}
	bool install();
	void repair();
	bool isCurrent(LPVOID br);
	void show();
public:
	DWORD dwLen;
};

class bp_mm : public breakpoint
{
public:
	bp_mm(LPVOID address) :breakpoint(address)
	{
		this->type = MEMORY_BREAKPOINT;
	}
	~bp_mm(){}
	bool install();
	void repair();
	bool isCurrent(LPVOID br);
	void show();
	void cancel();
public:
	DWORD OldProtect;
	DWORD dwBase;
	DWORD dwRegion;
};

void setBreakpoint_tf();
void disableBreakpoint_tf();
