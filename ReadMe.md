SmallDebuggerConsole

；This project is a small demo, in fact, a homework of 15PB, 
；this debugger is based on c++, windows programming,
；using capstone as disassembly engine and keystone as assembler engine,

usage:
1. exection:
	g	；go
	t   ；step into
	p   ；step out
2. breakpoint
	bp	address		； software breakpoint
	ba  address		； hardware breakpoint
	bm	address		； memory breakpoint
	bapi ApiName	； API breakpoint
	bt	address		； condition breakpoint
	bc	num			； clean a breakpoint
3. edit memory
	ed	memory		； edit a memory (DWORD)
	eb	memory		； edit a memory	(BYTE)
	a   address		； write an assembly
4. display
	h				； show the help information
	k				； show the calling stack (just user mode)
	r				； show registers information
	bl				； show breakpoint list
	lm				； show module information
	exchain			； show SEH chain
	s (num)			； show stack 
	x address		； show code information of this memory 
	u (addr) (num)	； disassembly
	dd address		； show memory (dword)
	db address		； show memory (byte)
	da address		； show memory (ASCII)
	export address	； show export table
	import address	； show import table
5. dump
	dump			； which will create "Mydump.dmp" in current path