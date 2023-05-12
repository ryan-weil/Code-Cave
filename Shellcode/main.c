#include "main.h"

_declspec (naked) main()
{
	__asm
	{
		pushad
		pushfd
	}

	// If you do not mark it as volate, it will put it in the .rdata section, which will create relocs in the shellcode
	//volatile char text[] = "Injected!";
	(*(t_MessageBoxA*)(0xAAAAAAAA))(0,0,0,0);

	__asm
	{
		popfd
		popad
		_emit 0xE9 __asm _emit 0xBB __asm _emit 0xBB __asm _emit 0xBB __asm _emit 0xBB // jmp to OEP (SHELLCODE_JMP_OFFSET)
	}
}