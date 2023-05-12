#include "main.h"

PIMAGE_SECTION_HEADER pISH;

// Converts an RVA to a raw offset
ULONG RvaToOffset(PIMAGE_NT_HEADERS pnth, ULONG Rva)
{
	PIMAGE_SECTION_HEADER psh = IMAGE_FIRST_SECTION(pnth);
	USHORT NumberOfSections = pnth->FileHeader.NumberOfSections;

	for (int i = 0; i < NumberOfSections; i++)
		if (psh[i].VirtualAddress <= Rva && (psh[i].VirtualAddress + psh[i].Misc.VirtualSize) > Rva)
			return Rva - psh[i].VirtualAddress + psh[i].PointerToRawData;

	return -1;
}

// Returns a pointer to MessageBoxA from the Imports
DWORD GetFunctionAddress(PVOID base, LPCSTR name)
{
	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS pNTH = (PIMAGE_NT_HEADERS)((DWORD)pIDH + pIDH->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR pDescriptor =
		(PIMAGE_IMPORT_DESCRIPTOR)((char*)base + RvaToOffset(pNTH, pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));

	while (pDescriptor->Name)
	{
		LPCSTR pDllName = (LPCSTR)((char*)base + RvaToOffset(pNTH, pDescriptor->Name));
		HMODULE hDll = LoadLibraryA(pDllName);

		if (hDll)
		{
			PIMAGE_THUNK_DATA pThunk;
			PIMAGE_THUNK_DATA pAddrThunk;

			if (pDescriptor->OriginalFirstThunk)
			{
				pThunk = (PIMAGE_THUNK_DATA)((char*)base + RvaToOffset(pNTH, pDescriptor->OriginalFirstThunk));
			}
			else
			{
				pThunk = (PIMAGE_THUNK_DATA)((char*)base + RvaToOffset(pNTH, pDescriptor->FirstThunk));
			}

			pAddrThunk = (PIMAGE_THUNK_DATA)((char*)base + RvaToOffset(pNTH, pDescriptor->FirstThunk));

			PIMAGE_THUNK_DATA pAddrThunk2 = (PIMAGE_THUNK_DATA)((DWORD)0x00400000 + pDescriptor->FirstThunk);
			while (pThunk->u1.AddressOfData)
			{
				PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)((char*)base + RvaToOffset(pNTH, pThunk->u1.AddressOfData));
				if (!strcmp(pImport->Name, name))
				{
					DWORD a = pAddrThunk - (PIMAGE_THUNK_DATA)base + (pISH[1].VirtualAddress - pISH[1].PointerToRawData);
					return (DWORD)pAddrThunk2;
				}

				pThunk++;
				pAddrThunk++;
				pAddrThunk2++;
			}
		}

		pDescriptor++;
	}

	return 0;
}

// Process relocations
void CreateRelocs(LPVOID lpMapped, uintptr_t functionAddress)
{
	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)lpMapped;
	PIMAGE_NT_HEADERS pNTH = (PIMAGE_NT_HEADERS)((DWORD)pIDH + pIDH->e_lfanew);
	PIMAGE_BASE_RELOCATION pRelocTable =
		(PIMAGE_BASE_RELOCATION)((char*)lpMapped + RvaToOffset(pNTH, pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));

	uintptr_t pRelocTableLast = (uintptr_t)pRelocTable + pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	while (pRelocTable->SizeOfBlock)
	{
		short* pRelocationData = (short*)((char*)pRelocTable + sizeof(IMAGE_BASE_RELOCATION));
		int NumberOfRelocationData = (pRelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(short);

		PIMAGE_BASE_RELOCATION pNextRelocTable = (PIMAGE_BASE_RELOCATION)((char*)pRelocTable + pRelocTable->SizeOfBlock);
		if (pNextRelocTable->VirtualAddress < functionAddress)
		{
			pRelocTable = (PIMAGE_BASE_RELOCATION)((char*)pRelocTable + pRelocTable->SizeOfBlock);
			continue;
		}

		short relocToInsert = (IMAGE_REL_BASED_HIGHLOW << 0xC) + functionAddress - pRelocTable->VirtualAddress; // This is the reloc we are injecting
			
		for (int i = 0; i < NumberOfRelocationData; i++)
		{
			if (pRelocationData[i] > relocToInsert // Address is bigger
				|| ((PIMAGE_BASE_RELOCATION)((char*)pRelocTable + pRelocTable->SizeOfBlock) == 0 && (pRelocationData[i] >> 0xC) == IMAGE_REL_BASED_ABSOLUTE)) // Hit the end of the last reloc table
			{
				/***********Insert Relocation***********/
				uintptr_t source = (uintptr_t)pRelocationData + i * 2;
				uintptr_t dest = (uintptr_t)pRelocationData + i * 2 + 2;
				SIZE_T length = ((uintptr_t)pRelocTableLast) - source;

				memmove((short*)dest, (short*)source, length);
				pRelocationData[i] = relocToInsert;
				pRelocTable->SizeOfBlock += 2;
				//NumberOfRelocationData++;

				/**************Fix Padding**************/

				if (pRelocationData[NumberOfRelocationData] >> 0xC == IMAGE_REL_BASED_ABSOLUTE)
				{
					uintptr_t source2 = (uintptr_t)pRelocationData + NumberOfRelocationData * 2;
					uintptr_t dest2 = (uintptr_t)pRelocationData + NumberOfRelocationData * 2 - 2;
					SIZE_T length2 = ((uintptr_t)pRelocTableLast) - source2;

					memmove((short*)dest2, (short*)source2, length2);
					pRelocTable->SizeOfBlock -= 2;
				}
				else
				{
					uintptr_t source2 = (uintptr_t)pRelocationData + NumberOfRelocationData * 2 + 2;
					uintptr_t dest2 = (uintptr_t)pRelocationData + NumberOfRelocationData * 2 + 4;
					SIZE_T length2 = ((uintptr_t)pRelocTableLast) - source2;

					memmove((short*)dest2, (short*)source2, length2);
					pRelocationData[NumberOfRelocationData + 1] = 0;
					pRelocTable->SizeOfBlock += 2;
				}

				return;
			}
		}
	}
}

// Returns an insertion point
int GetInsertionPoint(LPVOID lpMapped, PIMAGE_DOS_HEADER pIDH, PIMAGE_NT_HEADERS pNTH, int& sectionNumber)
{
	SIZE_T InsertionPointOffset = 0;
	int countZeroes = 0;

	// Loop through each section
	for (sectionNumber = 0; sectionNumber < pNTH->FileHeader.NumberOfSections; sectionNumber++)
	{
		// Loop through each byte in section
		for (int j = 0; j < pISH[sectionNumber].SizeOfRawData; j++)
		{
			// Break if we've reached a large enough size to insert the shellcode
			if (sectionNumber != 1 && countZeroes == sizeof(shellcode) + 16 /*To avoid damaging other code, be safe and get a head start of 16 bytes*/)
			{
				InsertionPointOffset = pISH[sectionNumber].PointerToRawData + j - countZeroes + 16;
				printf("Found suitable insertion at point 0x%p, which is in %s\n", InsertionPointOffset, pISH[sectionNumber].Name);
				break;
			}
			// Check if byte is zero
			else if (*((LPBYTE)lpMapped + pISH[sectionNumber].PointerToRawData + j) == 0)
			{
				countZeroes++;
			}
			// Reset counter if we've reached a non-zero;
			else
			{
				countZeroes = 0;
			}
		}

		if (InsertionPointOffset)
			break;
	}

	return InsertionPointOffset;
}

int main(int argc, char** argv)
{
	printf("Opening File: %s\n", argv[1]);
	HANDLE hFile = CreateFile(argv[1], FILE_READ_ACCESS | FILE_WRITE_ACCESS, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile)
		return -1;
	printf("Created handle to file: 0x%X\n", hFile);

	HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (!hMapping)
		return -1;
	printf("Created file mapping for: 0x%X\n", hMapping);

	LPVOID lpMapped = MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (!lpMapped)
		return -1;
	printf("Mapped view of file: 0x%X\n", lpMapped);

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)lpMapped;
	PIMAGE_NT_HEADERS pNTH = (PIMAGE_NT_HEADERS)((UINT_PTR)pIDH + pIDH->e_lfanew);
	pISH = IMAGE_FIRST_SECTION(pNTH);

	int sectionIndex;
	int InsertionPointOffset = GetInsertionPoint(lpMapped, pIDH, pNTH, sectionIndex);
	if (!InsertionPointOffset)
		return -1;

	pISH[sectionIndex].Characteristics |= IMAGE_SCN_MEM_EXECUTE;
	printf("Set %s characteristics to IMAGE_SCN_MEM_EXECUTE\n", pISH[sectionIndex].Name);

	uintptr_t functionAddr = GetFunctionAddress(lpMapped, "MessageBoxA");
	if (!functionAddr)
	{
		printf("The specified API does not exist in the program's IAT!");
		getchar();
		return -1;
	}
		
	*(uintptr_t*)(shellcode + MESSAGEBOXA_OFFSET) = functionAddr; // Add MessageBoxA
	uintptr_t rva = pNTH->OptionalHeader.AddressOfEntryPoint - pISH[sectionIndex].VirtualAddress - (InsertionPointOffset - pISH[sectionIndex].PointerToRawData) - (SHELLCODE_JMP_ADR_OFFSET + 4); //JMP to original Entrypoint
	*(uintptr_t*)(shellcode + SHELLCODE_JMP_ADR_OFFSET) = rva;

	pNTH->OptionalHeader.AddressOfEntryPoint = InsertionPointOffset + pISH[sectionIndex].VirtualAddress - pISH[sectionIndex].PointerToRawData;

	for (int i = 0; i < sizeof(shellcode); i++)
	{
		((LPBYTE)lpMapped + InsertionPointOffset)[i] = shellcode[i];
	}

	if (RvaToOffset(pNTH, pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) != -1)
	{
		printf("File has relocations\n");
		CreateRelocs(lpMapped, (InsertionPointOffset - pISH[sectionIndex].PointerToRawData) + MESSAGEBOXA_OFFSET);
	}

	UnmapViewOfFile(lpMapped);
	CloseHandle(hMapping);
	CloseHandle(hFile);

	printf("Done\n");

	(void)getchar();
}