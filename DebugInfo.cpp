#include "DebugInfo.h"
#include <iostream>
#include <iomanip>

VOID printInfoDosHeader(PIMAGE_DOS_HEADER lpDosHeader)
{
	printf(" DOS HEADER:\n");
	printf(" -----------\n\n");

	printf(" Magic: 0x%X\n", lpDosHeader->e_magic);
	printf(" Address of pe file header: 0x%X\n", lpDosHeader->e_lfanew);
}

VOID printInfoNTHeaders64(PIMAGE_NT_HEADERS64 peFileNTHeaders)
{
	IMAGE_FILE_HEADER peFileHeader = peFileNTHeaders->FileHeader;
	IMAGE_OPTIONAL_HEADER64 peFileOptionalHeader = peFileNTHeaders->OptionalHeader;

	printf(" NT HEADERS:\n");
	printf(" -----------\n\n");

	printf(" PE Signature: 0x%X  |  %d\n", peFileNTHeaders->Signature, peFileNTHeaders->Signature);

	printf("\n File Header:\n\n");
	printf("   Machine: 0x%X  |  %d\n", peFileHeader.Machine, peFileHeader.Machine);
	printf("   Number of sections: 0x%X  |  %d\n", peFileHeader.NumberOfSections, peFileHeader.NumberOfSections);
	printf("   Size of optional header: 0x%X  |  %d\n", peFileHeader.SizeOfOptionalHeader, peFileHeader.SizeOfOptionalHeader);

	printf("\n Optional Header:\n\n");
	printf("   Magic: 0x%X  |  %d\n", peFileOptionalHeader.Magic, peFileOptionalHeader.Magic);
	printf("   Size of code section: 0x%X  |  %d\n", peFileOptionalHeader.SizeOfCode, peFileOptionalHeader.SizeOfCode);
	printf("   Size of initialized data: 0x%X  |  %d\n", peFileOptionalHeader.SizeOfInitializedData, peFileOptionalHeader.SizeOfInitializedData);
	printf("   Size of uninitialized data: 0x%X  |  %d\n", peFileOptionalHeader.SizeOfUninitializedData, peFileOptionalHeader.SizeOfUninitializedData);
	printf("   Address of entry point: 0x%X  |  %d\n", peFileOptionalHeader.AddressOfEntryPoint, peFileOptionalHeader.AddressOfEntryPoint);
	printf("   RVA of start of code section: 0x%X  |  %d\n", peFileOptionalHeader.BaseOfCode, peFileOptionalHeader.BaseOfCode);
	printf("   Desired image base: 0x%llX  |  %d\n", peFileOptionalHeader.ImageBase, peFileOptionalHeader.ImageBase);
	printf("   Section alignment: 0x%X  |  %d\n", peFileOptionalHeader.SectionAlignment, peFileOptionalHeader.SectionAlignment);
	printf("   File alignment: 0x%X  |  %d\n", peFileOptionalHeader.FileAlignment, peFileOptionalHeader.FileAlignment);
	printf("   Size of image: 0x%X  |  %d\n", peFileOptionalHeader.SizeOfImage, peFileOptionalHeader.SizeOfImage);
	printf("   Size of headers: 0x%X  |  %d\n", peFileOptionalHeader.SizeOfHeaders, peFileOptionalHeader.SizeOfHeaders);
	printf("   Image base: 0x%llX\n", peFileOptionalHeader.ImageBase);

	printf("\n Data Directories:\n");
	printf("\n   * Export Directory:\n");
	printf("       RVA: 0x%X  |  %d\n", peFileOptionalHeader.DataDirectory->VirtualAddress, peFileOptionalHeader.DataDirectory->VirtualAddress);
	printf("       Size: 0x%X  |  %d\n", peFileOptionalHeader.DataDirectory->Size, peFileOptionalHeader.DataDirectory->Size);
}