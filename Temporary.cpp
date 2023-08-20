#include <iostream>
#include <Windows.h>

using namespace std;

#define PE_FILES {"./assets/cmmon32.exe", "./assets/kernel32.dll", "./assets/peparser.dll"}

#ifdef PRINT_INFO
#include "DebugInfo.h"
#endif

int main(int argc, char* argv[])
{
	//if (argc != 2)
	//{
	//	printf("Usage: %s <PEFilePath>\n", argv[0]);
	//	return EXIT_FAILURE;
	//}

	const char* peFiles[] = PE_FILES;

	cout << "Enter file index: ";
	int fileIndex;
	cin >> fileIndex;

	const char* peFilePath = peFiles[fileIndex];
	HANDLE peFileHandle = CreateFileA(peFilePath, GENERIC_READ | GENERIC_WRITE,
		0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (peFileHandle == INVALID_HANDLE_VALUE)
	{
		cerr << "Can't open file " << peFilePath << "\nError: " << GetLastError() << endl;
		exit(EXIT_FAILURE); // what is exit function itself
	}

	IMAGE_DOS_HEADER dosHeader = { 0 };
	DWORD bytesWritten = 0;

	if (!ReadFile(peFileHandle, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesWritten, NULL))
	{
		cerr << "Error reading the DOS header: " << GetLastError() << endl;
		CloseHandle(peFileHandle);
		exit(EXIT_FAILURE);
	}

	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		cerr << "Error: this is not a valid PE file" << endl;
		CloseHandle(peFileHandle);
		exit(EXIT_FAILURE);
	}

	DWORD peHeaderOffset = dosHeader.e_lfanew;

	cout << "pe header offset: " << peHeaderOffset << endl;

	// Seek to the PE header offset and read the PE header
	if (SetFilePointer(peFileHandle, peHeaderOffset, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		cerr << "Error changing file pointer: " << GetLastError() << endl;
		CloseHandle(peFileHandle);
		exit(EXIT_FAILURE);
	}

	DWORD peFileSignature = 0;
	if (!ReadFile(peFileHandle, &peFileSignature, sizeof(DWORD), &bytesWritten, NULL))
	{
		cerr << "Error reading IMAGE_NT_SIGNATURE: " << GetLastError() << endl;
		CloseHandle(peFileHandle);
		exit(EXIT_FAILURE);
	}

	if (peFileSignature != IMAGE_NT_SIGNATURE) // note: https://www.gdatasoftware.com/blog/pebitnesstrick
	{
		cerr << "Error: this is not a valid PE file" << endl;
		CloseHandle(peFileHandle);
		exit(EXIT_FAILURE);
	}

	IMAGE_FILE_HEADER peFileHeader = { 0 };
	if (!ReadFile(peFileHandle, &peFileHeader, sizeof(IMAGE_FILE_HEADER), &bytesWritten, NULL))
	{
		cerr << "Error reading IMAGE_FILE_HEADER: " << GetLastError() << endl;
		CloseHandle(peFileHandle);
		exit(EXIT_FAILURE);
	}

	if (peFileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		cout << "64-bit pe file" << endl;
		IMAGE_OPTIONAL_HEADER64 peFileOptionalHeader = { 0 }; // if sizeofoptionalheader -- !
		if (!ReadFile(peFileHandle, &peFileOptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER), &bytesWritten, NULL))
		{
			cerr << "Error reading IMAGE_OPTIONAL_HEADER: " << GetLastError() << endl;
			CloseHandle(peFileHandle);
			exit(EXIT_FAILURE);
		}

		IMAGE_NT_HEADERS64 peFileNTHeaders = { 0 };
		peFileNTHeaders.Signature = peFileSignature;
		peFileNTHeaders.FileHeader = peFileHeader;
		peFileNTHeaders.OptionalHeader = peFileOptionalHeader;
#ifdef PRINT_INFO
		printInfoNTHeaders64(&peFileNTHeaders);
#endif
		printf("VA of import table: %llX\n", peFileOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	}
	else if (peFileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		cout << "32-bit pe file" << endl;
	}
	else
	{
		cout << "Another pe file" << endl;
	}

#ifdef PRINT_INFO
	cout << "Debug mode" << endl;
	printInfoDosHeader(&dosHeader);
#endif

	cout << "Header closed: " << CloseHandle(peFileHandle) << endl;
	return EXIT_SUCCESS;
}