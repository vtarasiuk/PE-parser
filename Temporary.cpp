#include <iostream>
#include <Windows.h>

using namespace std;

#define PE_32 IMAGE_FILE_MACHINE_I386
#define PE_32_PLUS 0x8664

#define PE_FILES {"./assets/cmmon32.exe", "./assets/kernel32.dll"}

int main(int argc, char* argv[])
{
	//if (argc != 2)
	//{
	//	printf("Usage: %s <PEFilePath>\n", argv[0]);
	//	return EXIT_FAILURE;
	//}

	const char *peFiles[] = PE_FILES;
	cout << "Enter file index: ";
	int fileIndex;
	cin >> fileIndex;
	const char *peFilePath = peFiles[fileIndex];
	HANDLE peFileHandle = CreateFileA(peFilePath, GENERIC_READ | GENERIC_WRITE,
																		0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if (peFileHandle == INVALID_HANDLE_VALUE)
	{
		cerr << "Error: " << GetLastError() << endl;
		exit(EXIT_FAILURE); // what is exit function itself
	}
	// open the PE file and analyze what's the type (PE32 or PE32+) respectively
	// signature - this is PE file 
	// Optional Header (Image Only) determines whether it is PE32 or PE32+

	IMAGE_DOS_HEADER dosHeader = { 0 };
	DWORD bytesWritten = 0;

	if (!ReadFile(peFileHandle, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesWritten, NULL))
	{
		cerr << "Error reading the DOS header: " << GetLastError() << endl;
		CloseHandle(peFileHandle);
		exit(EXIT_FAILURE);
	}
	
	cout << "BytesRead: " << bytesWritten << endl;

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
	
	DWORD ntSignature = 0;
	if (!ReadFile(peFileHandle, &ntSignature, sizeof(DWORD), &bytesWritten, NULL))
	{
		cerr << "Error reading IMAGE_NT_SIGNATURE: " << GetLastError() << endl;
		CloseHandle(peFileHandle);
		exit(EXIT_FAILURE);
	}

	if (ntSignature != IMAGE_NT_SIGNATURE) // note: https://www.gdatasoftware.com/blog/pebitnesstrick
	{
		cerr << "Error: this is not a valid PE file" << endl;
		CloseHandle(peFileHandle);
		exit(EXIT_FAILURE);
	}

	IMAGE_FILE_HEADER fileHeader = { 0 };
	if (!ReadFile(peFileHandle, &fileHeader, sizeof(IMAGE_FILE_HEADER), &bytesWritten, NULL))
	{
		cerr << "Error reading IMAGE_FILE_HEADER: " << GetLastError() << endl;
		CloseHandle(peFileHandle);
		exit(EXIT_FAILURE);
	}
	
	cout << "Type: " << fileHeader.Machine << endl;
	
	if (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		cout << "64-bit pe file" << endl;
	}
	else if (fileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		cout << "32-bit pe file" << endl;
	}
	else
	{
		cout << "Another pe file" << endl;
	}

	cout << "Header closed: " << CloseHandle(peFileHandle) << endl;
	return EXIT_SUCCESS;
}