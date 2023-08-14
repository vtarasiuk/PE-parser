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

	const DWORD dwfileSize = GetFileSize(peFileHandle, NULL);
	if (dwfileSize == INVALID_FILE_SIZE)
	{
		cerr << "Eror: " << GetLastError() << endl;
		CloseHandle(peFileHandle);
		exit(EXIT_FAILURE);
	}
	char* rawFile = new char[dwfileSize + 1];
	if (rawFile == NULL)
	{
		cerr << "Error while memory allocation" << endl;
		CloseHandle(peFileHandle);
		exit(EXIT_FAILURE);
	}

	DWORD bytesWritten = 0;
	if (!ReadFile(peFileHandle, rawFile, dwfileSize, &bytesWritten, NULL)) // bytesReads
	{
		cerr << "Error: " << GetLastError() << endl;
		delete[] rawFile;
		CloseHandle(peFileHandle);
		exit(EXIT_FAILURE);
	}
	cout << "BytesRead: " << bytesWritten << endl;

	if (rawFile[0] != 'M' && rawFile[1] != 'Z') // validating a file !!! size of the file careful
	{
		cerr << "Error: this is not a valid file" << endl;
		delete[] rawFile;
		CloseHandle(peFileHandle);
		exit(EXIT_FAILURE);
	}

	DWORD peHeaderPointer = SetFilePointer(peFileHandle, 0x3C, NULL, FILE_BEGIN);
	if (peHeaderPointer == INVALID_SET_FILE_POINTER)
	{
		cerr << "Error: " << GetLastError() << endl;
		delete[] rawFile;
		CloseHandle(peFileHandle);
		exit(EXIT_FAILURE);
	}
	cout << "peHeader = " << peHeaderPointer << endl;

	DWORD peHeaderOffset;
	if (!ReadFile(peFileHandle, &peHeaderOffset, sizeof(peHeaderOffset), &bytesWritten, NULL) || bytesWritten != 4)
	{
		cerr << "Error: " << GetLastError() << endl;
		delete[] rawFile;
		CloseHandle(peFileHandle);
		exit(EXIT_FAILURE);
	}

	cout << "pe header offset: " << peHeaderOffset << endl;

	// Seek to the PE header offset and read the PE header
	if (SetFilePointer(peFileHandle, peHeaderOffset, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		cerr << "Error: " << GetLastError() << endl;
		delete[] rawFile;
		CloseHandle(peFileHandle);
		exit(EXIT_FAILURE);
	}

	DWORD peSignature;
	ReadFile(peFileHandle, &peSignature, sizeof(peSignature), &bytesWritten, NULL);

	if (peSignature != 0x00004550) // PE/0/0 note: https://www.gdatasoftware.com/blog/pebitnesstrick
	{
		cerr << "Error: this file isn't PE file format" << endl;
		// ... another cleaning
	}

	WORD machineType;
	ReadFile(peFileHandle, &machineType, sizeof(machineType), &bytesWritten, NULL);
	cout << "Type: " << hex << machineType << dec << endl;
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		cout << "64-bit pe file" << endl;
	}
	else if (machineType == IMAGE_FILE_MACHINE_I386)
	{
		cout << "32-bit pe file" << endl;
	}
	else
	{
		cout << "Another pe file" << endl;
	}

	cout << "Header closed: " << CloseHandle(peFileHandle) << endl;
	delete[] rawFile;
	return EXIT_SUCCESS;
}