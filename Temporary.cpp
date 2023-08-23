#include <iostream>
#include <windows.h>
#include <exception>

using namespace std;

/*
typedef struct
{
  HANDLE Handle;
  HANDLE Mapping;
  LPVOID Content;
} PEFile;
*/

// PEFile* Open_and_Map_File(PEFile *file, const LPBYTE filePath);

int main()
{
  const char* filePath = "./assets/peparser.dll";
  HANDLE hPeFile = CreateFileA(filePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hPeFile == INVALID_HANDLE_VALUE) cout << "Error 1" << endl;
  HANDLE hPeFileMapping = CreateFileMappingA(hPeFile, NULL, PAGE_READWRITE, 0, 0, NULL);
  if (hPeFileMapping == NULL) cout << "Error 2" << endl;
  LPVOID peFileContent = MapViewOfFile(hPeFileMapping, FILE_MAP_READ, 0, 0, 0);
  if (peFileContent == NULL) cout << "Error 3" << endl;

  PIMAGE_DOS_HEADER peFileDOSHeader = (PIMAGE_DOS_HEADER)peFileContent;
  PIMAGE_FILE_HEADER peFileHeader = (PIMAGE_FILE_HEADER)((BYTE*)peFileContent + peFileDOSHeader->e_lfanew + sizeof(DWORD));
  cout << "File Header" << endl;
  cout << hex << peFileHeader->Machine << endl;
  cout << dec << peFileHeader->NumberOfSections << endl;
  cout << dec << peFileHeader->SizeOfOptionalHeader << endl << endl;
  PIMAGE_OPTIONAL_HEADER64 peFileOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)((BYTE*)peFileHeader + sizeof(IMAGE_FILE_HEADER));
  cout << "Optional Header" << endl;
  cout << hex << peFileOptionalHeader->Magic << endl;
  cout << hex << peFileOptionalHeader->DataDirectory[1].VirtualAddress << endl;
  cout << dec << peFileOptionalHeader->SizeOfHeaders << endl;


  PIMAGE_SECTION_HEADER peFileSectionHeaders = (PIMAGE_SECTION_HEADER)((BYTE*)peFileOptionalHeader + peFileHeader->SizeOfOptionalHeader);


  DWORD importTableVirtualAddress = peFileOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress; // temp
  BYTE importTableSectionIndex = 0;
  for (WORD i = 0; i < peFileHeader->NumberOfSections; i++)
  {
    IMAGE_SECTION_HEADER sectionHeader = peFileSectionHeaders[i];
    cout << sectionHeader.Name << endl;
    cout << hex;
    cout << "  Virtual Address: " << sectionHeader.VirtualAddress << endl;
    cout << "  Virtual Size: " << sectionHeader.Misc.VirtualSize << endl;
    cout << "  Pointer to raw data: " << sectionHeader.PointerToRawData << endl;
    cout << "  Size of raw data: " << sectionHeader.SizeOfRawData << endl;

    if (importTableVirtualAddress > sectionHeader.VirtualAddress && importTableVirtualAddress < sectionHeader.VirtualAddress + sectionHeader.Misc.VirtualSize)
    {
      importTableSectionIndex = i;
    }
  }

  cout << "Import table VA: " << peFileOptionalHeader->DataDirectory[1].VirtualAddress << endl;
  cout << "Import table is located in " << peFileSectionHeaders[importTableSectionIndex].Name << " section" << endl;

  DWORD importTableRVA = peFileOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
  DWORD sectionOfImportTableRVA = peFileSectionHeaders[importTableSectionIndex].VirtualAddress;
  DWORD rawDataPointerImportTableSection = peFileSectionHeaders[importTableSectionIndex].PointerToRawData;

  DWORD rawOffsetToImportTable = importTableRVA - sectionOfImportTableRVA + rawDataPointerImportTableSection;
  cout << "rawOffsetToImportDescriptor: " << rawOffsetToImportTable << endl;

  DWORD importDescriptorsCount = 0;
  PIMAGE_IMPORT_DESCRIPTOR importDescriptorEntry = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)peFileContent + rawOffsetToImportTable);
  while (true)
  {
    if (importDescriptorEntry[importDescriptorsCount].OriginalFirstThunk == 0 && importDescriptorEntry[importDescriptorsCount].FirstThunk == 0)
    {
      // cout << "last offset: " << offset << endl;
      break;
    }
    importDescriptorsCount += 1;
  }

  cout << "Import Descriptors count: " << dec << importDescriptorsCount << endl;
  cout << "function address: " << hex << importDescriptorEntry->OriginalFirstThunk - sectionOfImportTableRVA + rawDataPointerImportTableSection << endl;

  for (size_t i = 0; i < importDescriptorsCount; i++)
  {
    LPBYTE libName = (LPBYTE)((LPBYTE)peFileContent + importDescriptorEntry[i].Name - sectionOfImportTableRVA + rawDataPointerImportTableSection);
    cout << libName << endl;
    ULONGLONG* funcAddress = (ULONGLONG*)((BYTE*)peFileContent + (importDescriptorEntry + i)->OriginalFirstThunk - sectionOfImportTableRVA + rawDataPointerImportTableSection);

    DWORD functionIndex = 0;
    while (*(funcAddress + functionIndex))
    {
      if (*(funcAddress + functionIndex) & IMAGE_ORDINAL_FLAG)
      {
        cout << "\t" << functionIndex + 1 << " Ordinal" << endl;
        functionIndex += 1;
        continue;
      }
      PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)peFileContent + *(funcAddress + functionIndex) - sectionOfImportTableRVA + rawDataPointerImportTableSection);
      cout << dec << "\t" << functionIndex + 1 << " Name: " << functionName->Name << endl;
      functionIndex += 1;
    }
  }

  UnmapViewOfFile(peFileContent);
  CloseHandle(hPeFileMapping);
  CloseHandle(hPeFile);
}

/*
PEFile* Open_and_Map_File(PEFile *file, const LPBYTE filePath)
{
  if (file == nullptr || filePath == nullptr) {
    return FileError::InvalidArguments;
  }

  // Opening a file and mapping data
  // ...
  if ( file open fails ) {
    return FileError::FileOpenError;
  }

  if ( mapping fails ) {
    return FileError::MappingError;
  }

  return FileError::Success;
}

enum class FileError {
    Success,
    InvalidArguments,
    FileOpenError,
    MappingError
};
*/