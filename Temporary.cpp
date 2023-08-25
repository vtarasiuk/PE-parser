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
  // Section 1 remarks
  // Take path to file from command line arguments
  const char* filePath = "./peparser.dll";

  // Section 2 remarks
  // Add error handling with enum
  HANDLE hPeFile = CreateFileA(filePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hPeFile == INVALID_HANDLE_VALUE) cout << "Error 1" << endl;
  HANDLE hPeFileMapping = CreateFileMappingA(hPeFile, NULL, PAGE_READWRITE, 0, 0, NULL);
  if (hPeFileMapping == NULL) cout << "Error 2" << endl;
  LPVOID peFileContent = MapViewOfFile(hPeFileMapping, FILE_MAP_READ, 0, 0, 0);
  if (peFileContent == NULL) cout << "Error 3" << endl;

  // Section 3 remarks
  // Use NT_HEADERS
  // PIMAGE_NT_HEADERS64 lpPeFileNTHeaders64 = nullptr;
  // PIMAGE_NT_HEADERS32 lpPeFileNTHeaders32 = nullptr;
  // BOOLEAN isPEFile64Bit = false;

  PIMAGE_DOS_HEADER peFileDOSHeader = (PIMAGE_DOS_HEADER)peFileContent;
  PIMAGE_FILE_HEADER peFileHeader = (PIMAGE_FILE_HEADER)((LPBYTE)peFileContent + peFileDOSHeader->e_lfanew + sizeof(DWORD));
  PIMAGE_OPTIONAL_HEADER64 peFileOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)((LPBYTE)peFileHeader + sizeof(IMAGE_FILE_HEADER));
  PIMAGE_SECTION_HEADER peFileSectionHeaders = (PIMAGE_SECTION_HEADER)((LPBYTE)peFileOptionalHeader + peFileHeader->SizeOfOptionalHeader);

  DWORD importTableVirtualAddress = peFileOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress; // temp
  WORD importTableSectionIndex = 0;
  for (WORD i = 0; i < peFileHeader->NumberOfSections; i++)
  {
    IMAGE_SECTION_HEADER sectionHeader = peFileSectionHeaders[i];

    if (importTableVirtualAddress > sectionHeader.VirtualAddress && importTableVirtualAddress < sectionHeader.VirtualAddress + sectionHeader.Misc.VirtualSize)
    {
      importTableSectionIndex = i;
    }
  }

  cout << "Import table is located in " << peFileSectionHeaders[importTableSectionIndex].Name << " section" << endl;

  DWORD importTableRVA = peFileOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
  DWORD sectionOfImportTableRVA = peFileSectionHeaders[importTableSectionIndex].VirtualAddress;
  DWORD rawDataPointerImportTableSection = peFileSectionHeaders[importTableSectionIndex].PointerToRawData;

  DWORD rawOffsetToImportTable = importTableRVA - sectionOfImportTableRVA + rawDataPointerImportTableSection;

  DWORD importDescriptorsCount = 0;
  PIMAGE_IMPORT_DESCRIPTOR importDescriptorEntry = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)peFileContent + rawOffsetToImportTable);
  while (!(importDescriptorEntry[importDescriptorsCount].OriginalFirstThunk == 0 && importDescriptorEntry[importDescriptorsCount].FirstThunk == 0))
  {
    importDescriptorsCount += 1;
  }
  // may be helpful
  /*

  #define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

  */
  cout << "Import Descriptors count: " << dec << importDescriptorsCount << endl;

  for (size_t i = 0; i < importDescriptorsCount; i++)
  {
    LPBYTE libName = (LPBYTE)((LPBYTE)peFileContent + importDescriptorEntry[i].Name - sectionOfImportTableRVA + rawDataPointerImportTableSection);
    cout << libName << endl;
    ULONGLONG* funcAddress = (ULONGLONG*)((LPBYTE)peFileContent + (importDescriptorEntry + i)->OriginalFirstThunk - sectionOfImportTableRVA + rawDataPointerImportTableSection);

    DWORD functionIndex = 0;
    while (*(funcAddress + functionIndex))
    {
      if (*(funcAddress + functionIndex) & IMAGE_ORDINAL_FLAG)
      {
        cout << "\t" << functionIndex + 1 << " " << hex << *(funcAddress + functionIndex) << endl;
        functionIndex += 1;
        continue;
      }
      PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)peFileContent + *(funcAddress + functionIndex) - sectionOfImportTableRVA + rawDataPointerImportTableSection);
      cout << dec << "\t" << functionIndex + 1 << " Name: " << functionName->Name << endl;
      functionIndex += 1;
    }
  }

  UnmapViewOfFile(peFileContent);
  CloseHandle(hPeFileMapping);
  CloseHandle(hPeFile);
}

// may be helpful
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