#pragma once
#include <Windows.h>

VOID printInfoDosHeader(PIMAGE_DOS_HEADER lpDosHeader);
VOID printInfoNTHeaders64(PIMAGE_NT_HEADERS64 peFileNTHeaders);