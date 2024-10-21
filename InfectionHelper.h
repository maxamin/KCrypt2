#ifndef INFHELP_H
#define INFHELP_H
#include <windows.h>

typedef struct _MAPINFO {
  HANDLE  hFile;
  HANDLE  hFileMapping;
  LPBYTE  lpBuffer;
} MAPINFO, *LPMAPINFO;

BOOL CryptFile(const char *target, const char *stub, const char mode, const char *szKey);
#endif