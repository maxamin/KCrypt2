
# PE Modification Library Documentation

## Overview

This PE (Portable Executable) modification library provides functionality for manipulating PE files on Windows, including encryption, section addition, and code injection. It supports custom encryption using RC4 and the injection of a custom stub into PE files.

### Key Features:
- Encrypt sections of PE files using RC4.
- Add new sections to PE files.
- Modify PE headers and manage file/virtual address translations.
- Inject custom code (stub) into a PE file.
- Handle TLS (Thread Local Storage) and import tables.

## Functions

### `RC4(LPBYTE lpBuf, LPBYTE lpKey, DWORD dwBufLen, DWORD dwKeyLen)`
Implements RC4 encryption/decryption on a buffer.

- `lpBuf`: Pointer to the buffer to be encrypted or decrypted.
- `lpKey`: Encryption key.
- `dwBufLen`: Length of the buffer.
- `dwKeyLen`: Length of the encryption key.

### `FileToVa(DWORD dwFileAddr, PIMAGE_NT_HEADERS pNtHeaders)`
Converts a file address (file offset) to a virtual address (VA) in memory. This is often necessary when working with PE files, as sections may have different positions in memory and on disk.

- `dwFileAddr`: Address in the file to convert.
- `pNtHeaders`: Pointer to the PE's NT headers.

### `VaToFile(DWORD dwVirtAddr, PIMAGE_NT_HEADERS pNtHeaders)`
Converts a virtual address (VA) to a file offset. This helps map virtual memory addresses to the file's structure.

### `LoadFile(LPCTSTR lpszFileName, DWORD dwStubSize)`
Loads a file into memory, returning a structure that maps the file. This is a utility for working with the file in memory.

- `lpszFileName`: File path.
- `dwStubSize`: Size of the stub (optional).

### `UnloadFile(LPMAPINFO lpMapInfo)`
Unmaps a previously loaded file from memory.

### `AddSection(PCHAR szName, DWORD dwSize, PIMAGE_NT_HEADERS pNtHeaders)`
Adds a new section to the PE file.

- `szName`: Name of the section.
- `dwSize`: Size of the new section.
- `pNtHeaders`: Pointer to the PE's NT headers.

### `CalcNewChecksum(LPMAPINFO lpMapInfo)`
Calculates a new checksum for the PE file after modifications.

### `CryptFile(const char *target, const char *stub, const char mode, const char *szKey)`
Handles the main logic of injecting a stub into the PE file and optionally encrypting sections.

- `target`: Path to the target PE file.
- `stub`: Path to the stub to inject.
- `mode`: Mode of operation ('n' for adding a new section).
- `szKey`: Encryption key for RC4.

## Usage Example

Here is an example of how to use this library to encrypt sections and inject a stub:

```cpp
BOOL success = CryptFile("target.exe", "stub.bin", 'n', "encryptionkey123");
if(success) {
    printf("PE file modified successfully.");
} else {
    printf("Failed to modify the PE file.");
}
```

## Dependencies
- Windows-specific libraries like `imagehlp.h` for PE handling.
- Functions like `CreateFile`, `MapViewOfFile`, `ImageNtHeader`, and `CheckSumMappedFile` are used to manipulate the PE structure.

## Credits
- **KOrUPt**: Original developer.
- **Napalm**: Contributor of address translation functions.
- **Irwin**: Contributor of file mapping and loading functions.
- **Ashkbiz Danehkar**: Provided the original section addition code.
