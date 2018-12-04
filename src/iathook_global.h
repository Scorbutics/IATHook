#ifndef IATHOOK_GLOBAL_H
#define IATHOOK_GLOBAL_H

#if defined(IATHOOK_LIBRARY)
#  define IATHOOKSHARED_EXPORT __declspec( dllexport )
#else
#  define IATHOOKSHARED_EXPORT __declspec( dllimport )
#endif

#define PtrFromRva( base, rva ) ( ( ( PBYTE ) base ) + rva )

#ifndef DWORDPTR
#ifdef _WIN64
#define DWORDPTR DWORD64
#else
#define DWORDPTR DWORD
#endif
#endif

#define IATUTILS_ERROR_NO_ERROR 0
#define IATUTILS_ERROR_FILE_NOT_FOUND 1
#define IATUTILS_ERROR_PROC_NOT_FOUND 2
#define IATUTILS_ERROR_INVALID_MODULE 3

#endif // IATHOOK_GLOBAL_H
