#include <windows.h>
#include <iostream>
#include <algorithm>
#include <ctime>
#include <sstream>
#define IATHOOK_LIBRARY

#define MODULE_ALL 0
#define MODULE_MAIN 1
#define MODULE_NOT_SYS 2

#define MODULE_NOT_CARD '|'
#define MODULE_SEPARATOR_CARD ':'
#define MODULE_JOKER_CARD "*"

#define ORDINAL_TEXT_DUMP "ordinal"

#include "IATUtils.h"
#include "IATHook.h"


using namespace std;

// UTILS
std::string GetShortName(const char* fullName) {
	size_t j;
	std::string strShortModName;
	for (j = strlen(fullName) - 1; j >= 0 && fullName[j] != '\\'; j--);
	if (j >= 0) {
		strShortModName = std::string(fullName + j + 1);
	}
	return strShortModName;
}

std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
	std::stringstream ss(s);
	std::string item;
	while (std::getline(ss, item, delim)) {
		elems.push_back(item);
	}
	return elems;
}


std::vector<std::string> split(const std::string &s, char delim) {
	std::vector<std::string> elems;
	split(s, delim, elems);
	return elems;
}

std::string StringToLower(const std::string& s) {
	std::string result = s;
	std::transform(result.begin(), result.end(), result.begin(), ::tolower);
	return result;
}

bool StringStartsWith(const std::string& s, const std::string& prefix) {
	bool result = false;

	if (s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix) {
		result = true;
	}
	return result;
}
// END UTILS





/// <summary>
/// An access violation exception handler that logs and continue execution
/// </summary>
/// <param name="code">The code.</param>
/// <param name="ep">The ep.</param>
/// <returns></returns>
int AccessViolationHandler(unsigned int code, struct _EXCEPTION_POINTERS *ep) {

	std::cout << "Exception detected, code 0x" << std::hex << code << std::endl;
	if (code == EXCEPTION_ACCESS_VIOLATION) {
		return EXCEPTION_EXECUTE_HANDLER;
	}

	return EXCEPTION_CONTINUE_SEARCH;

}


/// <summary>
/// Checks if the module full name is matching the module pattern.
/// </summary>
/// <param name="moduleFullName">Full name of the module.</param>
/// <param name="modulePattern">The module pattern.</param>
/// <param name="result">The boolean result.</param>
/// <returns>The module type of the module pattern (main, not system, all)</returns>
int CheckModuleOK(const std::string& moduleFullName, const std::string& modulePattern, bool* result) {
	*result = false;

	if (modulePattern == "MAIN") {
		*result = true;
		return MODULE_MAIN;
	}

	char* pPath;
	std::string sys32Dir;
	pPath = getenv("WINDIR");
	if (pPath != NULL) {
		sys32Dir = StringToLower(pPath);
	}

	auto moduleName = GetShortName(moduleFullName.c_str());

	if (modulePattern == "ALL_BUT_SYSTEM") {
		auto pathModuleVar = StringToLower(moduleFullName.substr(0, moduleFullName.length() - moduleName.length() + 1));
		if (!StringStartsWith(pathModuleVar, sys32Dir)) {
			*result = true;
		}
		return MODULE_NOT_SYS;
	}
	

	bool ok = modulePattern.empty();
	bool negative = false;
	bool joker = false;
	
	
	auto moduleList = split(modulePattern, MODULE_SEPARATOR_CARD);

	for (auto currentPatternIt = moduleList.begin(); currentPatternIt != moduleList.end(); currentPatternIt++) {
		std::string& currentPattern = *currentPatternIt;
		if (currentPattern == MODULE_JOKER_CARD) {
			joker = true;
		} else {
			if (!currentPattern.empty() && currentPattern[0] != MODULE_NOT_CARD && !lstrcmpiA(currentPattern.c_str(), moduleName.c_str()))  {
				ok = true;
			}
			else if (!currentPattern.empty() && currentPattern[0] == MODULE_NOT_CARD && !lstrcmpiA(currentPattern.substr(1, currentPattern.size() - 1).c_str(), moduleName.c_str())) {
				negative = true;
			}
		}

	}

	if (negative) {
		ok = false;
	}

	*result = (ok || (!negative && joker));
	return MODULE_ALL;
}

std::string ConstructOrdinalFunction(IMAGE_THUNK_DATA* pThunkOriData) {
	std::stringstream ss; 
	ss << ORDINAL_TEXT_DUMP << " " << pThunkOriData->u1.Ordinal;
	return ss.str();
}

/// <summary>
/// From a module handle, retrieve the beginning of the Import Address Table (IAT)
/// </summary>
/// <param name="hModule">The module handle.</param>
/// <returns>A pointer that leads to the beginning of the IAT</returns>
IMAGE_IMPORT_DESCRIPTOR* IATGetImportDescriptor(HMODULE hModule)
{
    PIMAGE_DOS_HEADER pDosH;
    PIMAGE_NT_HEADERS pNTH;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;

    // Get DOS Header
    pDosH = (PIMAGE_DOS_HEADER) hModule;

    if(pDosH == NULL || pDosH->e_magic != IMAGE_DOS_SIGNATURE)
          return NULL;

    // Find the NT Header by using the offset of e_lfanew value from hMod
    pNTH = (PIMAGE_NT_HEADERS) PtrFromRva( pDosH , pDosH->e_lfanew);

	if (pNTH == NULL || pNTH->Signature != IMAGE_NT_SIGNATURE || IsBadReadPtr(pNTH, sizeof(IMAGE_NT_HEADERS)))
          return NULL;

    // iat patching
    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR) PtrFromRva ( pDosH,
          (pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));

    return pImportDesc;
}

/// <summary>
/// Get the thunk (IMAGE_THUNK_DATA) of an iterator through the elements of the IAT
/// </summary>
/// <param name="hModule">The module handle.</param>
/// <param name="pTable">An iterator through the IAT.</param>
/// <returns>The thunk</returns>
inline IMAGE_THUNK_DATA* IATGetThunk(HMODULE hModule, IMAGE_IMPORT_DESCRIPTOR* pTable)
{
    return (PIMAGE_THUNK_DATA) PtrFromRva( hModule, pTable->FirstThunk);
}

/// <summary>
/// Get the original thunk (IMAGE_THUNK_DATA) of an iterator through the elements of the IAT
/// </summary>
/// <param name="hModule">The module handle.</param>
/// <param name="pTable">An iterator through the IAT.</param>
/// <returns>The original thunk</returns>
inline IMAGE_THUNK_DATA* IATGetOriginalThunk(HMODULE hModule, IMAGE_IMPORT_DESCRIPTOR* pTable)
{
    return (PIMAGE_THUNK_DATA) PtrFromRva( hModule, pTable->OriginalFirstThunk);
}

/// <summary>
/// Get the function name of an iterator through the elements of the IAT
/// </summary>
/// <param name="hModule">The module handle.</param>
/// <param name="pTable">An iterator through the IAT.</param>
/// <returns>The function name</returns>
inline const char* IATGetImportTableName(HMODULE hModule, IMAGE_IMPORT_DESCRIPTOR* pTable)
{
    const char *name = (const char *) PtrFromRva( hModule, (pTable->Name));
    return name;
}

/// <summary>
/// Get the image import by name of an iterator through the elements of the IAT
/// </summary>
/// <param name="hModule">The module handle.</param>
/// <param name="pTable">An iterator through the IAT.</param>
/// <returns>The image import by name</returns>
inline IMAGE_IMPORT_BY_NAME* IATGetImportName(HMODULE hModule, IMAGE_THUNK_DATA* pThunkData)
{
    return (PIMAGE_IMPORT_BY_NAME)PtrFromRva(hModule, pThunkData->u1.AddressOfData);
}


/// <summary>
/// Patch the IAT. Allows detouring the function named "funcName" to another function "hook" in every loaded dll in the modules with name that matches the pattern "modulePattern".
/// throws std::range_error, std::invalid_argument, std::system_error
/// </summary>
/// <param name="modulePattern">The module pattern.</param>
/// <param name="szDll">The dll name or an empty string if no restriction.</param>
/// <param name="funcName">Name of the function.</param>
/// <param name="hook">The hook.</param>
void IATPatch(const std::string& modulePattern, const std::string& szDll, const std::string& funcName, PVOID hook) {
	DWORD cbNeeded;
	HMODULE hMods[1024];

	bool patchDone = false;

	typedef BOOL(WINAPI *ENUMPROCESSMODULES) (HANDLE, HMODULE *, DWORD, LPDWORD);

	HINSTANCE            hPsApi;
	ENUMPROCESSMODULES   EnumProcessModules;

	if (!(hPsApi = LoadLibrary("PSAPI.DLL"))) {
		throw std::runtime_error("Error : unable to find PSAPI.DLL");
	}

	EnumProcessModules = (ENUMPROCESSMODULES)GetProcAddress(hPsApi, "EnumProcessModules");
	if (!EnumProcessModules) {
		throw std::runtime_error("Error : unable to find procedure EnumProcessModules in PSAPI.DLL");
	}

	if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
		for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			char szModName[1024];


			if (GetModuleFileNameA(hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
				bool isModuleOK = false;

				switch (CheckModuleOK(szModName, modulePattern, &isModuleOK)) {
				case MODULE_ALL:
				case MODULE_NOT_SYS:
					if (isModuleOK) {
						if(IATPatch(hMods[i], szDll, funcName, hook)) {
							patchDone = true;
						}
					}
					break;
				case MODULE_MAIN:
					if(IATPatch(GetModuleHandle(0), szDll, funcName, hook)) {
						patchDone = true;
						return;
					}
				default:
					break;
				}

			}
		}
	}

	if(!patchDone) {
		std::stringstream ss;
		ss << "Unable to find the function " << funcName << " in modules matching pattern " << modulePattern;
		throw std::invalid_argument(ss.str());
	}
}


/// <summary>
/// Direct patch the IAT by calling an instance of the class IATHook
/// </summary>
/// <param name="hModule">The module handle</param>
/// <param name="szDll">The dll name or an empty string if no restriction.</param>
/// <param name="readFunctionName">Name of the read function in the IAT.</param>
/// <param name="readFunction">The read function in the IAT.</param>
/// <param name="hook">The hook.</param>
void DirectIATPatch(HMODULE hModule, const std::string& szDll, const char* readFunctionName, PVOID readFunction, PVOID hook) {
	IATHook h(hModule, szDll, readFunctionName, "", hook);
	h.patch(readFunction);
}


/// <summary>
/// Checks if the provided function name is an ordinal function name (then we'll have to check in the Import Address Table and not the Import Table where names are) or not.
/// If it's an ordinal function, then "ordinalFunctionOutput" is filled with the numeric value of the ordinal
/// </summary>
/// <param name="funcName">Name of the function.</param>
/// <param name="ordinalFunctionOutput">The ordinal function output.</param>
/// <returns>true if the function name is an ordinal, false otherwise</returns>
bool CheckOrdinalFunction(const std::string& funcName, DWORDPTR* ordinalFunctionOutput) {
	vector<string> funcNameParts = split(funcName, ' ');
	if (funcNameParts.size() != 2) {
		return false;
	} else if (ORDINAL_TEXT_DUMP == StringToLower(funcNameParts[0])) {
		DWORDPTR szFunction = 0;
		DWORDPTR maxValue;
		char* pEnd;
		const char* ordinalFunctionName = funcNameParts[1].c_str();
		#ifdef _WIN64
			szFunction = strtoull(ordinalFunctionName, &pEnd, 10);
			maxValue = ULLONG_MAX;
		#else
			szFunction = strtoul(ordinalFunctionName, &pEnd, 10);
			maxValue = ULONG_MAX;
		#endif
		
		errno = 0;
		if (szFunction == 0 && pEnd == ordinalFunctionName) {
			/* str was not a number */
			return false;
		} else if (szFunction == maxValue && errno) {
			/* the value of str does not fit */
			return false;
		} else if (*pEnd) {
			/* str began with a number but has junk left over at the end */
			return false;
		}

		/* success */
		*ordinalFunctionOutput = szFunction;
		return true;
	}
	return false;
}

/// <summary>
/// DLL internal function
/// Patch the IAT. Allows detouring the function named "funcName" in the dll "szDll" to another function "hook".
/// throws std::range_error, std::invalid_argument, std::system_error
/// </summary>
/// <param name="hModule">The module handle.</param>
/// <param name="szDll">The dll name or an empty string if no restriction.</param>
/// <param name="funcName">Name of the function.</param>
/// <param name="hook">The hook.</param>
/// <returns>true if the patch is done, false otherwise</returns>
bool IATPatch(HMODULE hModule, const std::string& szDll, const std::string& funcName, PVOID hook) {

	const char* szDllName = NULL;
	IMAGE_IMPORT_DESCRIPTOR* pTable = IATGetImportDescriptor(hModule);
	bool patchDone = false;
	bool ordinalFunction = false;
	DWORDPTR szFunction;
	ordinalFunction = CheckOrdinalFunction(funcName, &szFunction);

	if (pTable == NULL) {
		char buffer[512] = { 0 };
		sprintf_s(buffer, "Unable to read current module at 0x%p", hModule);
		throw std::range_error(buffer);
	}


#ifdef _MSC_VER
	__try {
#endif
		while (pTable->Characteristics != 0 
				&& (szDllName = IATGetImportTableName(hModule, pTable)) != NULL 
				&& !IsBadReadPtr(szDllName, sizeof(const char*)) 
				&& szDllName[0] != '\0') {		
		
			if (szDll.empty() || !lstrcmpiA(szDll.c_str(), szDllName)) {
				IMAGE_THUNK_DATA* pThunkData = IATGetThunk(hModule, pTable);
				IMAGE_THUNK_DATA* pThunkOriData = IATGetOriginalThunk(hModule, pTable);

				if (pThunkData != NULL && pThunkOriData != NULL) {
					size_t nThunk = 0;
					while (pThunkOriData->u1.AddressOfData != 0) {

						if (ordinalFunction && (pThunkOriData->u1.Ordinal & IMAGE_ORDINAL_FLAG || pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
							if (IMAGE_ORDINAL(pThunkOriData->u1.Ordinal) == szFunction) {
								patchDone = true;
								/* Allow stack unwinding : do not create tmp C++ objects with SEH handling in the same function !
								That's why we create a separate function */
								DirectIATPatch(hModule, szDll, NULL, (PVOID)pThunkData->u1.Function, hook);
							}							
						} else if (!ordinalFunction) {
							IMAGE_IMPORT_BY_NAME* pImport = IATGetImportName(hModule, pThunkOriData);
							//PVOID func_addr = (PVOID)pThunkData->u1.Function;
							if (pImport != NULL
								&& pImport->Name != NULL
								&& !IsBadReadPtr(pImport->Name, sizeof(const char*))
								&& !strcmp((const char*)pImport->Name, funcName.c_str())) {

								patchDone = true;
								/* Allow stack unwinding : do not create tmp C++ objects with SEH handling in the same function !
								That's why we create a separate function */
								DirectIATPatch(hModule, szDll, (const char*)pImport->Name, (PVOID)pThunkData->u1.Function, hook);
							}
						}

						nThunk++;
						pThunkData++;
						pThunkOriData++;
					}
				}
			}

			pTable++;
		}
		
#ifdef _MSC_VER
	} __except (AccessViolationHandler(GetExceptionCode(), GetExceptionInformation())){
		std::cout << " IAT FIND NAME BAD READ" << std::endl;
	}
#endif

	return patchDone;
}

void DirectIATTrace(HMODULE hModule, std::unordered_map<std::string, bool>& map, bool include, IMAGE_THUNK_DATA* pThunkData, const std::string& funcName, HookCallback* staticTracer) {
	bool notContained = map.find(funcName) == map.end() || !map[funcName];

	if (include && !notContained || !include && notContained) {
		std::cout << "TRACING FUNC " << funcName << std::endl;
		IATHooker* hooker = IATHooker::createHooker((PVOID)pThunkData->u1.Function, staticTracer);

		char fileName[512];
		GetModuleFileNameA(hModule, fileName, sizeof(fileName));

		IATHook h(hModule, "", funcName, GetShortName(fileName), hooker->getTrampoline());
		h.patch((PVOID)pThunkData->u1.Function);
	}
}

/// <summary>
/// Trace ALL the functions stored in the map "map" or NONE of its (depends of the "include" boolean)
/// Everything is printed on the standard output.
/// throws std::range_error, std::system_error, std::invalid_argument
/// </summary>
/// <param name="hModule">The module handle</param>
/// <param name="map">The map.</param>
/// <param name="include">if set to <c>true</c> [include].</param>
void IATTrace(HMODULE hModule, std::unordered_map<std::string, bool>& map, bool include, std::unique_ptr<HookCallback> callback) {
	

	class TraceCallback : public HookCallback {
	private:
		bool alreadyPresent;
		std::unique_ptr<HookCallback> hookCallback;
	public:
		TraceCallback(std::unique_ptr<HookCallback> cb) {
			alreadyPresent = false;
			hookCallback = std::move(cb);
		}

		void callback(PVOID originalFunc, std::vector<PVOID> registerArgs, PVOID stackPtr) override {
			if (!alreadyPresent) {
				alreadyPresent = true;
				hookCallback->callback(originalFunc, registerArgs, stackPtr);
				alreadyPresent = false;
			}
		}
	};

	static std::unique_ptr<TraceCallback> tracer = NULL;
	if (tracer == NULL) {
		tracer = std::unique_ptr<TraceCallback>(new TraceCallback(std::move(callback)));
	}

	
	IMAGE_IMPORT_DESCRIPTOR* pTable = IATGetImportDescriptor(hModule);

	if (pTable == NULL)
	{
		std::stringstream ss;
		ss << "Unable to read current module at " << hModule << std::endl;
		throw std::range_error(ss.str());
	}

	while (pTable->Characteristics != 0)
	{
		IMAGE_THUNK_DATA* pThunkData = IATGetThunk(hModule, pTable);
		IMAGE_THUNK_DATA* pThunkOriData = IATGetOriginalThunk(hModule, pTable);

		if (pThunkData != NULL && pThunkOriData != NULL && !IsBadReadPtr(pThunkData, sizeof(IMAGE_THUNK_DATA*)) && !IsBadReadPtr(pThunkOriData, sizeof(IMAGE_THUNK_DATA*)))
		{
			size_t nThunk = 0;
			while (pThunkOriData != NULL && pThunkData != NULL && pThunkOriData->u1.AddressOfData != 0 && pThunkData->u1.AddressOfData != 0)
			{
					
				//PVOID func_addr = (PVOID)pThunkData->u1.Function;
				if (pThunkOriData->u1.Ordinal & IMAGE_ORDINAL_FLAG || pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					std::string currentFuncName(ConstructOrdinalFunction(pThunkOriData));
					DirectIATTrace(hModule, map, include, pThunkData, currentFuncName, tracer.get());
				} else {
					IMAGE_IMPORT_BY_NAME* pImport = IATGetImportName(hModule, pThunkOriData);
					if (!IsBadReadPtr(pImport->Name, sizeof(const char*)))
					{
						std::string currentFuncName((const char*)pImport->Name);
						DirectIATTrace(hModule, map, include, pThunkData, currentFuncName, tracer.get());
					}
				}

				nThunk++;
				pThunkData++;
				pThunkOriData++;
			}
		}

		pTable++;
	}



}

/// <summary>
/// From a function address, iterate through the IAT and search for the name of the function
/// throws std::invalid_argument if the function is not present in the IAT of the module
/// </summary>
/// <param name="hModule">The module handle.</param>
/// <param name="func">The function to search.</param>
/// <returns>The name of the function</returns>
const char* IATFindName(HMODULE hModule, PVOID func) {
    const char* szDllName = NULL;
    IMAGE_IMPORT_DESCRIPTOR* pTable = IATGetImportDescriptor(hModule);
    PVOID startAddress = NULL;

	if (pTable == NULL) {
		std::stringstream ss;
		ss << "Unable to read current module at " << hModule << std::endl;
		throw std::range_error(ss.str());
	}

	while (pTable->Characteristics != 0 && (szDllName = IATGetImportTableName(hModule, pTable)) != NULL && szDllName[0] != '\0') {
		IMAGE_THUNK_DATA* pThunkData = IATGetThunk(hModule, pTable);
		IMAGE_THUNK_DATA* pThunkOriData = IATGetOriginalThunk(hModule, pTable);

        if (pThunkData != NULL && pThunkOriData != NULL) {
            size_t nThunk = 0;
            while (pThunkOriData->u1.AddressOfData != 0) {
                if (startAddress == NULL) {
                    startAddress = &pThunkData->u1.Function;
                }

                if (!(pThunkOriData->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {

					IMAGE_IMPORT_BY_NAME* pImport = IATGetImportName(hModule, pThunkOriData);
                    PVOID func_addr = (PVOID)pThunkData->u1.Function;
                    if (&func_addr == func) {
                        return (const char*) pImport->Name;
                    }
                }

                nThunk++;
                pThunkData++;
                pThunkOriData++;
            }
        }

        pTable++;
    }

	std::stringstream ss;
	ss << "Unable to locate function at " << func << " in module at " << hModule;
	throw std::invalid_argument(ss.str());

}




/// <summary>
/// Iterate through the IAT and search for the function name "szFunction" in the dll "szDll"
/// </summary>
/// <param name="hModule">The module handle</param>
/// <param name="szDll">The dll name</param>
/// <param name="szFunction">The function name</param>
/// <returns>A pointer that leads to the address of the function</returns>
void** IATGetFirstImport(HMODULE hModule, const char* szDll, const char* szFunction) {
    const char* szDllName = NULL;
	IMAGE_IMPORT_DESCRIPTOR* pTable = IATGetImportDescriptor(hModule);
    if(pTable == NULL) {
        return NULL;
    }

#ifdef _MSC_VER
	__try {
#endif
		while (pTable->Characteristics != 0 && (szDllName = IATGetImportTableName(hModule, pTable)) != NULL)
		{
			//Compare la dll cherchÃ©e et le module rÃ©cupÃ©rÃ©
			//Si szDll est NULL, la premiÃ¨re fonction du mÃªme nom
			//que szFonction trouvÃ©e dans un module est renvoyÃ©e
			if(szDll == NULL || !lstrcmpiA(szDll, szDllName))
			{
				
				//L'original pour le nom de fonction et l'ordinal,
				//l'autre pour l'adresse de fonction
				IMAGE_THUNK_DATA* pThunkData = IATGetThunk(hModule, pTable);
				IMAGE_THUNK_DATA* pThunkOriData = IATGetOriginalThunk(hModule, pTable);
				if (pThunkData != NULL && pThunkOriData != NULL)
				{

					size_t nThunk = 0;
					while (pThunkOriData != NULL && pThunkData != NULL && pThunkOriData->u1.AddressOfData != 0 && pThunkData->u1.AddressOfData != 0)
					{

						if (pThunkOriData->u1.Ordinal & IMAGE_ORDINAL_FLAG || pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
						{
							if(IMAGE_ORDINAL(pThunkOriData->u1.Ordinal) == (DWORDPTR)szFunction)
							{
								return (PVOID*)&pThunkData->u1.Function;
							}
						}
						else
						{
							IMAGE_IMPORT_BY_NAME* pImport = IATGetImportName(hModule, pThunkOriData);
							//std::cout << "Function found " << (const char*)pImport->Name << endl;
							//Compare le nom rÃ©cupÃ©rÃ© de la fonction (pImport->Name) et le nom fourni en paramÃ¨tre (szFunction)
							if (pImport != NULL && pImport->Name != NULL && !lstrcmpA(szFunction, (const char*)pImport->Name))
							{
								return (PVOID*)&pThunkData->u1.Function;
							}
						}

						nThunk++;
						pThunkData++;
						pThunkOriData++;
					}
				}
			}

			pTable++;
		}

#ifdef _MSC_VER
	} __except (AccessViolationHandler(GetExceptionCode(), GetExceptionInformation())){
		std::cout << " IAT FIND NAME BAD READ " << std::endl;
	}
#endif

    return NULL;
}


/// <summary>
/// Gets the stack trace.
/// throws std::runtime_error, std::invalid_argument
/// </summary>
/// <param name="outputStack">The output stack.</param>
/// <param name="maxCallers">The maximum callers.</param>
/// <returns></returns>
int GetStackTrace(PVOID* outputStack, int maxCallers) {
    typedef USHORT(WINAPI *CaptureStackBackTraceType)(ULONG, ULONG, PVOID*, PULONG);
    CaptureStackBackTraceType CaptureStackBackTrace = (CaptureStackBackTraceType)(GetProcAddress(LoadLibraryA("KERNEL32.dll"), "RtlCaptureStackBackTrace"));

    if (CaptureStackBackTrace == NULL) {
		throw std::runtime_error("Unable to locate function RtlCaptureStackBackTrace in KERNEL32.DLL");
    }


    // Quote from Microsoft Documentation:
    // ## Windows Server 2003 and Windows XP:
    // ## The sum of the FramesToSkip and FramesToCapture parameters must be less than 63.
    const int kMaxCallers = 62;

    if (maxCallers > kMaxCallers) {
		std::stringstream ss;
		ss << "kMaxCallers mustn't be greater than " << kMaxCallers;
		throw std::invalid_argument(ss.str());
    }

    int count = (CaptureStackBackTrace)(0, maxCallers, outputStack, NULL);
    return count;
}

/// <summary>
/// Prints the stack trace.
/// </summary>
void PrintStackTraceIAT() {
    const int kMaxCallers = 62;
    PVOID stack[kMaxCallers];
    int count = GetStackTrace(stack, kMaxCallers);
    for (int i = 0; i < count; i++) {
		try {
			const char* funcName = IATFindName(GetModuleHandle(0), stack[i]);
			printf("*** %d called from %s (%p)\n", i, funcName, stack[i]);
		} catch (std::invalid_argument& iae) {
			printf("*** %d called from UNKNOWN (%p)\n", i, stack[i]);
		}
	
    }
}





/// <summary>
/// Trace the IAT for several modules that follow a module pattern (as explained in the function CheckModuleOk)
/// If "include" is true, then we catch ONLY functions stored in the map, if false, we catch NONE of its
/// throws std::runtime_error, std::range_error, std::system_error, std::invalid_argument
/// </summary>
/// <param name="includeds">The functions.</param>
/// <param name="modules">The module pattern.</param>
/// <param name="include">if set to <c>true</c> [include].</param>
void IATTraceMultiModule(std::unordered_map<std::string, bool>& functions, const std::string& modules, bool include, std::unique_ptr<HookCallback> callback) {
	DWORD cbNeeded;
	HMODULE hMods[1024];

	typedef BOOL(WINAPI *ENUMPROCESSMODULES) (HANDLE, HMODULE *, DWORD, LPDWORD);

	HINSTANCE            hPsApi;
	ENUMPROCESSMODULES   EnumProcessModules;

	if (!(hPsApi = LoadLibrary("PSAPI.DLL"))) {
		throw std::runtime_error("Error : unable to find PSAPI.DLL");
	}
		
	EnumProcessModules = (ENUMPROCESSMODULES)GetProcAddress(hPsApi, "EnumProcessModules");
	if (!EnumProcessModules) {
		throw std::runtime_error("Error : unable to find procedure EnumProcessModules in PSAPI.DLL");
	}

	std::cout << "Current modules loaded : " << std::endl;

	if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
		for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			char szModName[1024];
			

			if (GetModuleFileNameA(hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
				bool isModuleOK = false;

				switch (CheckModuleOK(szModName, modules, &isModuleOK)) {
					case MODULE_ALL:
					case MODULE_NOT_SYS:
						if (isModuleOK) {
							std::cout << "Tracing " << szModName << std::endl;
							IATTrace(hMods[i], functions, include, std::move(callback));
						}
						break;
					case MODULE_MAIN:
						std::cout << "Tracing process module" << std::endl;
						IATTrace(GetModuleHandle(0), functions, include, std::move(callback));
						return;
					default:
						break;
				}

			}
		}
	}


}

/// <summary>
/// Trace the IAT for several modules that follow a module pattern (as explained in the function CheckModuleOk)
/// We catch NONE of the functions stored in the map
/// </summary>
/// <param name="excludeds">The excludeds functions.</param>
/// <param name="modules">The modules.</param>
void IATTraceExclude(std::unordered_map<std::string, bool>& excludeds, const std::string& modules, std::unique_ptr<HookCallback> callback) {
	IATTraceMultiModule(excludeds, modules, false, std::move(callback));
}

/// <summary>
/// Trace the IAT for several modules that follow a module pattern (as explained in the function CheckModuleOk)
/// We catch ONLY functions stored in the map
/// </summary>
/// <param name="includeds">The includeds functions.</param>
/// <param name="modules">The modules.</param>
void IATTraceInclude(std::unordered_map<std::string, bool>& includeds, const std::string& modules, std::unique_ptr<HookCallback> callback) {
	IATTraceMultiModule(includeds, modules, true, std::move(callback));
}



/// <summary>
/// Dump the IAT of each module of the current process that follows the module pattern "modules" as a text format to an ostream
/// </summary>
/// <param name="dumpOutput">The dump output.</param>
/// <param name="modules">The module pattern.</param>
void IATDumpProcess(ostream& dumpOutput, const std::string& modules) {
	DWORD cbNeeded;
	HMODULE hMods[1024];

	typedef BOOL(WINAPI *ENUMPROCESSMODULES) (HANDLE, HMODULE *, DWORD, LPDWORD);

	HINSTANCE            hPsApi;
	ENUMPROCESSMODULES   EnumProcessModules;


	if (!(hPsApi = LoadLibrary("PSAPI.DLL"))) {
		throw std::runtime_error("Error : unable to find PSAPI.DLL");
	}

	EnumProcessModules = (ENUMPROCESSMODULES)GetProcAddress(hPsApi, "EnumProcessModules");
	if (!EnumProcessModules) {
		throw std::runtime_error("Error : unable to find procedure EnumProcessModules in PSAPI.DLL");
	}
	
	if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
		for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			char szModName[1024];


			if (GetModuleFileNameA(hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
				auto strShortModName = GetShortName(szModName);
				dumpOutput << hMods[i] << "\t" << strShortModName.c_str() << std::endl;

				bool isModuleOK = false;

				switch (CheckModuleOK(szModName, modules, &isModuleOK)) {
				case MODULE_ALL:
				case MODULE_NOT_SYS:
					if (isModuleOK) {
						IATDump(hMods[i], dumpOutput);
					}
					break;
				case MODULE_MAIN:
					IATDump(GetModuleHandle(0), dumpOutput);
					return;
				default:
					break;
				}

				

			}
		}
	}
    
}
	


/// <summary>
/// Dump the IAT of the main module hModule
/// </summary>
/// <param name="hModule">The module handle.</param>
/// <param name="dumpOutput">The dump output.</param>
void IATDump(HMODULE hModule, ostream& dumpOutput)
{
    dumpOutput << "Dump de " << hModule << ", process id : " << GetCurrentProcessId() << std::endl;

    const char* szDllName = NULL;
	IMAGE_IMPORT_DESCRIPTOR* pTable = IATGetImportDescriptor(hModule);
    if(pTable == NULL && dumpOutput)
    {
        dumpOutput << "Erreur : Impossible de lire le module courant\n";
        return;
    }
    
#ifdef _MSC_VER
	__try {
#endif
		while (pTable != NULL && pTable->Characteristics != 0 && (szDllName = IATGetImportTableName(hModule, pTable)) != NULL && szDllName[0] != '\0')
		{
			if (dumpOutput) {
				dumpOutput << "\t" << (PVOID)hModule << "\t" << szDllName << endl;
			}

			IMAGE_THUNK_DATA* pThunkData = IATGetThunk(hModule, pTable);
			IMAGE_THUNK_DATA* pThunkOriData = IATGetOriginalThunk(hModule, pTable);

			if (pThunkData != NULL && pThunkOriData != NULL)
			{

				size_t nThunk = 0;
				while (pThunkOriData != NULL && pThunkData != NULL && pThunkOriData->u1.AddressOfData != 0 && pThunkData->u1.AddressOfData != 0)
				{

					if (pThunkOriData->u1.Ordinal & IMAGE_ORDINAL_FLAG || pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
						if (dumpOutput)
							dumpOutput << "\t\t" << (PVOID)pThunkData->u1.Function << "\t" << ORDINAL_TEXT_DUMP << " " << pThunkOriData->u1.Ordinal << endl;
					} else {
						IMAGE_IMPORT_BY_NAME* pImport = IATGetImportName(hModule, pThunkOriData);
						if (dumpOutput) {
							dumpOutput << "\t\t" << (PVOID)pThunkData->u1.Function;
						
								if (pImport != NULL && pImport->Name != NULL) {
									dumpOutput << "\t" << (const char*)pImport->Name << endl;
								} else {
									dumpOutput << std::endl;
								}
						
						}
					}
				
				
					nThunk++;
					pThunkData++;
					pThunkOriData++;
				}
			}

			pTable++;
		}
#ifdef _MSC_VER
	}__except (AccessViolationHandler(GetExceptionCode(), GetExceptionInformation())){
		if (dumpOutput) {
			dumpOutput << "\t\tBAD READ " << std::endl;
		}
	}
#endif

}

