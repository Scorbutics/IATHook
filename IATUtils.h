#ifndef IATUTILS_H
#define IATUTILS_H

#include <windows.h>
#include <cstdlib>
#include <fstream>
#include <ostream>
#include <unordered_map>
#include <memory>

#include "iathook_global.h"
#include "GlobalIATHooker.h"

IATHOOKSHARED_EXPORT void IATPatch(const std::string& modulePattern, const std::string& szDll, const std::string& funcName, PVOID hook);
IATHOOKSHARED_EXPORT void IATDumpProcess(std::ostream& dumpOutput, const std::string& modules);
IATHOOKSHARED_EXPORT void IATDump(HMODULE hModule, std::ostream& dumpOutput);
IATHOOKSHARED_EXPORT void IATTraceExclude(std::unordered_map<std::string, bool>& excluded, const std::string& modules, std::unique_ptr<HookCallback> callback);
IATHOOKSHARED_EXPORT void IATTraceInclude(std::unordered_map<std::string, bool>& included, const std::string& modules, std::unique_ptr<HookCallback> callback);
bool IATPatch(HMODULE hModule, const std::string& szDll, const std::string& funcName, PVOID hook);
void** IATGetFirstImport(HMODULE hModule, const char* moduleName, const char* funcName);

#endif // IATUTILS_H
