#ifndef IATHOOK_H
#define IATHOOK_H

#include <windows.h>
#include <iostream>
#include <unordered_map>
#include "iathook_global.h"

struct HookIAT {
    void** originalFunction;
    void* hookFunction, *originalFunctionCaller;
    char name[256];
};
typedef struct HookIAT HookIAT;

void HookIATPatch(HookIAT* hook);
void HookIATUnpatch(HookIAT* hook);
HookIAT HookIATCreate(HMODULE hModProcess, const char* moduleName, const char* funcName, void* hookFunc);


class IATHook
{

public:
	IATHook();
    IATHook(HMODULE hModProcess, const std::string& moduleName, const std::string& funcName, const std::string& indicativeModuleName, void* hookFunc);
	IATHook(const IATHook& h);
	void patch(PVOID keyAddress);
    void unpatch();
    ~IATHook();
	
	IATHOOKSHARED_EXPORT std::string& getIndicativeModuleName();
	IATHOOKSHARED_EXPORT std::string& getFunctionName();
	IATHOOKSHARED_EXPORT std::string& getModuleName();
	IATHOOKSHARED_EXPORT PVOID getOriginalFunction();

	IATHOOKSHARED_EXPORT static IATHook* getHookFromAddress(PVOID address);
	IATHOOKSHARED_EXPORT static IATHook* getHookFromName(const std::string& funcName);

private:
    HookIAT wrapped;
	PVOID m_keyAddress;
    std::string m_moduleName;
	std::string m_indicativeModuleName;
    std::string m_funcName;
    static std::unordered_map<DWORDPTR, IATHook> hooksMap;
	static std::unordered_map<std::string, IATHook*> hooksNamedMap;
};







#endif // IATHOOK_H
