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


class IATHOOKSHARED_EXPORT IATHook {

public:
     ~IATHook();
	
	IATHook(const IATHook& h);
    IATHook(HMODULE hModProcess, const std::string& moduleName, const std::string& funcName, const std::string& indicativeModuleName, void* hookFunc);
    
	std::string& getIndicativeModuleName();
	std::string& getFunctionName();
	std::string& getModuleName();
	PVOID getOriginalFunction();

	
	void patch(PVOID keyAddress);
    void unpatch();
	static IATHook* getHookFromAddress(PVOID address);
	static IATHook* getHookFromName(const std::string& funcName);

private:
	IATHook();
    
    HookIAT wrapped;
	PVOID m_keyAddress;
    std::string m_moduleName;
	std::string m_indicativeModuleName;
    std::string m_funcName;
    static std::unordered_map<DWORDPTR, IATHook> hooksMap;
	static std::unordered_map<std::string, IATHook*> hooksNamedMap;
};


#endif // IATHOOK_H
