#pragma once

#include <windows.h>
#include <iostream>
#include <unordered_map>
#include "iathook_global.h"

struct HookIAT {
    void** originalFunction;
    void* hookFunction, *originalFunctionCaller;
    char name[256];
};

class IATHook {

public:
     ~IATHook() = default;

	IATHook(const IATHook& h) = default;
    IATHook(HMODULE hModProcess, std::string moduleName, std::string functionName, std::string indicativeModuleName, void* hookFunc);
    
	const std::string& getIndicativeModuleName() const;
	const std::string& getFunctionName() const;
	const std::string& getModuleName() const;
	PVOID getOriginalFunction();
	
	void patch(PVOID keyAddress);
    void unpatch();

	static IATHOOKSHARED_EXPORT IATHook* getHookFromAddress(PVOID address);
	static IATHOOKSHARED_EXPORT IATHook* getHookFromName(const std::string& funcName);

private:
	IATHook() = default;
    
	PVOID m_keyAddress;
    std::string m_moduleName;
	std::string m_indicativeModuleName;
    std::string m_functionName;
	HookIAT m_wrapped;

    static std::unordered_map<DWORDPTR, IATHook> hooksMap;
	static std::unordered_map<std::string, IATHook*> hooksNamedMap;
};
