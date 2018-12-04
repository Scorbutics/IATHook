#include <stdlib.h>
#include <iostream>
#include <unordered_map>
#include <windows.h>
#include <string>
#include <sstream>
#include <system_error>
#include <exception>

#define IATHOOK_LIBRARY

#include "IATHook.h"
#include "IATUtils.h"

std::unordered_map<DWORDPTR, IATHook> IATHook::hooksMap;
std::unordered_map<std::string, IATHook*> IATHook::hooksNamedMap;

/// <summary>
/// Patches the IAT from the provided hook
/// throws std::system_error, std::invalid_argument
/// </summary>
/// <param name="hook">The hook.</param>
void HookIATPatch(HookIAT* hook) {
    if(hook->originalFunction != NULL && hook->hookFunction != NULL && (*(hook->originalFunction)) != NULL) {
        DWORD oldProt;
        if(VirtualProtect(hook->originalFunction, sizeof(LPDWORD), PAGE_EXECUTE_READWRITE, &oldProt)) {
            memcpy(hook->originalFunction, &hook->hookFunction, sizeof(PVOID));
            VirtualProtect(hook->originalFunction, sizeof(LPDWORD), oldProt, NULL);
        } else {
			std::stringstream ss;
			ss << "Unable to patch/unpatch IAT : unable to unprotect memory at " << (hook->originalFunction) << " to PAGE_EXECUTE_READWRITE" << std::endl;
			throw std::system_error(GetLastError(), std::system_category(), ss.str().c_str());
        }
    } else {
		throw std::invalid_argument("Unable to patch/unpatch IAT : invalid argument provided containing null value(s)");
    }
}

/// <summary>
/// Unpatches the IAT from the provided hook
/// </summary>
/// <param name="hook">The hook.</param>
void HookIATUnpatch(HookIAT* hook) {
    //le but est de restaurer l'IAT
    void* lastHook = hook->hookFunction;

    hook->hookFunction = hook->originalFunction;
    HookIATPatch(hook);
    hook->hookFunction = lastHook;
}

/// <summary>
/// Creates an IAT Hook instance
/// </summary>
/// <param name="hModProcess">The process handle module.</param>
/// <param name="moduleName">Name of the module where the function to hook is.</param>
/// <param name="funcName">Name of the function to hook.</param>
/// <param name="hookFunc">The hook function.</param>
/// <returns>The HookIAT instance</returns>
HookIAT HookIATCreate(HMODULE hModProcess, const char* moduleName, const char* funcName, void* hookFunc) {
    HookIAT result;
    result.originalFunction = IATGetFirstImport(hModProcess, moduleName, funcName);
    result.hookFunction = hookFunc;

    if(result.originalFunction != NULL) {
        result.originalFunctionCaller = *result.originalFunction;
	} else {
		result.originalFunctionCaller = NULL;
	}

    if(strlen(funcName) < 255) {
        strcpy(result.name, funcName);
        result.name[255] = '\0';
    }
    return result;
}

/// <summary>
/// Initializes a new instance of the <see cref="IATHook"/> class.
/// </summary>
/// <param name="hModProcess">The process handle module.</param>
/// <param name="moduleName">Name of the module where the function to hook is.</param>
/// <param name="functionName">Name of the function to hook.</param>
/// <param name="indicativeModuleName">Human readable name of the module</param>
/// <param name="hookFunc">The hook function.</param>
IATHook::IATHook(HMODULE hModProcess, std::string moduleName, std::string functionName, std::string indicativeModuleName, void* hookFunc) :
	m_functionName(std::move(functionName)),
	m_moduleName(std::move(moduleName)),
	m_indicativeModuleName(std::move(indicativeModuleName)),
	m_wrapped(HookIATCreate(hModProcess, m_moduleName.empty() ? NULL : m_moduleName.c_str(), m_functionName.c_str(), hookFunc)){
}

/// <summary>
/// Patches the hook from a function at the specified key address.
/// </summary>
/// <param name="keyAddress">The key address.</param>
void IATHook::patch(PVOID keyAddress) {
	m_keyAddress = keyAddress;
	DWORDPTR key = (DWORDPTR)keyAddress;
	hooksMap.emplace(key, *this);
	hooksNamedMap.emplace(m_functionName, &hooksMap.at(key));
	HookIATPatch(&hooksMap.at(key).m_wrapped);
}

/// <summary>
/// Gets the hook from address stored into the internal Hook address map.
/// </summary>
/// <param name="keyAddress">The key address.</param>
/// <returns>A pointer to the IATHook stored</returns>
IATHook* IATHook::getHookFromAddress(PVOID keyAddress) {
	DWORDPTR key = (DWORDPTR)keyAddress;
    if(hooksMap.find(key) != hooksMap.end()) {
        return &hooksMap.at(key);
    }

    return NULL;
}

/// <summary>
/// Gets the hook from name stored into the internal Hook name map.
/// </summary>
/// <param name="hookName">Name of the hook.</param>
/// <returns>A pointer to the IATHook stored</returns>
IATHook* IATHook::getHookFromName(const std::string& hookName) {
	if (hooksNamedMap.find(hookName) != hooksNamedMap.end()) {
		return hooksNamedMap[hookName];
	}
	return NULL;
}

/// <summary>
/// Gets the original (unhooked) function.
/// </summary>
/// <returns>The address of the function</returns>
PVOID IATHook::getOriginalFunction() {
	return m_wrapped.originalFunctionCaller;
}

/// <summary>
/// Gets the name of the function.
/// </summary>
/// <returns>The name of the function</returns>
const std::string& IATHook::getFunctionName() const {
	return m_functionName;
}

/// <summary>
/// Gets the name of the module.
/// </summary>
/// <returns>The name of the module</returns>
const std::string& IATHook::getModuleName() const {
	return m_moduleName;
}

/// <summary>
/// Gets the indicative (human readable) name of the module.
/// </summary>
/// <returns>The indicative (human readable) name of the module.</returns>
const std::string& IATHook::getIndicativeModuleName() const {
	return m_indicativeModuleName;
}

/// <summary>
/// Unpatches this hook
/// </summary>
void IATHook::unpatch() {
	auto it = hooksMap.find((DWORDPTR)m_keyAddress);
	auto itName = hooksNamedMap.find(m_functionName);
	HookIATUnpatch(&it->second.m_wrapped);
	hooksMap.erase(it);
	hooksNamedMap.erase(itName);
}
