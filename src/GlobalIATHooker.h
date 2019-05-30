#pragma once

#include <iostream>
#include <unordered_map>
#include <memory>
#include <vector>
#include <Windows.h>
#include "iathook_global.h"

extern "C" void LIBHOOKGeneralHookFunc(PVOID originalFunc);

class HookCallback {
public:
	virtual void callback(PVOID originalFunc, std::vector<PVOID> registerArgs, PVOID stackPtr) = 0;
};

class IATHooker {
private:
	IATHooker(PVOID function, HookCallback* callback);
	
	static PVOID generateTrampolineDetourFunction(PVOID originalFunc);
	static std::unordered_map<PVOID, HookCallback*> hookCallbacks;
	static std::unordered_map<PVOID, std::shared_ptr<IATHooker>> hookers;
	
	void setHookFunction(PVOID function, HookCallback* h);
	void freeTrampoline();

	HookCallback* hookCallback;
	PVOID trampoline;

public:
	static HookCallback* getCallback(PVOID);
	static IATHooker* createHooker(PVOID function, HookCallback* callback);
	static std::weak_ptr<IATHooker> getHooker(PVOID func);
	PVOID getTrampoline();
	~IATHooker();
};

