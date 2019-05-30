#include <cstdio>
#include <Windows.h>
#include <iostream>

#define IATHOOK_LIBRARY

#include "GlobalIATHooker.h"
#include "ASMUtils.h"
#include "IATHook.h"

std::unordered_map<PVOID, HookCallback*> IATHooker::hookCallbacks;
std::unordered_map<PVOID, std::shared_ptr<IATHooker>> IATHooker::hookers;

extern "C" {
#ifdef _MSC_VER
	#ifdef _WIN64
		PVOID GetRSPx64(void);
		PVOID GetRCXx64(void);
		PVOID GetRDXx64(void);
		PVOID GetR8x64(void);
		PVOID GetR9x64(void);
	#else
		PVOID GetESP(void);
	#endif

#else
	PVOID GetRSPx64(void) {
		PVOID result = 0;
		__asm__(
			"MOVQ %%RSP, %0"
			: "=&R"(result)
			::);
		return result;
	}

	PVOID GetRCXx64(void) {
		PVOID result = 0;
		__asm__(
			"MOVQ %%RCX, %0"
			: "=&R"(result)
			::);
		return result;
	}

	PVOID GetRDXx64(void) {
		PVOID result = 0;
		__asm__(
			"MOVQ %%RDX, %0"
			: "=&R"(result)
			::);
		return result;
	}

	PVOID GetR8x64(void) {
		PVOID result = 0;
		__asm__(
			"MOVQ %%R8, %0"
			: "=&R"(result)
			::);
		return result;
	}

	PVOID GetR9x64(void) {
		PVOID result = 0;
		__asm__(
			"MOVQ %%R9, %0"
			: "=&R"(result)
			::);
		return result;
	}
#endif
}

/// <summary>
/// Hooks the original function
/// </summary>
/// <param name="originalFunc">The original (unhooked) function.</param>
extern "C" void LIBHOOKGeneralHookFunc(PVOID originalFunc) {

	HookCallback * h = IATHooker::getCallback(originalFunc); 
	if (h != NULL) {
#ifdef _WIN64
		/* x86-64 MS calling convention */
		PVOID rcx = GetRCXx64();
		PVOID rdx = GetRDXx64();
		PVOID r8 = GetR8x64();
		PVOID r9 = GetR9x64();
		PVOID sp = GetRSPx64();

		std::vector<PVOID> registerArgs;
		registerArgs.push_back(rcx);
		registerArgs.push_back(rdx);
		registerArgs.push_back(r8);
		registerArgs.push_back(r9);
#else
		/* cdecl : arguments on the stack */
		auto registerArgs = std::vector<PVOID> {};
		auto sp = GetESP();
#endif
		h->callback(originalFunc, registerArgs, sp);
	}
}
extern "C" {
#ifdef _MSC_VER
	/* Defined in the ASM linked file */
	PVOID LIBHOOKDetourFunctionASM(DWORD ptr);
	/* end define */
#else
	PVOID LIBHOOKDetourFunctionASM(void) {

		__asm__(
			/* Allocate stack space */
			"SUBQ $0x80, %%RSP\n"

			/* Prologue */
				/* Freeze registers */
			"PUSHQ %%RDI\n"
			"PUSHQ %%RAX\n"
			"PUSHQ %%RDX\n"
			"PUSHQ %%RCX\n"
			"PUSHQ %%R8\n"
			"PUSHQ %%R9\n"

			/* Call hook function (input) with prototype : void hook(PVOID originalFunc) */
			"CALLQ *%0\n"

			/* Epilogue */
				/* Restore registers*/
			"POPQ %%R9\n"
			"POPQ %%R8\n"
			"POPQ %%RCX\n"
			"POPQ %%RDX\n"
			"POPQ %%RAX\n"
			"POPQ %%RDI\n"

			/* Free stack space */
			"ADDQ $0x80, %%RSP\n"

			/* Extra POP : comes from the way we call this function (LIBHOOKDetourFunctionx64) : the first QWORD on stack is the original function address */
			"POPQ %%RAX\n"

			/* Original function called (input) with a JMP (we cannot do it in C, it would be a CALL or JMP + RET) */
			"JMPQ *%%RAX\n"
			:
		/* output operands */
		:
			/* input operands */
			"r" (reinterpret_cast<PVOID>(LIBHOOKGeneralHookFunc))
			: );

	}
#endif
}

/// <summary>
/// Sets the function to hook with the associated callback.
/// </summary>
/// <param name="function">The function.</param>
/// <param name="callback">The callback.</param>
void IATHooker::setHookFunction(PVOID function, HookCallback* callback) {
	hookCallback = callback;
	hookCallbacks[function] = callback;
}


/// <summary>
/// Gets the callback of a hooked function.
/// </summary>
/// <param name="originalFunc">The function.</param>
/// <returns></returns>
HookCallback* IATHooker::getCallback(PVOID originalFunc) {
	if (hookCallbacks.find(originalFunc) != hookCallbacks.end()) {
		return hookCallbacks[originalFunc];
	}
	return NULL;
}

/// <summary>
/// Factory method that creates a hooker instance that hooks a function with a callback.
/// </summary>
/// <param name="function">The function.</param>
/// <param name="callback">The callback.</param>
/// <returns>The hooker instance</returns>
IATHooker* IATHooker::createHooker(PVOID function, HookCallback* callback) {
	hookers[function] = std::shared_ptr<IATHooker>(new IATHooker(function, callback));
	return hookers[function].get();
}

/// <summary>
/// Gets the hooker stored in the internal map of hookers from the hooked function address.
/// </summary>
/// <param name="func">The original hooked function.</param>
/// <returns>The hooker instance or a null pointer if there is no hooker for this function</returns>
std::weak_ptr<IATHooker> IATHooker::getHooker(PVOID func) {
	if (hookers.find(func) != hookers.end()) {
		return hookers[func];
	}
	return std::shared_ptr<IATHooker>(NULL);
}


IATHooker::IATHooker(PVOID function, HookCallback* callback) {
	trampoline = generateTrampolineDetourFunction(function);
	setHookFunction(function, callback);
}

/// <summary>
/// Gets the trampoline function.
/// </summary>
/// <returns>The trampoline function</returns>
PVOID IATHooker::getTrampoline() {
	return trampoline;
}

/// <summary>
/// In assembly language, generates the trampoline detour function that will lead to a proc in an asm project-linked file.
/// This function allows us to first push the address of the original (unhooked) function in the stack and then the asm file
/// will call LIBHOOKGeneralHookFunc with this function as a parameter to retrieve the original function.
/// </summary>
/// <param name="originalFunc">The original function.</param>
/// <returns>A dynamically allocated pointer that leads to the generated ASM code of the trampoline function</returns>
PVOID IATHooker::generateTrampolineDetourFunction(PVOID originalFunc) {
	
#ifdef _WIN64
	/* This is a non conventional way to call LIBHOOKDetourFunctionASM : first (and only) parameter is stored on the stack. 
	* So we'll have to manually query it in the function in assembly */
	BYTE code[] = {
		0x50,													//PUSH RAX
		0x48, 0xB8,												//MOV RAX, originalFunc
		0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE,			//
		0x50,													//PUSH RAX

		0x48, 0xB9,												//MOV RCX, LIBHOOKGeneralHookFunc
		0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE,
		0x48, 0xB8,												//MOV RAX, LIBHOOKDetourFunctionASM
		0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE,			//
		0xFF, 0xE0												//JMP RAX
	};


	ASMUtils::reverseAddressx64((DWORD64)originalFunc, code + 3);
	ASMUtils::reverseAddressx64((DWORD64)LIBHOOKGeneralHookFunc, code + 14);
	ASMUtils::reverseAddressx64((DWORD64)LIBHOOKDetourFunctionASM, code + 24);

#else
	BYTE code[] = { 					   
		  0x50, 						   //PUSH EAX
		  0xB8, 						   //MOV EAX, originalFunc
		  0xEF, 0xBE, 0xAD, 0xDE, 		   
		  0x50,							   //PUSH EAX
		  0xB8, 						   //MOV EAX, LIBHOOKGeneralHookFunc
		  0xEF, 0xBE, 0xAD, 0xDE,
		  0x50,							   //PUSH EAX
		  0xB8, 						   //MOV EAX, LIBHOOKDetourFunctionASM
		  0xEF, 0xBE, 0xAD, 0xDE, 		   
		  0xFF, 0xE0 					   //JMP EAX
	};

	ASMUtils::reverseAddressx86((DWORD)originalFunc, code + 2);
	ASMUtils::reverseAddressx86((DWORD)LIBHOOKGeneralHookFunc, code + 8);
	ASMUtils::reverseAddressx86((DWORD)LIBHOOKDetourFunctionASM, code + 14);
#endif

	
	return ASMUtils::writeAssembly(code, sizeof(code));
}

/// <summary>
/// Frees the trampoline function.
/// </summary>
void IATHooker::freeTrampoline() {
	/* First, we have to free the dynamically allocated trampoline function */
	VirtualFree(trampoline, 0, MEM_RELEASE);
	trampoline = NULL;
}

/// <summary>
/// Finalizes an instance of the <see cref="IATHooker"/> class.
/// </summary>
IATHooker::~IATHooker() {
	/* Do not free trampoline here : the code still has to be reachable even after the instance of IATHooker is dead. 
	   To free a trampoline, we have to explicitly call "freeTrampoline" by using the IATHooker map. */
}
