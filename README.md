Example of utilisation of IATHook (here is a program as a "ptrace" but on Windows) :

#include <Windows.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <memory>
#include <unordered_map>
#include <ctime>

#include "IATUtils.h"
#include "IATHook.h"

using namespace std;
HMODULE hModule;
std::string moduleDirectory;

const std::string currentDateTime() {
	time_t     now = time(0);
	struct tm  tstruct;
	char       buf[80];
	tstruct = *localtime(&now);
	strftime(buf, sizeof(buf), "%X", &tstruct);
	return buf;
}

void TryDisplayAsString(PVOID p, const std::string& type) {

	std::cout << type << " : ";
	printf("0x%p(%20llu)\t", p, p);

	PVOID dereferenced = 0;
	WCHAR* unicode = (WCHAR*)p;
	TCHAR* ansi = (TCHAR*)p;
	WCHAR finalUnicode[256] = { 0 };
	char finalAnsi[256] = { 0 };
	__try
	{
		dereferenced = *((PVOID*)p);
		wsprintf(finalUnicode, unicode);
		sprintf(finalAnsi, (char*)ansi);

	} __except (EXCEPTION_EXECUTE_HANDLER) {
		//Captures native Access Violation 
	}

	printf("Dereferenced : %20llu\t", dereferenced);
	wprintf(L"Unicode : %s\t", finalUnicode);
	printf("ANSI : %s\n", finalAnsi);

}

class LogHookCallback : public HookCallback {
public:
	void callback(PVOID originalFunc, std::vector<PVOID> registerArgs, PVOID stackPtr) override {
		IATHook* currentHook = IATHook::getHookFromAddress(originalFunc);
		HANDLE consoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(consoleOutput, FOREGROUND_RED | BACKGROUND_BLUE | FOREGROUND_INTENSITY);
		std::cout << currentDateTime().c_str() << " : ";
		if (currentHook != NULL) {
			std::cout << currentHook->getFunctionName().c_str() << "\t (" << currentHook->getIndicativeModuleName().c_str() << ")" << std::endl;
		} else {
			std::cout << originalFunc << std::endl;
		}
		
		SetConsoleTextAttribute(consoleOutput, FOREGROUND_GREEN | BACKGROUND_BLUE | FOREGROUND_INTENSITY);
#ifdef _WIN64
		TryDisplayAsString(registerArgs[0], "RCX");
		TryDisplayAsString(registerArgs[1], "RDX");
		TryDisplayAsString(registerArgs[2], "R8 ");
		TryDisplayAsString(registerArgs[3], "R9 ");
#endif
		printf("SP  : 0x%p\n", stackPtr);
		SetConsoleTextAttribute(consoleOutput, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	}
};

std::string GetModuleDirectory(HMODULE hMod) {
	std::string result;
	char *outputDir;
	char buf;
	unsigned int maxSize = 15;
	unsigned int outputMaxSize;
	outputDir = (char*)calloc(maxSize, sizeof(char));

	while (maxSize == (outputMaxSize = GetModuleFileNameA(hModule, outputDir, maxSize))) {
		maxSize *= 3.F / 2;
		outputDir = (char*)realloc(outputDir, maxSize*sizeof(char));

		if (outputMaxSize == 0) {
			printf("Erreur lors de la recuperation du chemin vers le module 0x%p\n", hMod);
			free(outputDir);
			return "";
		}
	}

	int i;
	for (i = strlen(outputDir); i >= 0 && outputDir[i] != '\\'; i--);
	if (i > 0) {
		outputDir[i + 1] = '\0';
	}
	result = std::string(outputDir);
	free(outputDir);
	return result;
}



DWORD WINAPI startUpThreadGlobalHook(LPVOID args)
{
	if (AllocConsole()) {
		freopen("CONOUT$", "w", stdout);
	}
	moduleDirectory = GetModuleDirectory(hModule);

	unordered_map<string, bool> includeds;

	char currentAppDir[512] = { '\0' };
	GetCurrentDirectoryA(sizeof(currentAppDir)-1, currentAppDir);

	cout << "Current application directory : " << currentAppDir << endl;
	cout << "Module directory : " << moduleDirectory << endl;

	ifstream fConfig(moduleDirectory + "ptrace_conf.cfg", ios::in);
	ofstream fDummpIAT(moduleDirectory + "DumpIAT.txt", ios::out);

	std::string modules;
	getline(fConfig, modules);

	if (fConfig) {
		cout << "Including functions..." << endl;
		std::string buffer;
		while (getline(fConfig, buffer)) {
			includeds[buffer] = true;
		}
		cout << "Including OK" << endl;

	}
	else {
		cout << "Warning : fichier de config introuvable" << endl;
	}


	
	IATDumpProcess(fDummpIAT, modules);

	std::cout << "IATs Dumps finished ! Take a look at DumpIAT.txt" << std::endl;

	IATTraceInclude(includeds, modules, std::move(std::unique_ptr<HookCallback>(new LogHookCallback())));
	return 0;
}


BOOL APIENTRY DllMain(HMODULE hMod, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	hModule = hMod;

	switch (ul_reason_for_call) {
		
		case DLL_PROCESS_ATTACH: {
			CreateThread(NULL, 0, startUpThreadGlobalHook, NULL, 0, NULL);
			break;
		}
		
		case DLL_PROCESS_DETACH: {
			break;
		}
	}
	return TRUE;
}
