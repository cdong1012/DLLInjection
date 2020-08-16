#include "windows.h"
#include <iostream>
#include <string>
#include "tlhelp32.h"
#include "atlconv.h"
#include <tchar.h>
using namespace std;
void dllInjection(const char* processName, const char* dllFileName);
void printError(const char* error);
int main(int argc, char* argv[]) {
	string fileName;
	string processName;
	printf("Enter DLL file name to inject: ");
	getline(cin, fileName);
	printf("Enter process name to inject: ");
	getline(cin, processName);

	dllInjection(processName.c_str(), fileName.c_str());
}

void dllInjection(const char* processName, const char* dllFileName) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printError("CreateToolhelp32Snapshot");
		return;
	}

	LPPROCESSENTRY32 processEntry = (LPPROCESSENTRY32)(&PROCESSENTRY32());
	processEntry->dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, processEntry) == 0) {
		printError("Process32First");
		CloseHandle(hSnapshot);
		return;
	}

	DWORD dwProcessID = 0;
	while (Process32Next(hSnapshot, processEntry) != 0) {
		wstring temp(processEntry->szExeFile);
		string name(temp.begin(), temp.end());


		if (!strcmp(name.c_str(), processName)) {
			dwProcessID = processEntry->th32ProcessID;
			printf("FIND process ID of 0x%x for %s!!\nStarting injection\n", dwProcessID, name.c_str());
			break;
		}
	}

	HANDLE hVictimProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
	if (hVictimProcess == INVALID_HANDLE_VALUE) {
		printError("OpenProcess");
		CloseHandle(hSnapshot);
		return;
	}

	// Write dll name into virtual memory of the process
	LPVOID nameBuffer = VirtualAllocEx(hVictimProcess, NULL, strlen(dllFileName), MEM_COMMIT, PAGE_READWRITE);
	if (!nameBuffer) {
		printError("VirtualAllocEx");
		CloseHandle(hVictimProcess);
		CloseHandle(hSnapshot);
		return;
	}

	if (!WriteProcessMemory(hVictimProcess, nameBuffer, dllFileName, strlen(dllFileName), NULL)) {
		printError("WriteProcessMemory");
		CloseHandle(hVictimProcess);
		CloseHandle(hSnapshot);
		return;
	}

	HMODULE hKernel32 = GetModuleHandle(L"Kernel32.dll");
	if (!hKernel32) {
		printError("GetModuleHandle");
		CloseHandle(hVictimProcess);
		CloseHandle(hSnapshot);
		return;
	}
	FARPROC fpLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
	DWORD dwInjectedProcessID = 0;

	if (!fpLoadLibrary) {
		printError("GetProcAddress");
		CloseHandle(hVictimProcess);
		CloseHandle(hSnapshot);
		return;
	}

	HANDLE hInjectedThread = CreateRemoteThread(hVictimProcess, NULL, 0, (LPTHREAD_START_ROUTINE)fpLoadLibrary, nameBuffer, 0, &dwInjectedProcessID);
	if (!hInjectedThread) {
		printError("CreateRemoteThread");
		CloseHandle(hVictimProcess);
		CloseHandle(hSnapshot);
		return;
	}

	CloseHandle(hVictimProcess);
	CloseHandle(hSnapshot);
	WaitForSingleObject(hInjectedThread, INFINITE);
	printf("Doneee!\n");
}

void printError(const char* error) {
	printf("%s is failing. Error code: 0x%x\n\n", error, GetLastError());
}
