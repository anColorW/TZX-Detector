#pragma once
#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <string>
#include <TlHelp32.h>
#include <set>
#include <vector>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <string>


DWORD GetPIDByName(const std::wstring& processName) {
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32First(hSnapshot, &processEntry)) {
        do {
            if (wcsstr(processEntry.szExeFile, processName.c_str()) != nullptr) {
                CloseHandle(hSnapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &processEntry));
    }

    CloseHandle(hSnapshot);
    return 0;
}


int main() {
  
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetPIDByName(L"GTAProcess.exe"));

    if (hProcess == NULL) {
        std::cerr << "Process not found..." << std::endl;
        return 0;
    }



    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {

                std::wstring ws(szModName); 
                std::string moduleName(ws.begin(), ws.end());


                if (moduleName.find("GTAProcess.exe") == std::string::npos) {
                    continue;
                }


                MODULEINFO modInfo;
                if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {

                    std::cout << "Memory Region Address: " << modInfo.lpBaseOfDll << std::endl;

                    if (modInfo.SizeOfImage > 105360000) {
                        std::cout << "TZX found injected in fivem process...";
                    }
                    else {
                        std::cout << "TZX not found in fivem process...";
                    }
                }
            }
        }
    }

    CloseHandle(hProcess);

    return 0;
}