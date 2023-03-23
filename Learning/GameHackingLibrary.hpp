#pragma once
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string.h>
#include <psapi.h>
#include <vector>
#include <array>


namespace external {
	HANDLE getProcHandle(DWORD pid);
	DWORD getProcID(const wchar_t* name);
	int LoadLibaryInjector(const wchar_t* dllPath, HANDLE proc);

	template<typename T>
	T readMemory(HANDLE proc, LPVOID addr);
	template<typename T>
	T writeMemory(HANDLE proc, LPVOID addr, T var);
	template<typename T>
	DWORD protectMemory(HANDLE proc, LPVOID addr, DWORD prot);
}

namespace internal {
	void    x64_detour(DWORD64* target, DWORD64 hook);

	template<typename T>
	T readMemory(LPVOID addr);
	template<typename T>
	void writeMemory(LPVOID addr, T val);
	template<typename T>
	DWORD protectMemory(LPVOID addr, DWORD prot);
	template<int SIZE>
	void writeNops(DWORD addr);

}