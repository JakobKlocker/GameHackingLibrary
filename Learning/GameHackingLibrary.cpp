#include "GameHackingLibrary.hpp"

DWORD getProcID(const wchar_t* name);
HANDLE  getProcHandle(DWORD pid);
int injector(const wchar_t* dllPath, HANDLE proc);


namespace external
{

    HANDLE  getProcHandle(DWORD pid)
    {
        if (pid <= 0)
            return NULL;
        HANDLE process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, NULL, pid);
        if (process == INVALID_HANDLE_VALUE)
        {
            std::cout << "Couldn't Open Process\n";
            return NULL;
        }
        std::cout << "Sucesfully got a handle\n";
        return process;
    }

    DWORD getProcID(const wchar_t* name)
    {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (Process32First(snap, &entry))
        {
            while (Process32Next(snap, &entry))
            {
                //if (wcscmp(name, entry.szExeFile) == 0)
                //    LoadLibaryInjector(L"C:\\MessageBoxDLL.dll", getProcHandle(entry.th32ProcessID)); //if more than one process, inject it into all with that name
            }
        }
        std::cout << "Process not found\n";
        return (0);
    }

    int LoadLibaryInjector(const wchar_t* dllPath, HANDLE proc)
    {
        int nameLen = wcslen(dllPath);
        LPVOID remoteString = VirtualAllocEx(proc, NULL, nameLen * 2, MEM_COMMIT, PAGE_EXECUTE);
        if (remoteString == NULL)
        {
            std::cout << "Virtual Alloc failed\n";
            return 1;
        }
        WriteProcessMemory(proc, remoteString, dllPath, nameLen * 2, NULL);

        HMODULE k32 = GetModuleHandleA("kernel32.dll");
        if (k32 == NULL)
        {
            std::cout << "Get Kernel32 Handle failed\n";
            return 1;
        }
        LPVOID LLAddr = GetProcAddress(k32, "LoadLibraryW");
        if (LLAddr == NULL)
        {
            std::cout << "Get Proc Addr LoadLibaryW failed\n";
            return 1;
        }
        HANDLE thread = CreateRemoteThread(proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LLAddr, remoteString, NULL, NULL);
        if (thread == NULL)
        {
            std::cout << "Create Remote Thread failed failed\n";
            return 1;
        }
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
        return 0;
    }

    template<typename T>
    T readMemory(HANDLE proc, LPVOID addr)
    {
        T ret;
        ReadProcessMemory(proc, addr, &ret, sizeof(T), NULL);
        return ret;
    }

    template<typename T>
    T writeMemory(HANDLE proc, LPVOID addr, T var)
    {
        WriteProcessMemory(proc, addr, &var, sizeof(T), NULL);
    }

    template<typename T>
    DWORD protectMemory(HANDLE proc, LPVOID addr, DWORD prot)
    {
        DWORD oldProtect;
        VirtualProtectEx(proc, addr, sizeof(T), prot, &oldProtect);
        return oldProtect;
    }

}

namespace internal
{
    template<typename T>
    T readMemory(LPVOID addr)
    {
        return *((T*)addr);
    }

    template<typename T>
    void writeMemory(LPVOID addr, T val)
    {
        *(T*)addr = val;
    }

    template<typename T>
    DWORD protectMemory(LPVOID addr, DWORD prot)
    {
        DWORD oldProtect;
        VirtualProtect(addr, sizeof(T), prot, &oldProtect);
        return oldProtect;
    }

    template<int SIZE>
    void writeNops(DWORD addr)
    {
        DWORD oldProtection = internal::protectMemory<BYTE[SIZE]>(addr, PAGE_EXECUTE_READWRITE);
        for (int i = 0; i < SIZE; i++)
            internal::writeMemory<BYTE>(addr, 0x90);
        internal::protectMemory<BYTE[SIZE]>(addr, oldProtection);
    }

    void    x64_detour(DWORD64* target, DWORD64 hook)
    {
        std::array<BYTE, 12> jmp_hook{ {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov rax, 00000 << replaced with our function bytes
            0xFF, 0xE0                                                      // jmp rax
            } };
        *reinterpret_cast<DWORD64*>(jmp_hook.data() + 2) = hook;
        DWORD oldProt = 0;
        VirtualProtectEx(GetCurrentProcess(), (LPVOID)target, jmp_hook.size(), PAGE_EXECUTE_READWRITE, &oldProt);
        WriteProcessMemory(GetCurrentProcess(), (LPVOID)target, jmp_hook.data(), jmp_hook.size(), NULL);
        VirtualProtectEx(GetCurrentProcess(), (LPVOID)target, jmp_hook.size(), oldProt, &oldProt);
    }
}
