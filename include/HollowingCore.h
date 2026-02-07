#pragma once
#include "Common.h"

namespace Hollowing {
    /**
     * @brief 进程镂空核心逻辑类
     * 负责创建进程、内存替换、重定位修复及执行流切换
     */
    class HollowingCore {
    public:
        /**
         * @brief 执行进程镂空主流程
         * @param targetPath 宿主进程路径 (如 C:\Windows\System32\notepad.exe)
         * @param peInfo 待注入的 PE 文件信息
         * @return 执行成功返回 true
         */
        static bool PerformHollowing(const std::string& targetPath, const PE_INFO& peInfo);

        
        

    private:
        /**
         * @brief 修复 PE 文件的基址重定位表
         * 当 PE 被加载到非首选 ImageBase 时，需要修正硬编码的绝对地址
         */
        static bool FixRelocations(HANDLE hProcess, PVOID remoteBase, const PE_INFO& peInfo, ULONG_PTR delta);

        /**
         * @brief 修复 PE 文件的导入地址表 (IAT)
         * 将所需的 DLL 导出函数地址填入目标进程
         */
        static bool FixImports(HANDLE hProcess, const PE_INFO& peInfo, PVOID remoteBase);


       
    };
}
