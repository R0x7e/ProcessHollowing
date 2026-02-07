#include "../include/PEParser.h"

namespace Hollowing {
    /**
     * @brief 解析并验证 PE 文件格式
     * 
     * 该函数会检查：
     * 1. DOS 头部 (MZ 签名)
     * 2. NT 头部 (PE 签名)
     * 3. 目标机器架构 (x86 或 x64)
     */
    bool PEParser::Parse(const std::vector<BYTE>& data, PE_INFO& peInfo) {
        LOG_INFO("正在解析 PE 头部信息...");
        
        // 1. 基本大小检查
        if (data.size() < sizeof(IMAGE_DOS_HEADER)) return false;

        peInfo.data = data;
        peInfo.size = (DWORD)data.size();
        
        // 2. 获取 DOS 头并验证 MZ 签名
        peInfo.dosHeader = (PIMAGE_DOS_HEADER)peInfo.data.data();
        if (peInfo.dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            LOG_ERROR("无效的 DOS 签名 (MZ)");
            return false;
        }

        // 3. 获取 NT 头并验证 PE 签名
        // e_lfanew 指向 NT 头的起始位置
        peInfo.ntHeaders32 = (PIMAGE_NT_HEADERS32)(peInfo.data.data() + peInfo.dosHeader->e_lfanew);
        if (peInfo.ntHeaders32->Signature != IMAGE_NT_SIGNATURE) {
            LOG_ERROR("无效的 NT 签名 (PE)");
            return false;
        }

        // 4. 检测架构 (32 位 vs 64 位)
        // 通过 OptionalHeader 中的 Magic 字段判断
        if (peInfo.ntHeaders32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            peInfo.is64Bit = true;
            peInfo.ntHeaders64 = (PIMAGE_NT_HEADERS64)peInfo.ntHeaders32;
            LOG_INFO("检测到目标 PE 为 64 位架构");
        } else if (peInfo.ntHeaders32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            peInfo.is64Bit = false;
            LOG_INFO("检测到目标 PE 为 32 位架构");
        } else {
            LOG_ERROR("未知的 PE 架构");
            return false;
        }

        return true;
    }
}
