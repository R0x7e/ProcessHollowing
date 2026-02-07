#pragma once
#include "Common.h"

namespace Hollowing {
    /**
     * @brief PE 文件解析器类
     * 负责验证 PE 文件的合法性并解析出头信息、架构等关键字段
     */
    class PEParser {
    public:
        /**
         * @brief 解析 PE 文件数据
         * @param data 包含 PE 原始二进制数据的 vector
         * @param peInfo [out] 解析后的 PE 信息结构体
         * @return 解析成功返回 true
         */
        static bool Parse(const std::vector<BYTE>& data, PE_INFO& peInfo);
    };
}
