#include "FileSystemWatcher.h"
#include <spdlog/spdlog.h>
#include <csignal>

// 声明信号处理函数
void signal_handler(int signal);

int main() {
    try {
        // 注册信号处理函数 (Unix)
#if defined(__unix__)
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
#elif defined(_WIN32)
        // Windows 下可以使用 SetConsoleCtrlHandler 注册控制台信号处理函数
        SetConsoleCtrlHandler([](DWORD dwCtrlType) -> BOOL {
            if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_CLOSE_EVENT ||
                dwCtrlType == CTRL_BREAK_EVENT || dwCtrlType == CTRL_LOGOFF_EVENT ||
                dwCtrlType == CTRL_SHUTDOWN_EVENT) {
                signal_handler(dwCtrlType);
                return TRUE;
            }
            return FALSE;
        }, TRUE);
#endif

        FileSystemWatcher watcher;

        watcher.setEncryptedFolder("/path/to/encrypted_folder");
        watcher.setDecryptedFolder("/path/to/decrypted_folder");
        watcher.setSecretKey("mysecretaeskey123");

        // 设置全局指针用于信号处理
        g_watcher = &watcher;

        watcher.start();
    } catch (const std::exception& e) {
        spdlog::error("An error occurred: {}", e.what());
    }

    return 0;
}

void signal_handler(int signal) {
    if (g_watcher) {
        spdlog::info("Signal received: {}", signal);
        g_watcher->stop();
    }
}