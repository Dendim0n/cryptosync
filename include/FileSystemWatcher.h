#pragma once

#include <filesystem>
 <string>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>

namespace fs = std::filesystem;

class FileSystemWatcher {
public:
    FileSystemWatcher();
    ~FileSystemWatcher();

    void start();
    void stop();
    void setEncryptedFolder(const fs::path& encrypted_folder);
    void setDecryptedFolder(const fs::path& decrypted_folder);
    void setSecretKey(const std::string& key);

private:
    void watch_directory(fs::path directory, std::function<void(const fs::path&)> callback);
    void encrypt_file(const fs::path& file_path);
    void decrypt_file(const fs::path& file_path);
    void save_state();
    void load_state();

    fs::path encrypted_folder_;
    fs::path decrypted_folder_;
    CryptoPP::SecByteBlock secret_key_;
    std::unordered_set<fs::path> existing_encrypted_files_;
    std::unordered_set<fs::path> existing_decrypted_files_;
    std::unordered_map<fs::path, std::string> task_state_; // 存储文件处理状态
    std::mutex mtx_;
    std::condition_variable cv_;
    bool stop_watching_ = false;
    std::thread watcher_thread_;
    std::string state_file_ = "sync_state.txt"; // 状态文件名

#if defined(_WIN32)
    HANDLE dir_handle_;
#elif defined(__unix__)
    int inotify_fd_;
#endif
};

// 信号处理函数
void signal_handler(int signal);