#include "FileSystemWatcher.h"
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <spdlog/spdlog.h>
#include <fstream>
#include <sstream>

// 全局指针，用于信号处理
FileSystemWatcher* g_watcher = nullptr;

FileSystemWatcher::FileSystemWatcher() {
    spdlog::info("Initializing FileSystemWatcher");

    // Initialize platform specific handles
#if defined(_WIN32)
    dir_handle_ = INVALID_HANDLE_VALUE;
#elif defined(__unix__)
    inotify_fd_ = inotify_init();
    if (inotify_fd_ < 0) {
        spdlog::error("Error initializing inotify");
        exit(EXIT_FAILURE);
    }
#endif

    // 加载状态
    load_state();

    // 设置全局指针
    g_watcher = this;
}

FileSystemWatcher::~FileSystemWatcher() {
    stop();
    // Clean up platform specific handles
#if defined(_WIN32)
    if (dir_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(dir_handle_);
    }
#elif defined(__unix__)
    if (inotify_fd_ >= 0) {
        close(inotify_fd_);
    }
#endif
}

void FileSystemWatcher::stop() {
    spdlog::info("Stopping FileSystemWatcher...");
    stop_watching_ = true;
    cv_.notify_all();
    if (watcher_thread_.joinable()) {
        watcher_thread_.join();
    }
    save_state(); // 保存状态
}

void FileSystemWatcher::setEncryptedFolder(const fs::path& encrypted_folder) {
    std::lock_guard<std::mutex> lock(mtx_);
    encrypted_folder_ = encrypted_folder;
    spdlog::info("Set encrypted folder to: {}", encrypted_folder_.string());

#if defined(_WIN32)
    if (dir_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(dir_handle_);
    }
    dir_handle_ = CreateFile(encrypted_folder_.c_str(), FILE_LIST_DIRECTORY,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                             OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
#elif defined(__unix__)
    inotify_add_watch(inotify_fd_, encrypted_folder_.c_str(), IN_CREATE | IN_MODIFY);
#endif
}

void FileSystemWatcher::setDecryptedFolder(const fs::path& decrypted_folder) {
    std::lock_guard<std::mutex> lock(mtx_);
    decrypted_folder_ = decrypted_folder;
    spdlog::info("Set decrypted folder to: {}", decrypted_folder_.string());

#if defined(__unix__)
    inotify_add_watch(inotify_fd_, decrypted_folder_.c_str(), IN_CREATE | IN_MODIFY);
#endif
}

void FileSystemWatcher::setSecretKey(const std::string& key) {
    secret_key_ = CryptoPP::SecByteBlock(reinterpret_cast<const byte*>(key.data()), key.size());
    spdlog::info("Set secret key");
}

void FileSystemWatcher::start() {
    try {
        spdlog::info("Starting FileSystemWatcher");

        std::unique_lock<std::mutex> lock(mtx_);
        for (const auto& file : fs::directory_iterator(encrypted_folder_)) {
            existing_encrypted_files_.emplace(file.path().filename());
        }
        for (const auto& file : fs::directory_iterator(decrypted_folder_)) {
            existing_decrypted_files_.emplace(file.path().filename());
        }

        watcher_thread_ = std::thread([this]() {
            while (!stop_watching_) {
                watch_directory(encrypted_folder_, [this](const fs::path& file_path) {
                    if (task_state_[file_path] != "decrypted") {
                        decrypt_file(file_path);
                    }
                });

                watch_directory(decrypted_folder_, [this](const fs::path& file_path) {
                    if (task_state_[file_path] != "encrypted") {
                        encrypt_file(file_path);
                    }
                });

                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        });

        cv_.wait(lock, [this]() { return stop_watching_; });

    } catch (const std::exception& e) {
        spdlog::error("An error occurred during monitoring: {}", e.what());
    }
}

#if defined(_WIN32)
void FileSystemWatcher::watch_directory(fs::path directory, std::function<void(const fs::path&)> callback) {
    std::lock_guard<std::mutex> lock(mtx_);
    FILE_NOTIFY_INFORMATION buffer[1024];
    DWORD bytesReturned;
    while (!stop_watching_) {
        if (ReadDirectoryChangesW(dir_handle_, buffer, sizeof(buffer), TRUE,
                                  FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE, &bytesReturned, NULL, NULL)) {
            for (int i = 0; i < bytesReturned / sizeof(FILE_NOTIFY_INFORMATION); ++i) {
                FILE_NOTIFY_INFORMATION* event = &buffer[i];
                std::wstring fileName(event->FileName, event->FileNameLength / sizeof(WCHAR));
                fs::path changedPath = directory / fileName;
                if (event->Action == FILE_ACTION_ADDED || event->Action == FILE_ACTION_MODIFIED) {
                    callback(changedPath);
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
};
#elif defined(__unix__)
void FileSystemWatcher::watch_directory(fs::path directory, std::function<void(const fs::path&)> callback) {
    std::lock_guard<std::mutex> lock(mtx_);
    char buffer[1024];
    while (!stop_watching_) {
        int length = read(inotify_fd_, buffer, 1024);
        if (length < 0) {
            spdlog::error("Error reading inotify events");
            continue;
        }
        int i = 0;
        while (i < length) {
            struct inotify_event* event = (struct inotify_event*)&buffer[i];
            if (event->len && (event->mask & (IN_CREATE | IN_MODIFY))) {
                fs::path changedPath = directory / event->name;
                callback(changedPath);
            }
            i += sizeof(struct inotify_event) + event->len;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
};
#endif

void FileSystemWatcher::encrypt_file(const fs::path& file_path) {
    std::lock_guard<std::mutex> lock(mtx_);
    try {
        spdlog::info("Encrypting file: {}", file_path.string());

        std::ifstream infile(file_path, std::ios::binary);
        std::ofstream outfile(file_path.string() + ".enc", std::ios::binary);

        if (!infile || !outfile) {
            throw std::runtime_error("Error opening files for encryption.");
        }

        CryptoPP::AutoSeededRandomPool prng;
        byte iv[CryptoPP::AES::BLOCKSIZE];
        prng.GenerateBlock(iv, sizeof(iv));

        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor(secret_key_, secret_key_.size(), iv);
        CryptoPP::FileSource(infile, true, 
            new CryptoPP::StreamTransformationFilter(encryptor, 
            new CryptoPP::FileSink(outfile), CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING));

        infile.close();
        outfile.close();

        spdlog::info("Encrypted file: {}", file_path.string());
        task_state_[file_path] = "encrypted"; // 更新状态

    } catch (const std::exception& e) {
        spdlog::error("An error occurred during file encryption: {}", e.what());
    }
}

void FileSystemWatcher::decrypt_file(const fs::path& file_path) {
    std::lock_guard<std::mutex> lock(mtx_);
    try {
        spdlog::info("Decrypting file: {}", file_path.string());

        std::ifstream infile(file_path, std::ios::binary);
        auto decrypted_filename = file_path.stem();
        std::ofstream outfile((decrypted_filename.string()).c_str(), std::ios::binary);

        if (!infile || !outfile) {
            throw std::runtime_error("Error opening files for decryption.");
        }

        byte iv[CryptoPP::AES::BLOCKSIZE];
        infile.read(reinterpret_cast<char*>(iv), sizeof(iv));

        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor(secret_key_, secret_key_.size(), iv);
        CryptoPP::FileSource(infile, true, 
            new CryptoPP::StreamTransformationFilter(decryptor, 
            new CryptoPP::FileSink(outfile), CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING));

        infile.close();
        outfile.close();

        spdlog::info("Decrypted file: {}", file_path.string());
        task_state_[file_path] = "decrypted"; // 更新状态

    } catch (const std::exception& e) {
        spdlog::error("An error occurred during file decryption: {}", e.what());
    }
}

// 保存状态到文件
void FileSystemWatcher::save_state() {
    try {
        std::ofstream ofs(state_file_, std::ios::out | std::ios::trunc);
        if (!ofs) {
            throw std::runtime_error("Failed to open state file for writing");
        }

        for (const auto& [file_path, state] : task_state_) {
            ofs << file_path.string() << " " << state << "\n";
        }

        ofs.close();
        spdlog::info("Saved state to: {}", state_file_);
    } catch (const std::exception &e) {
        spdlog::error("Failed to save state: {}", e.what());
    }
}

// 加载状态从文件
void FileSystemWatcher::load_state() {
    try {
        std::ifstream ifs(state_file_, std::ios::in);
        if (!ifs) {
            spdlog::warn("State file not found: {}", state_file_);
            return;
        }

        std::string file_path;
        std::string state;
        while (ifs >> file_path >> state) {
            task_state_[file_path] = state;
        }

        ifs.close();
        spdlog::info("Loaded state from: {}", state_file_);
    } catch (const std::exception &e) {
        spdlog::error("Failed to load state: {}", e.what());
    }
}

// 信号处理函数
void signal_handler(int signal) {
    if (g_watcher) {
        spdlog::info("Signal received: {}", signal);
        g_watcher->stop();
    }
}