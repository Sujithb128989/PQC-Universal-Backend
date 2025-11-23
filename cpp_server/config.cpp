#include "config.hpp"
#include "logger.hpp"
#include <fstream>
#include <iostream>

Config& Config::Instance() {
    static Config instance;
    return instance;
}

void Config::Load(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        Logger::Warn("Config file not found at " + path + ". Using defaults.", "Config");
        return;
    }

    try {
        nlohmann::json j;
        file >> j;

        if (j.contains("address")) config_.address = j["address"];
        if (j.contains("storage_path")) config_.storage_path = j["storage_path"];
        if (j.contains("key_path")) config_.key_path = j["key_path"];
        if (j.contains("log_level")) config_.log_level = j["log_level"];
        if (j.contains("http_api_key")) config_.http_api_key = j["http_api_key"];

        if (j.contains("s3")) {
            auto& s3 = j["s3"];
            if (s3.contains("endpoint")) config_.s3_endpoint = s3["endpoint"];
            if (s3.contains("bucket")) config_.s3_bucket = s3["bucket"];
            if (s3.contains("access_key")) config_.s3_access_key = s3["access_key"];
            if (s3.contains("secret_key")) config_.s3_secret_key = s3["secret_key"];
            if (s3.contains("region")) config_.s3_region = s3["region"];
            if (!config_.s3_bucket.empty() && !config_.s3_access_key.empty()) {
                config_.use_s3 = true;
            }
        }

        Logger::Info("Configuration loaded from " + path, "Config");
    } catch (const std::exception& e) {
        Logger::Error("Failed to parse config file: " + std::string(e.what()), "Config");
    }
}

const Config::ServerConfig& Config::Get() const {
    return config_;
}
