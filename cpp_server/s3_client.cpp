#include "s3_client.hpp"
#include "logger.hpp"
#include <curl/curl.h>
#include <fstream>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <algorithm>

// Helper for HMAC-SHA256
std::string HmacSha256(const std::string& key, const std::string& msg) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    HMAC(EVP_sha256(), key.c_str(), key.length(),
         reinterpret_cast<const unsigned char*>(msg.c_str()), msg.length(),
         hash, NULL);
    return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

std::string HexEncode(const unsigned char* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << (int)data[i];
    }
    return ss.str();
}

std::string Sha256Hex(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(str.c_str()), str.length(), hash);
    return HexEncode(hash, SHA256_DIGEST_LENGTH);
}

S3Client::S3Client(const Config::ServerConfig& config)
    : endpoint_(config.s3_endpoint), bucket_(config.s3_bucket),
      access_key_(config.s3_access_key), secret_key_(config.s3_secret_key),
      region_(config.s3_region) {
    curl_global_init(CURL_GLOBAL_ALL);
}

S3Client::~S3Client() {
    curl_global_cleanup();
}

// Simple read callback for uploading
size_t ReadCallback(void* ptr, size_t size, size_t nmemb, void* stream) {
    std::ifstream* file = static_cast<std::ifstream*>(stream);
    file->read(static_cast<char*>(ptr), size * nmemb);
    return file->gcount();
}

// Simple write callback for downloading
size_t WriteCallback(void* ptr, size_t size, size_t nmemb, void* stream) {
    std::ofstream* file = static_cast<std::ofstream*>(stream);
    file->write(static_cast<char*>(ptr), size * nmemb);
    return size * nmemb;
}

// AWS Signature V4 Implementation helper
// Note: This is a simplified implementation for the MVP.
// Full AWS SigV4 is complex. We implement enough for PUT/GET.
std::string GetAuthHeader(const std::string& method, const std::string& uri,
                          const std::string& query, const std::string& access_key,
                          const std::string& secret_key, const std::string& region,
                          const std::string& service, const std::string& date_iso,
                          const std::string& date_ymd, const std::string& payload_hash,
                          const std::string& host) {

    // 1. Canonical Request
    std::stringstream canonical_req;
    canonical_req << method << "\n"
                  << uri << "\n"
                  << query << "\n"
                  << "host:" << host << "\n"
                  << "x-amz-content-sha256:" << payload_hash << "\n"
                  << "x-amz-date:" << date_iso << "\n\n"
                  << "host;x-amz-content-sha256;x-amz-date\n"
                  << payload_hash;

    // 2. String to Sign
    std::string scope = date_ymd + "/" + region + "/" + service + "/aws4_request";
    std::stringstream string_to_sign;
    string_to_sign << "AWS4-HMAC-SHA256\n"
                   << date_iso << "\n"
                   << scope << "\n"
                   << Sha256Hex(canonical_req.str());

    // 3. Signature
    std::string kDate = HmacSha256("AWS4" + secret_key, date_ymd);
    std::string kRegion = HmacSha256(kDate, region);
    std::string kService = HmacSha256(kRegion, service);
    std::string kSigning = HmacSha256(kService, "aws4_request");
    std::string signature = HexEncode(reinterpret_cast<const unsigned char*>(HmacSha256(kSigning, string_to_sign.str()).c_str()), SHA256_DIGEST_LENGTH);

    // 4. Header
    std::stringstream auth_header;
    auth_header << "AWS4-HMAC-SHA256 Credential=" << access_key << "/" << scope
                << ", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=" << signature;

    return auth_header.str();
}

bool S3Client::UploadFile(const std::string& local_path, const std::string& s3_key) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    std::ifstream file(local_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Payload Hash (Empty string hash or actual file hash? AWS requires Unsigned-Payload or actual hash)
    // For simplicity with streaming, we use UNSIGNED-PAYLOAD if allowed, or we must hash the file.
    // Let's calculate hash for robustness.
    // NOTE: Reading entire file to hash it fits MVP but not large scale.
    // For now, we assume we can hash it (since we just wrote it to temp).
    // Actually, let's use "UNSIGNED-PAYLOAD" for simplicity if the endpoint supports it (MinIO does).
    // AWS S3 generally requires it for chunked uploads or signed payload.
    // Let's compute hash to be safe.
    // ... (Hash computation omitted for brevity in MVP implementation, using dummy or assuming small file)
    std::string payload_hash = "UNSIGNED-PAYLOAD";

    // Date
    time_t now = time(0);
    tm* gmt = gmtime(&now);
    char date_iso[20];
    strftime(date_iso, 20, "%Y%m%dT%H%M%SZ", gmt);
    char date_ymd[9];
    strftime(date_ymd, 9, "%Y%m%d", gmt);

    std::string host = bucket_ + "." + endpoint_;
    std::string url = "https://" + host + "/" + s3_key;

    // Headers
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, ("Host: " + host).c_str());
    headers = curl_slist_append(headers, ("x-amz-date: " + std::string(date_iso)).c_str());
    headers = curl_slist_append(headers, ("x-amz-content-sha256: " + payload_hash).c_str());

    std::string auth = GetAuthHeader("PUT", "/" + s3_key, "", access_key_, secret_key_, region_, "s3", date_iso, date_ymd, payload_hash, host);
    headers = curl_slist_append(headers, ("Authorization: " + auth).c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_PUT, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, ReadCallback);
    curl_easy_setopt(curl, CURLOPT_READDATA, &file);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)file_size);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    // For dev/test with self-signed certs (MinIO), we might need to relax SSL verify
    // But we want industrial grade... assume valid certs for S3.
    // curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        Logger::Error("S3 Upload failed: " + std::string(curl_easy_strerror(res)));
        return false;
    }
    return true;
}

bool S3Client::DownloadFile(const std::string& s3_key, const std::string& local_path) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    std::ofstream file(local_path, std::ios::binary);
    if (!file.is_open()) return false;

    std::string payload_hash = "UNSIGNED-PAYLOAD";

    time_t now = time(0);
    tm* gmt = gmtime(&now);
    char date_iso[20];
    strftime(date_iso, 20, "%Y%m%dT%H%M%SZ", gmt);
    char date_ymd[9];
    strftime(date_ymd, 9, "%Y%m%d", gmt);

    std::string host = bucket_ + "." + endpoint_;
    std::string url = "https://" + host + "/" + s3_key;

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, ("Host: " + host).c_str());
    headers = curl_slist_append(headers, ("x-amz-date: " + std::string(date_iso)).c_str());
    headers = curl_slist_append(headers, ("x-amz-content-sha256: " + payload_hash).c_str());

    std::string auth = GetAuthHeader("GET", "/" + s3_key, "", access_key_, secret_key_, region_, "s3", date_iso, date_ymd, payload_hash, host);
    headers = curl_slist_append(headers, ("Authorization: " + auth).c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &file);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        Logger::Error("S3 Download failed: " + std::string(curl_easy_strerror(res)));
        return false;
    }
    return true;
}
