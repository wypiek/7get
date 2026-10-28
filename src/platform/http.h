// SevenGet - HTTPS client on WinHTTP.
//
// Security properties:
//  * Only https:// URLs are accepted; HTTPS->HTTP redirects are refused.
//  * The session is restricted to TLS 1.2 (plus TLS 1.3 where the SDK and OS
//    know it). On Windows 7 this requires KB3140245; without it WinHTTP
//    rejects the option and SevenGet reports how to fix it instead of
//    silently falling back to older protocols.
//  * Certificate validation is never disabled.
#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace sg {

struct HttpOptions {
    int timeoutSeconds = 60;
    std::string proxy;        // "host:port"; empty = system (IE/WinHTTP) settings
    bool checkRevocation = false;  // WINHTTP_ENABLE_SSL_REVOCATION
    int retries = 3;
};

struct HttpError {
    enum class Kind { None, InvalidUrl, Tls, Network, Http, TooLarge, Cancelled, Io } kind = Kind::None;
    std::string message;
    std::string hint;
    int httpStatus = 0;
};

void SetHttpOptions(const HttpOptions& o);
const HttpOptions& GetHttpOptions();

// Validates that url is an absolute https:// URL with a host.
bool IsHttpsUrl(const std::string& url);

// Fetches a small resource (metadata) into memory.
bool HttpGetString(const std::string& url, uint64_t maxBytes, std::string& out, HttpError& err);

// progress(done, total) - total is 0 when unknown. Return false to cancel.
using ProgressFn = std::function<bool(uint64_t done, uint64_t total, double bytesPerSecond)>;

// Downloads url to dest. Data is written to "<dest>.part" and renamed on
// success; an existing .part for the same URL is resumed with HTTP Range
// requests. maxBytes aborts oversized responses.
bool HttpDownloadFile(const std::string& url, const std::string& dest, uint64_t maxBytes, const ProgressFn& progress,
                      HttpError& err);

// Probes whether TLS 1.2 can be enabled for a WinHTTP session (used by doctor).
bool ProbeTls12Support(std::string& detail);

}  // namespace sg
