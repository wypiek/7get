#include "platform/http.h"

#include <windows.h>
#include <winhttp.h>

#include <memory>

#include "platform/winutil.h"
#include "util/json.h"
#include "util/strings.h"

namespace sg {

namespace {

HttpOptions g_opts;

const char kTlsHint[] =
    "Windows 7 needs update KB3140245 and the WinHTTP 'DefaultSecureProtocols' registry value "
    "(see 'sevenget doctor' and docs/security.md) to use TLS 1.2. SevenGet will not fall back to "
    "older protocols or disable certificate validation.";

struct InetHandle {
    HINTERNET h = nullptr;
    InetHandle() = default;
    explicit InetHandle(HINTERNET x) : h(x) {}
    ~InetHandle() {
        if (h) WinHttpCloseHandle(h);
    }
    InetHandle(const InetHandle&) = delete;
    InetHandle& operator=(const InetHandle&) = delete;
};

std::string SecureFailureText(DWORD flags) {
    std::vector<std::string> parts;
    if (flags & WINHTTP_CALLBACK_STATUS_FLAG_CERT_REV_FAILED) parts.push_back("revocation check failed");
    if (flags & WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT) parts.push_back("invalid certificate");
    if (flags & WINHTTP_CALLBACK_STATUS_FLAG_CERT_REVOKED) parts.push_back("certificate revoked");
    if (flags & WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA)
        parts.push_back("untrusted certificate authority (Windows 7 may need root certificate updates)");
    if (flags & WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID) parts.push_back("certificate name mismatch");
    if (flags & WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID)
        parts.push_back("certificate expired or not yet valid (check the system clock)");
    if (flags & WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR)
        parts.push_back("TLS channel error (server may require a protocol or cipher suite this system lacks)");
    return parts.empty() ? "TLS handshake failed" : Join(parts, "; ");
}

void CALLBACK StatusCallback(HINTERNET, DWORD_PTR context, DWORD status, LPVOID info, DWORD) {
    if (status == WINHTTP_CALLBACK_STATUS_SECURE_FAILURE && context && info)
        *reinterpret_cast<DWORD*>(context) = *static_cast<DWORD*>(info);
}

bool OpenSession(InetHandle& session, HttpError& err) {
    std::wstring proxy = Widen(g_opts.proxy);
    std::wstring bypass;
    DWORD access = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
    if (!g_opts.proxy.empty()) {
        access = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
    } else {
        WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ie{};
        if (WinHttpGetIEProxyConfigForCurrentUser(&ie)) {
            if (ie.lpszProxy && *ie.lpszProxy) {
                access = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                proxy = ie.lpszProxy;
                if (ie.lpszProxyBypass) bypass = ie.lpszProxyBypass;
            }
            if (ie.lpszProxy) GlobalFree(ie.lpszProxy);
            if (ie.lpszProxyBypass) GlobalFree(ie.lpszProxyBypass);
            if (ie.lpszAutoConfigUrl) GlobalFree(ie.lpszAutoConfigUrl);
        }
    }
    session.h = WinHttpOpen(L"SevenGet/1.0 (Windows; WinHTTP)", access,
                            access == WINHTTP_ACCESS_TYPE_NAMED_PROXY ? proxy.c_str() : WINHTTP_NO_PROXY_NAME,
                            bypass.empty() ? WINHTTP_NO_PROXY_BYPASS : bypass.c_str(), 0);
    if (!session.h) {
        err.kind = HttpError::Kind::Network;
        err.message = "WinHTTP initialisation failed: " + LastErrorMessage(GetLastError());
        return false;
    }
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
#ifdef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
    // Only systems that implement TLS 1.3 in Schannel accept the flag; older
    // WinHTTP versions reject unknown bits, which would break TLS 1.2 too.
    const OsInfo& os = GetOsInfo();
    if (os.major >= 10 && os.build >= 20348) protocols |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
#endif
    if (!WinHttpSetOption(session.h, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof protocols)) {
        err.kind = HttpError::Kind::Tls;
        err.message = "this system's WinHTTP does not support TLS 1.2 (" + LastErrorMessage(GetLastError()) + ")";
        err.hint = kTlsHint;
        return false;
    }
    DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
    WinHttpSetOption(session.h, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof policy);
    int t = g_opts.timeoutSeconds * 1000;
    WinHttpSetTimeouts(session.h, t, t, t, t);
    return true;
}

// Applies WPAD / PAC proxy settings for a request when the user configured them in Internet Options.
void ApplyAutoProxy(HINTERNET session, HINTERNET request, const std::wstring& url) {
    if (!g_opts.proxy.empty()) return;
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ie{};
    if (!WinHttpGetIEProxyConfigForCurrentUser(&ie)) return;
    bool autoDetect = ie.fAutoDetect != FALSE;
    std::wstring pac = ie.lpszAutoConfigUrl ? ie.lpszAutoConfigUrl : L"";
    if (ie.lpszProxy) GlobalFree(ie.lpszProxy);
    if (ie.lpszProxyBypass) GlobalFree(ie.lpszProxyBypass);
    if (ie.lpszAutoConfigUrl) GlobalFree(ie.lpszAutoConfigUrl);
    if (!autoDetect && pac.empty()) return;
    WINHTTP_AUTOPROXY_OPTIONS ao{};
    if (!pac.empty()) {
        ao.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
        ao.lpszAutoConfigUrl = pac.c_str();
    } else {
        ao.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
        ao.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
    }
    ao.fAutoLogonIfChallenged = TRUE;
    WINHTTP_PROXY_INFO pi{};
    if (WinHttpGetProxyForUrl(session, url.c_str(), &ao, &pi)) {
        WinHttpSetOption(request, WINHTTP_OPTION_PROXY, &pi, sizeof pi);
        if (pi.lpszProxy) GlobalFree(pi.lpszProxy);
        if (pi.lpszProxyBypass) GlobalFree(pi.lpszProxyBypass);
    }
}

std::wstring QueryHeaderString(HINTERNET req, DWORD which) {
    DWORD size = 0;
    WinHttpQueryHeaders(req, which, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &size, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) return {};
    std::wstring buf(size / sizeof(wchar_t) + 1, L'\0');
    if (!WinHttpQueryHeaders(req, which, WINHTTP_HEADER_NAME_BY_INDEX, &buf[0], &size, WINHTTP_NO_HEADER_INDEX))
        return {};
    buf.resize(size / sizeof(wchar_t));
    return buf;
}

struct Response {
    InetHandle connect;
    InetHandle request;
    DWORD status = 0;
    uint64_t contentLength = 0;  // 0 = unknown
    std::string etag, lastModified;
};

bool NetworkErrorFromWin32(DWORD e, DWORD secureFlags, HttpError& err) {
    if (e == ERROR_WINHTTP_SECURE_FAILURE || secureFlags) {
        err.kind = HttpError::Kind::Tls;
        err.message = "secure connection failed: " + SecureFailureText(secureFlags);
        err.hint = kTlsHint;
        return false;
    }
    err.kind = HttpError::Kind::Network;
    err.message = LastErrorMessage(e);
    if (e == ERROR_WINHTTP_NAME_NOT_RESOLVED) err.hint = "check the network connection and proxy settings";
    return false;
}

bool SendRequest(HINTERNET session, const std::string& url, const std::wstring& extraHeaders, Response& resp,
                 HttpError& err) {
    std::wstring wurl = Widen(url);
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof uc;
    uc.dwSchemeLength = uc.dwHostNameLength = uc.dwUrlPathLength = uc.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc) || uc.nScheme != INTERNET_SCHEME_HTTPS) {
        err.kind = HttpError::Kind::InvalidUrl;
        err.message = "only https:// URLs are allowed: " + url;
        return false;
    }
    std::wstring host(uc.lpszHostName, uc.dwHostNameLength);
    std::wstring path(uc.lpszUrlPath, uc.dwUrlPathLength);
    if (uc.lpszExtraInfo) path.append(uc.lpszExtraInfo, uc.dwExtraInfoLength);
    if (path.empty()) path = L"/";
    resp.connect.h = WinHttpConnect(session, host.c_str(), uc.nPort, 0);
    if (!resp.connect.h) return NetworkErrorFromWin32(GetLastError(), 0, err);
    resp.request.h = WinHttpOpenRequest(resp.connect.h, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!resp.request.h) return NetworkErrorFromWin32(GetLastError(), 0, err);
    HINTERNET req = resp.request.h;
    ApplyAutoProxy(session, req, wurl);
    if (g_opts.checkRevocation) {
        DWORD feat = WINHTTP_ENABLE_SSL_REVOCATION;
        WinHttpSetOption(req, WINHTTP_OPTION_ENABLE_FEATURE, &feat, sizeof feat);
    }
    DWORD secureFlags = 0;
    DWORD_PTR ctx = reinterpret_cast<DWORD_PTR>(&secureFlags);
    WinHttpSetOption(req, WINHTTP_OPTION_CONTEXT_VALUE, &ctx, sizeof ctx);
    WinHttpSetStatusCallback(req, StatusCallback, WINHTTP_CALLBACK_FLAG_SECURE_FAILURE, 0);
    BOOL ok = WinHttpSendRequest(req, extraHeaders.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : extraHeaders.c_str(),
                                 extraHeaders.empty() ? 0 : static_cast<DWORD>(-1), WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (ok) ok = WinHttpReceiveResponse(req, nullptr);
    if (!ok) return NetworkErrorFromWin32(GetLastError(), secureFlags, err);

    // Belt and braces: the final URL after redirects must still be HTTPS.
    DWORD urlSize = 0;
    WinHttpQueryOption(req, WINHTTP_OPTION_URL, nullptr, &urlSize);
    if (urlSize) {
        std::wstring finalUrl(urlSize / sizeof(wchar_t) + 1, L'\0');
        if (WinHttpQueryOption(req, WINHTTP_OPTION_URL, &finalUrl[0], &urlSize)) {
            finalUrl.resize(wcsnlen(finalUrl.c_str(), finalUrl.size()));
            if (!IsHttpsUrl(Narrow(finalUrl))) {
                err.kind = HttpError::Kind::InvalidUrl;
                err.message = "redirected to a non-HTTPS location; refusing";
                return false;
            }
        }
    }
    DWORD status = 0, size = sizeof status;
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                        &status, &size, WINHTTP_NO_HEADER_INDEX);
    resp.status = status;
    int64_t len = 0;
    if (ParseInt64(Narrow(QueryHeaderString(req, WINHTTP_QUERY_CONTENT_LENGTH)), len) && len > 0)
        resp.contentLength = static_cast<uint64_t>(len);
    resp.etag = Narrow(QueryHeaderString(req, WINHTTP_QUERY_ETAG));
    resp.lastModified = Narrow(QueryHeaderString(req, WINHTTP_QUERY_LAST_MODIFIED));
    return true;
}

// Reads the body, calling sink for each chunk. Returns false on error/cancel.
template <typename Sink>
bool ReadBody(HINTERNET req, Sink sink, HttpError& err) {
    std::vector<char> buf(64 * 1024);
    for (;;) {
        if (CancelRequested()) {
            err.kind = HttpError::Kind::Cancelled;
            err.message = "download cancelled";
            return false;
        }
        DWORD got = 0;
        if (!WinHttpReadData(req, buf.data(), static_cast<DWORD>(buf.size()), &got)) {
            err.kind = HttpError::Kind::Network;
            err.message = "connection interrupted: " + LastErrorMessage(GetLastError());
            return false;
        }
        if (got == 0) return true;
        if (!sink(buf.data(), got)) return false;
    }
}

}  // namespace

void SetHttpOptions(const HttpOptions& o) { g_opts = o; }
const HttpOptions& GetHttpOptions() { return g_opts; }

bool IsHttpsUrl(const std::string& url) {
    if (!StartsWith(ToLowerAscii(url), "https://")) return false;
    std::string rest = url.substr(8);
    if (rest.empty() || rest[0] == '/' || rest[0] == ':' || rest[0] == '@') return false;
    for (char c : url)
        if (static_cast<unsigned char>(c) <= 0x20 || c == '"' || c == '<' || c == '>' || c == '\\' || c == 0x7F)
            return false;
    return true;
}

bool HttpGetString(const std::string& url, uint64_t maxBytes, std::string& out, HttpError& err) {
    out.clear();
    if (!IsHttpsUrl(url)) {
        err.kind = HttpError::Kind::InvalidUrl;
        err.message = "only https:// URLs are allowed: " + url;
        return false;
    }
    InetHandle session;
    if (!OpenSession(session, err)) return false;
    for (int attempt = 0;; ++attempt) {
        Response resp;
        err = HttpError{};
        out.clear();
        if (SendRequest(session.h, url, {}, resp, err)) {
            if (resp.status != 200) {
                err.kind = HttpError::Kind::Http;
                err.httpStatus = static_cast<int>(resp.status);
                err.message = "server returned HTTP " + std::to_string(resp.status) + " for " + url;
                return false;
            }
            if (resp.contentLength > maxBytes) {
                err.kind = HttpError::Kind::TooLarge;
                err.message = "response too large";
                return false;
            }
            bool ok = ReadBody(resp.request.h, [&](const char* p, DWORD n) {
                if (out.size() + n > maxBytes) {
                    err.kind = HttpError::Kind::TooLarge;
                    err.message = "response too large";
                    return false;
                }
                out.append(p, n);
                return true;
            }, err);
            if (ok) return true;
        }
        if (err.kind != HttpError::Kind::Network || attempt + 1 >= g_opts.retries || CancelRequested()) return false;
        Sleep(1000u << attempt);
    }
}

bool HttpDownloadFile(const std::string& url, const std::string& dest, uint64_t maxBytes, const ProgressFn& progress,
                      HttpError& err) {
    if (!IsHttpsUrl(url)) {
        err.kind = HttpError::Kind::InvalidUrl;
        err.message = "only https:// URLs are allowed: " + url;
        return false;
    }
    InetHandle session;
    if (!OpenSession(session, err)) return false;
    const std::string part = dest + ".part";
    const std::string partMeta = dest + ".part.json";

    for (int attempt = 0;; ++attempt) {
        err = HttpError{};
        // Resume state: only if the .part belongs to the same URL.
        uint64_t have = 0;
        std::string validator;
        std::string metaText;
        if (FileExists(part) && ReadFileBytes(partMeta, metaText, 1 << 16)) {
            auto pr = ParseJson(metaText);
            const Json* u = pr.ok ? pr.value.Find("url") : nullptr;
            const Json* v = pr.ok ? pr.value.Find("validator") : nullptr;
            if (u && u->IsString() && u->AsString() == url && v && v->IsString() && !v->AsString().empty()) {
                have = FileSize(part);
                validator = v->AsString();
            }
        }
        std::wstring headers;
        if (have > 0) {
            headers = L"Range: bytes=" + Widen(std::to_string(have)) + L"-\r\nIf-Range: " + Widen(validator) + L"\r\n";
        }
        Response resp;
        if (!SendRequest(session.h, url, headers, resp, err)) {
            if (err.kind == HttpError::Kind::Network && attempt + 1 < g_opts.retries && !CancelRequested()) {
                Sleep(1000u << attempt);
                continue;
            }
            return false;
        }
        bool append = false;
        uint64_t total = 0;
        if (resp.status == 206 && have > 0) {
            append = true;
            total = resp.contentLength ? have + resp.contentLength : 0;
        } else if (resp.status == 200) {
            have = 0;
            total = resp.contentLength;
        } else if (resp.status == 416 && have > 0) {
            // Our partial file is stale or complete-but-unrenamed; start over.
            DeleteFileUtf8(part);
            DeleteFileUtf8(partMeta);
            if (attempt + 1 < g_opts.retries) continue;
            err.kind = HttpError::Kind::Http;
            err.httpStatus = 416;
            err.message = "server rejected resume request";
            return false;
        } else {
            err.kind = HttpError::Kind::Http;
            err.httpStatus = static_cast<int>(resp.status);
            err.message = "server returned HTTP " + std::to_string(resp.status) + " for " + url;
            return false;
        }
        if (total > maxBytes) {
            err.kind = HttpError::Kind::TooLarge;
            err.message = "download larger than expected (" + FormatBytes(total) + ")";
            return false;
        }
        std::string newValidator = !resp.etag.empty() ? resp.etag : resp.lastModified;
        // Persist resume metadata before writing data.
        Json meta = Json::Object();
        meta.Set("url", url);
        meta.Set("validator", newValidator);
        WriteFileAtomic(partMeta, meta.Dump());

        HANDLE f = CreateFileW(Widen(part).c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                               append ? OPEN_ALWAYS : CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE) {
            err.kind = HttpError::Kind::Io;
            err.message = "cannot write " + part + ": " + LastErrorMessage(GetLastError());
            return false;
        }
        if (append) {
            LARGE_INTEGER zero{};
            SetFilePointerEx(f, zero, nullptr, FILE_END);
        }
        uint64_t done = have;
        DWORD startTick = GetTickCount();
        uint64_t startBytes = done;
        DWORD lastReport = 0;
        bool ok = ReadBody(resp.request.h, [&](const char* p, DWORD n) {
            if (done + n > maxBytes) {
                err.kind = HttpError::Kind::TooLarge;
                err.message = "download exceeded the expected size; aborting";
                return false;
            }
            DWORD wrote = 0;
            if (!WriteFile(f, p, n, &wrote, nullptr) || wrote != n) {
                err.kind = HttpError::Kind::Io;
                err.message = "write failed: " + LastErrorMessage(GetLastError());
                return false;
            }
            done += n;
            DWORD now = GetTickCount();
            if (progress && (now - lastReport >= 100 || (total && done == total))) {
                lastReport = now;
                double secs = (now - startTick) / 1000.0;
                double rate = secs > 0.2 ? (done - startBytes) / secs : 0;
                if (!progress(done, total, rate)) {
                    err.kind = HttpError::Kind::Cancelled;
                    err.message = "download cancelled";
                    return false;
                }
            }
            return true;
        }, err);
        FlushFileBuffers(f);
        CloseHandle(f);
        if (ok && total && done != total) {
            ok = false;
            err.kind = HttpError::Kind::Network;
            err.message = "connection closed before the download completed";
        }
        if (ok) {
            if (progress) {
                double secs = (GetTickCount() - startTick) / 1000.0;
                progress(done, done, secs > 0 ? (done - startBytes) / secs : 0);
            }
            if (!MoveFileReplace(part, dest)) {
                err.kind = HttpError::Kind::Io;
                err.message = "cannot move download into place: " + LastErrorMessage(GetLastError());
                return false;
            }
            DeleteFileUtf8(partMeta);
            return true;
        }
        if (err.kind == HttpError::Kind::Cancelled || err.kind == HttpError::Kind::TooLarge ||
            err.kind == HttpError::Kind::Io) {
            if (err.kind == HttpError::Kind::TooLarge) {
                DeleteFileUtf8(part);
                DeleteFileUtf8(partMeta);
            }
            return false;  // keep .part for a later resume after cancellation
        }
        if (attempt + 1 >= g_opts.retries || CancelRequested()) return false;
        Sleep(1000u << attempt);  // the next attempt resumes from the .part file
    }
}

bool ProbeTls12Support(std::string& detail) {
    HttpError err;
    InetHandle session;
    if (!OpenSession(session, err)) {
        detail = err.message;
        return false;
    }
    detail = "WinHTTP accepted TLS 1.2-only configuration";
    return true;
}

}  // namespace sg
