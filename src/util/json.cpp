#include "util/json.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "util/strings.h"

namespace sg {

Json::Json(int64_t v) : type_(Type::Number), isInt_(true), int_(v), num_(static_cast<double>(v)) {}

Json::Json(double v) : type_(Type::Number), num_(v) {
    if (std::isfinite(v) && std::floor(v) == v && std::fabs(v) < 9.0e15) {
        isInt_ = true;
        int_ = static_cast<int64_t>(v);
    }
}

const Json* Json::Find(const std::string& key) const {
    if (type_ != Type::Object) return nullptr;
    for (const auto& m : obj_)
        if (m.first == key) return &m.second;
    return nullptr;
}

Json& Json::Set(const std::string& key, Json v) {
    if (type_ != Type::Object) { *this = Object(); }
    for (auto& m : obj_)
        if (m.first == key) { m.second = std::move(v); return m.second; }
    obj_.emplace_back(key, std::move(v));
    return obj_.back().second;
}

void JsonEscape(std::string& out, const std::string& s) {
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20 || c == 0x7F) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    out += '"';
}

std::string Json::Dump(bool pretty) const {
    std::string out;
    DumpTo(out, pretty, 0);
    return out;
}

void Json::DumpTo(std::string& out, bool pretty, int indent) const {
    auto nl = [&](int ind) {
        if (!pretty) return;
        out += '\n';
        out.append(static_cast<size_t>(ind) * 2, ' ');
    };
    switch (type_) {
        case Type::Null: out += "null"; break;
        case Type::Bool: out += bool_ ? "true" : "false"; break;
        case Type::Number: {
            char buf[40];
            if (isInt_) std::snprintf(buf, sizeof buf, "%lld", static_cast<long long>(int_));
            else if (!std::isfinite(num_)) std::snprintf(buf, sizeof buf, "null");
            else std::snprintf(buf, sizeof buf, "%.17g", num_);
            out += buf;
            break;
        }
        case Type::String: JsonEscape(out, str_); break;
        case Type::Array:
            if (arr_.empty()) { out += "[]"; break; }
            out += '[';
            for (size_t i = 0; i < arr_.size(); ++i) {
                if (i) out += ',';
                nl(indent + 1);
                arr_[i].DumpTo(out, pretty, indent + 1);
            }
            nl(indent);
            out += ']';
            break;
        case Type::Object:
            if (obj_.empty()) { out += "{}"; break; }
            out += '{';
            for (size_t i = 0; i < obj_.size(); ++i) {
                if (i) out += ',';
                nl(indent + 1);
                JsonEscape(out, obj_[i].first);
                out += pretty ? ": " : ":";
                obj_[i].second.DumpTo(out, pretty, indent + 1);
            }
            nl(indent);
            out += '}';
            break;
    }
}

class JsonParser {
public:
    JsonParser(const std::string& t, size_t maxDepth) : t_(t), maxDepth_(maxDepth) {}

    JsonParseResult Run() {
        JsonParseResult r;
        if (!IsValidUtf8(t_)) {
            r.error = "input is not valid UTF-8";
            return r;
        }
        // Tolerate a UTF-8 BOM, which Windows editors commonly add.
        if (t_.size() >= 3 && static_cast<unsigned char>(t_[0]) == 0xEF &&
            static_cast<unsigned char>(t_[1]) == 0xBB && static_cast<unsigned char>(t_[2]) == 0xBF)
            p_ = 3;
        SkipWs();
        if (!ParseValue(r.value, 0)) { r.error = Where() + err_; return r; }
        SkipWs();
        if (p_ != t_.size()) { r.error = Where() + "unexpected trailing data"; return r; }
        r.ok = true;
        return r;
    }

private:
    std::string Where() const {
        size_t line = 1, col = 1;
        for (size_t i = 0; i < p_ && i < t_.size(); ++i) {
            if (t_[i] == '\n') { ++line; col = 1; } else ++col;
        }
        return "line " + std::to_string(line) + ", column " + std::to_string(col) + ": ";
    }
    bool Fail(const char* m) { err_ = m; return false; }
    void SkipWs() {
        while (p_ < t_.size() && (t_[p_] == ' ' || t_[p_] == '\t' || t_[p_] == '\n' || t_[p_] == '\r')) ++p_;
    }
    bool Lit(const char* w) {
        size_t n = std::strlen(w);
        if (t_.compare(p_, n, w) != 0) return Fail("invalid literal");
        p_ += n;
        return true;
    }

    bool ParseValue(Json& v, size_t depth) {
        if (depth > maxDepth_) return Fail("nesting too deep");
        if (p_ >= t_.size()) return Fail("unexpected end of input");
        char c = t_[p_];
        if (c == '{') return ParseObject(v, depth);
        if (c == '[') return ParseArray(v, depth);
        if (c == '"') { v.type_ = Json::Type::String; return ParseString(v.str_); }
        if (c == 't') { if (!Lit("true")) return false; v = Json(true); return true; }
        if (c == 'f') { if (!Lit("false")) return false; v = Json(false); return true; }
        if (c == 'n') { if (!Lit("null")) return false; v = Json(); return true; }
        if (c == '-' || (c >= '0' && c <= '9')) return ParseNumber(v);
        return Fail("unexpected character");
    }

    bool ParseObject(Json& v, size_t depth) {
        v = Json::Object();
        ++p_;
        SkipWs();
        if (p_ < t_.size() && t_[p_] == '}') { ++p_; return true; }
        for (;;) {
            SkipWs();
            if (p_ >= t_.size() || t_[p_] != '"') return Fail("expected object key");
            std::string key;
            if (!ParseString(key)) return false;
            if (v.Find(key)) return Fail("duplicate object key");
            SkipWs();
            if (p_ >= t_.size() || t_[p_] != ':') return Fail("expected ':'");
            ++p_;
            SkipWs();
            Json child;
            if (!ParseValue(child, depth + 1)) return false;
            v.obj_.emplace_back(std::move(key), std::move(child));
            SkipWs();
            if (p_ >= t_.size()) return Fail("unexpected end of input");
            if (t_[p_] == ',') { ++p_; continue; }
            if (t_[p_] == '}') { ++p_; return true; }
            return Fail("expected ',' or '}'");
        }
    }

    bool ParseArray(Json& v, size_t depth) {
        v = Json::Array();
        ++p_;
        SkipWs();
        if (p_ < t_.size() && t_[p_] == ']') { ++p_; return true; }
        for (;;) {
            SkipWs();
            Json child;
            if (!ParseValue(child, depth + 1)) return false;
            v.arr_.push_back(std::move(child));
            SkipWs();
            if (p_ >= t_.size()) return Fail("unexpected end of input");
            if (t_[p_] == ',') { ++p_; continue; }
            if (t_[p_] == ']') { ++p_; return true; }
            return Fail("expected ',' or ']'");
        }
    }

    bool Hex4(uint32_t& out) {
        if (p_ + 4 > t_.size()) return Fail("truncated \\u escape");
        out = 0;
        for (int i = 0; i < 4; ++i) {
            char c = t_[p_++];
            out <<= 4;
            if (c >= '0' && c <= '9') out |= static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') out |= static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') out |= static_cast<uint32_t>(c - 'A' + 10);
            else return Fail("invalid \\u escape");
        }
        return true;
    }

    bool ParseString(std::string& out) {
        ++p_;  // opening quote
        out.clear();
        while (p_ < t_.size()) {
            unsigned char c = static_cast<unsigned char>(t_[p_]);
            if (c == '"') { ++p_; return true; }
            if (c < 0x20) return Fail("control character in string");
            if (c != '\\') { out += static_cast<char>(c); ++p_; continue; }
            ++p_;
            if (p_ >= t_.size()) break;
            char e = t_[p_++];
            switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    uint32_t cp;
                    if (!Hex4(cp)) return false;
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        uint32_t lo;
                        if (p_ + 2 > t_.size() || t_[p_] != '\\' || t_[p_ + 1] != 'u')
                            return Fail("unpaired surrogate");
                        p_ += 2;
                        if (!Hex4(lo)) return false;
                        if (lo < 0xDC00 || lo > 0xDFFF) return Fail("unpaired surrogate");
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        return Fail("unpaired surrogate");
                    }
                    if (cp == 0) return Fail("NUL character in string");
                    std::wstring w;
                    if (cp >= 0x10000) {
                        w += static_cast<wchar_t>(0xD800 + ((cp - 0x10000) >> 10));
                        w += static_cast<wchar_t>(0xDC00 + ((cp - 0x10000) & 0x3FF));
                    } else {
                        w += static_cast<wchar_t>(cp);
                    }
                    out += Narrow(w);
                    break;
                }
                default: return Fail("invalid escape sequence");
            }
        }
        return Fail("unterminated string");
    }

    bool ParseNumber(Json& v) {
        size_t start = p_;
        if (t_[p_] == '-') ++p_;
        if (p_ >= t_.size()) return Fail("invalid number");
        if (t_[p_] == '0') {
            ++p_;
        } else if (t_[p_] >= '1' && t_[p_] <= '9') {
            while (p_ < t_.size() && t_[p_] >= '0' && t_[p_] <= '9') ++p_;
        } else {
            return Fail("invalid number");
        }
        bool isFloat = false;
        if (p_ < t_.size() && t_[p_] == '.') {
            isFloat = true;
            ++p_;
            if (p_ >= t_.size() || t_[p_] < '0' || t_[p_] > '9') return Fail("invalid number");
            while (p_ < t_.size() && t_[p_] >= '0' && t_[p_] <= '9') ++p_;
        }
        if (p_ < t_.size() && (t_[p_] == 'e' || t_[p_] == 'E')) {
            isFloat = true;
            ++p_;
            if (p_ < t_.size() && (t_[p_] == '+' || t_[p_] == '-')) ++p_;
            if (p_ >= t_.size() || t_[p_] < '0' || t_[p_] > '9') return Fail("invalid number");
            while (p_ < t_.size() && t_[p_] >= '0' && t_[p_] <= '9') ++p_;
        }
        std::string text = t_.substr(start, p_ - start);
        if (!isFloat) {
            int64_t iv;
            if (ParseInt64(text, iv)) { v = Json(iv); return true; }
        }
        double d = std::strtod(text.c_str(), nullptr);
        if (!std::isfinite(d)) return Fail("number out of range");
        v = Json(d);
        return true;
    }

    const std::string& t_;
    size_t maxDepth_;
    size_t p_ = 0;
    std::string err_;
};

JsonParseResult ParseJson(const std::string& text, size_t maxDepth) {
    return JsonParser(text, maxDepth).Run();
}

}  // namespace sg
