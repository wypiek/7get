// SevenGet - small strict JSON (RFC 8259) parser and writer.
//
// Design notes:
//  * Object member order is preserved (manifests are human-edited).
//  * Duplicate object keys are rejected: with signed metadata an ambiguous
//    document could be interpreted differently by different tools.
//  * Input must be valid UTF-8; nesting depth is limited.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace sg {

class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };
    using Member = std::pair<std::string, Json>;

    Json() = default;
    Json(std::nullptr_t) {}
    Json(bool b) : type_(Type::Bool), bool_(b) {}
    Json(int v) : Json(static_cast<int64_t>(v)) {}
    Json(int64_t v);
    Json(uint64_t v) : Json(static_cast<int64_t>(v)) {}
    Json(double v);
    Json(const char* s) : type_(Type::String), str_(s) {}
    Json(std::string s) : type_(Type::String), str_(std::move(s)) {}

    static Json Array() { Json j; j.type_ = Type::Array; return j; }
    static Json Object() { Json j; j.type_ = Type::Object; return j; }

    Type type() const { return type_; }
    bool IsNull() const { return type_ == Type::Null; }
    bool IsBool() const { return type_ == Type::Bool; }
    bool IsNumber() const { return type_ == Type::Number; }
    bool IsString() const { return type_ == Type::String; }
    bool IsArray() const { return type_ == Type::Array; }
    bool IsObject() const { return type_ == Type::Object; }
    // True if the number is integral and fits into int64.
    bool IsInteger() const { return type_ == Type::Number && isInt_; }

    bool AsBool() const { return bool_; }
    double AsDouble() const { return num_; }
    int64_t AsInt() const { return int_; }
    const std::string& AsString() const { return str_; }

    // Array access
    const std::vector<Json>& Items() const { return arr_; }
    void Push(Json v) { arr_.push_back(std::move(v)); }
    size_t Size() const { return type_ == Type::Array ? arr_.size() : obj_.size(); }

    // Object access
    const std::vector<Member>& Members() const { return obj_; }
    const Json* Find(const std::string& key) const;
    bool Has(const std::string& key) const { return Find(key) != nullptr; }
    // Sets (replacing an existing member with the same key).
    Json& Set(const std::string& key, Json v);

    std::string Dump(bool pretty = false) const;

private:
    void DumpTo(std::string& out, bool pretty, int indent) const;
    friend class JsonParser;

    Type type_ = Type::Null;
    bool bool_ = false;
    bool isInt_ = false;
    int64_t int_ = 0;
    double num_ = 0;
    std::string str_;
    std::vector<Json> arr_;
    std::vector<Member> obj_;
};

struct JsonParseResult {
    bool ok = false;
    Json value;
    std::string error;  // "line L, column C: message"
};

JsonParseResult ParseJson(const std::string& text, size_t maxDepth = 64);

// Appends a JSON string literal (with quotes) for s.
void JsonEscape(std::string& out, const std::string& s);

}  // namespace sg
