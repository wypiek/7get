#include "test.h"
#include "util/json.h"

using namespace sg;

TEST(json_parses_valid_document) {
    auto r = ParseJson(R"({"a": [1, -2.5, true, false, null, "x\u00e9\n"], "b": {"c": 9007199254740991}})");
    CHECK(r.ok);
    const Json* a = r.value.Find("a");
    CHECK(a && a->IsArray() && a->Size() == 6);
    CHECK(a->Items()[0].IsInteger() && a->Items()[0].AsInt() == 1);
    CHECK(a->Items()[1].IsNumber() && !a->Items()[1].IsInteger());
    CHECK_EQ(a->Items()[5].AsString(), std::string("x\xC3\xA9\n"));
    CHECK(r.value.Find("b")->Find("c")->AsInt() == 9007199254740991LL);
}

TEST(json_surrogate_pairs) {
    auto r = ParseJson(R"("\ud83d\ude00")");
    CHECK(r.ok);
    CHECK_EQ(r.value.AsString(), std::string("\xF0\x9F\x98\x80"));
    CHECK(!ParseJson(R"("\ud83d")").ok);
    CHECK(!ParseJson(R"("\ude00")").ok);
}

TEST(json_rejects_malformed) {
    const char* bad[] = {
        "", "{", "[1,]", "{\"a\":1,}", "{'a':1}", "[01]", "[1.]", "[.5]", "[1e]", "tru", "nul",
        "\"unterminated", "\"bad \\x escape\"", "\"tab\tinside\"", "[1] trailing", "{\"a\" 1}",
        "{\"a\":1 \"b\":2}", "NaN", "[Infinity]", "\"\\u0000\"", "{\"a\":1,\"a\":2}",
    };
    for (const char* b : bad) {
        auto r = ParseJson(b);
        if (r.ok) ::sgtest::ReportFailure(__FILE__, __LINE__, std::string("accepted: ") + b);
    }
}

TEST(json_rejects_invalid_utf8_and_deep_nesting) {
    CHECK(!ParseJson("\"\xC0\xAF\"").ok);      // overlong
    CHECK(!ParseJson("\"\xED\xA0\x80\"").ok);  // encoded surrogate
    CHECK(!ParseJson("\"\xFF\"").ok);
    std::string deep(100, '[');
    deep += std::string(100, ']');
    CHECK(!ParseJson(deep).ok);
    std::string ok(50, '[');
    ok += std::string(50, ']');
    CHECK(ParseJson(ok).ok);
}

TEST(json_accepts_bom_and_reports_position) {
    CHECK(ParseJson("\xEF\xBB\xBF{}").ok);
    auto r = ParseJson("{\n  \"a\": x\n}");
    CHECK(!r.ok);
    CHECK(r.error.find("line 2") != std::string::npos);
}

TEST(json_roundtrip_and_escaping) {
    Json o = Json::Object();
    o.Set("s", std::string("quote\" back\\ ctrl\x01 \xE6\x97\xA5"));
    o.Set("n", static_cast<int64_t>(-42));
    o.Set("d", 0.5);
    Json arr = Json::Array();
    arr.Push(Json(true));
    arr.Push(Json());
    o.Set("a", arr);
    for (bool pretty : {false, true}) {
        auto r = ParseJson(o.Dump(pretty));
        CHECK(r.ok);
        CHECK_EQ(r.value.Find("s")->AsString(), o.Find("s")->AsString());
        CHECK(r.value.Find("n")->AsInt() == -42);
        CHECK(r.value.Find("d")->AsDouble() == 0.5);
        CHECK(r.value.Find("a")->Size() == 2);
    }
    CHECK(o.Dump().find("\\u0001") != std::string::npos);
    // Set replaces an existing key and keeps order.
    o.Set("s", "x");
    CHECK(o.Members().front().first == "s" && o.Find("s")->AsString() == "x");
}
