/*
 * SPDX-License-Identifier: MIT
 */

// Checks on the translation table and language detection (no LVGL).

#include "i18n.h"

#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {
int failures = 0;

#define CHECK(cond)                                                                      \
    do {                                                                                 \
        if (!(cond)) {                                                                   \
            std::fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond); \
            ++failures;                                                                  \
        }                                                                                \
    } while (0)

#define CHECK_MSG(cond, ...)                                                             \
    do {                                                                                 \
        if (!(cond)) {                                                                   \
            std::fprintf(stderr, "%s:%d: ", __FILE__, __LINE__);                          \
            std::fprintf(stderr, __VA_ARGS__);                                           \
            std::fprintf(stderr, "\n");                                                  \
            ++failures;                                                                  \
        }                                                                                \
    } while (0)

using i18n::Lang;

// printf conversions in order, e.g. "%zu rules %d" -> {"zu", "d"}; "%%" is not one.
std::vector<std::string> conversions(const char* s) {
    std::vector<std::string> out;
    for (const char* p = s; *p; ++p) {
        if (*p != '%') continue;
        ++p;
        if (*p == '%') continue;
        std::string spec;
        while (*p && std::strchr("-+ #0123456789.", *p)) ++p; // flags, width, precision
        while (*p && std::strchr("hlLqjzt", *p)) spec += *p++;  // length
        if (*p) spec += *p;
        out.push_back(spec);
        if (!*p) break;
    }
    return out;
}

bool valid_utf8(const char* s) {
    const auto* p = reinterpret_cast<const unsigned char*>(s);
    while (*p) {
        int n = 0;
        if (*p < 0x80) n = 0;
        else if ((*p & 0xE0) == 0xC0 && *p >= 0xC2) n = 1;
        else if ((*p & 0xF0) == 0xE0) n = 2;
        else if ((*p & 0xF8) == 0xF0 && *p <= 0xF4) n = 3;
        else return false;
        ++p;
        for (int i = 0; i < n; ++i, ++p) {
            if ((*p & 0xC0) != 0x80) return false;
        }
    }
    return true;
}

void test_table() {
    std::size_t n = 0;
    const auto* e = i18n::entries(n);
    CHECK(n > 100);
    std::set<std::string> seen;
    for (std::size_t i = 0; i < n; ++i) {
        CHECK_MSG(seen.insert(e[i].en).second, "duplicate entry: \"%s\"", e[i].en);
        CHECK_MSG(valid_utf8(e[i].en), "bad UTF-8 in \"%s\"", e[i].en);
        const auto want = conversions(e[i].en);
        for (const char* t : {e[i].zh_cn, e[i].ja}) {
            CHECK_MSG(t && *t, "missing translation for \"%s\"", e[i].en);
            if (!t || !*t) continue;
            CHECK_MSG(valid_utf8(t), "bad UTF-8 in translation of \"%s\"", e[i].en);
            CHECK_MSG(conversions(t) == want, "printf conversions differ: \"%s\" vs \"%s\"",
                      e[i].en, t);
            // a leading space or newline in the English text is layout; keep it
            CHECK_MSG((e[i].en[0] == '\n') == (t[0] == '\n'), "leading newline: \"%s\"", e[i].en);
            CHECK_MSG(std::strchr(e[i].en, '\n') == nullptr || std::strchr(t, '\n') != nullptr,
                      "line break dropped: \"%s\"", e[i].en);
        }
    }
}

// Strings that end up in fixed-size LVGL string subjects (see base_viewmodel.h) must fit,
// or they get cut (at a character boundary, but still cut).
void test_budgets() {
    const std::map<std::string, std::size_t> budgets = {
        // title_subject_ (48): "Ipdoit  " + page name
        {"Status", 48 - 1 - 8},
        {"Rules", 48 - 1 - 8},
        {"Ports", 48 - 1 - 8},
        {"Networks", 48 - 1 - 8},
        // password_message_subject_ (96)
        {"Enter your sudo password", 95},
        {"Wrong password, try again", 95},
        {"Checking...", 95},
        // notice_subject_ (192); "%s" parts are change titles, ~40 bytes at most
        {"Busy - try again in a moment", 191},
        {"Firewall state not loaded yet", 191},
        {"Not connected to a network", 191},
        {"This network has no IPv4 subnet to whitelist", 191},
        {"Nothing to undo", 191},
        {"Only listens on this device; the firewall does not apply", 191},
        {"%s  (U undo)", 191 - 60},
        {"%s: done", 191 - 60},
    };
    std::size_t n = 0;
    const auto* e = i18n::entries(n);
    std::set<std::string> found;
    for (std::size_t i = 0; i < n; ++i) {
        const auto it = budgets.find(e[i].en);
        if (it == budgets.end()) continue;
        found.insert(it->first);
        for (const char* t : {e[i].en, e[i].zh_cn, e[i].ja}) {
            CHECK_MSG(std::strlen(t) <= it->second, "\"%s\" is %zu bytes, budget %zu", t,
                      std::strlen(t), it->second);
        }
    }
    CHECK(found.size() == budgets.size());
    // the longest change titles (used in notices) also fit the title budget above
    for (const char* title : {"Remove network from whitelist", "Follow network changes?"}) {
        for (const Lang l : {Lang::En, Lang::ZhCN, Lang::Ja}) {
            i18n::set_language(l);
            CHECK(std::strlen(i18n::tr(title)) <= 60);
        }
    }
}

void test_utf8_fit() {
    const char* s = "ab\xe4\xb8\xad\xe6\x96\x87"; // "ab中文"
    CHECK(i18n::utf8_fit(s, 100) == 8);
    CHECK(i18n::utf8_fit(s, 8) == 8);
    CHECK(i18n::utf8_fit(s, 7) == 5); // not inside 文
    CHECK(i18n::utf8_fit(s, 6) == 5);
    CHECK(i18n::utf8_fit(s, 5) == 5);
    CHECK(i18n::utf8_fit(s, 4) == 2); // not inside 中
    CHECK(i18n::utf8_fit(s, 2) == 2);
    CHECK(i18n::utf8_fit(s, 0) == 0);
    CHECK(i18n::utf8_fit(nullptr, 4) == 0);
}

Lang detect_with(const std::map<std::string, std::string>& env) {
    return i18n::detect([&env](const char* name) -> const char* {
        const auto it = env.find(name);
        return it == env.end() ? nullptr : it->second.c_str();
    });
}

void test_detect() {
    CHECK(detect_with({}) == Lang::En);
    CHECK(detect_with({{"LANG", "zh_CN.UTF-8"}}) == Lang::ZhCN);
    CHECK(detect_with({{"LANG", "zh_TW.UTF-8"}}) == Lang::ZhCN);
    CHECK(detect_with({{"LANG", "ja_JP.UTF-8"}}) == Lang::Ja);
    CHECK(detect_with({{"LANG", "en_GB.UTF-8"}}) == Lang::En);
    CHECK(detect_with({{"LANG", "de_DE.UTF-8"}}) == Lang::En);
    CHECK(detect_with({{"LANG", "C.UTF-8"}}) == Lang::En);
    // LC_ALL beats LC_MESSAGES beats LANG
    CHECK(detect_with({{"LANG", "ja_JP.UTF-8"}, {"LC_MESSAGES", "zh_CN.UTF-8"}}) == Lang::ZhCN);
    CHECK(detect_with({{"LC_MESSAGES", "zh_CN.UTF-8"}, {"LC_ALL", "ja_JP.UTF-8"}}) == Lang::Ja);
    CHECK(detect_with({{"LANG", "ja_JP.UTF-8"}, {"LC_ALL", "C"}}) == Lang::En);
    // LANGUAGE wins over the locale, except when the locale is C (gettext rule)
    CHECK(detect_with({{"LANG", "en_US.UTF-8"}, {"LANGUAGE", "ja:en"}}) == Lang::Ja);
    CHECK(detect_with({{"LANG", "C"}, {"LANGUAGE", "ja"}}) == Lang::En);
    CHECK(detect_with({{"LANGUAGE", "ja"}}) == Lang::En);
    CHECK(detect_with({{"LANG", "ja_JP.UTF-8"}, {"LANGUAGE", "fr:zh_CN"}}) == Lang::ZhCN);
    CHECK(detect_with({{"LANG", "ja_JP.UTF-8"}, {"LANGUAGE", "fr"}}) == Lang::Ja);
    // IPDOIT_LANG overrides everything
    CHECK(detect_with({{"LANG", "ja_JP.UTF-8"}, {"IPDOIT_LANG", "en"}}) == Lang::En);
    CHECK(detect_with({{"LC_ALL", "C"}, {"IPDOIT_LANG", "zh-CN"}}) == Lang::ZhCN);
    CHECK(detect_with({{"LANG", "zh_CN.UTF-8"}, {"IPDOIT_LANG", ""}}) == Lang::ZhCN);
}

void test_tr() {
    i18n::set_language(Lang::En);
    CHECK(std::strcmp(i18n::tr("Firewall ON"), "Firewall ON") == 0);
    CHECK(!i18n::needs_cjk());
    i18n::set_language(Lang::ZhCN);
    CHECK(std::strcmp(i18n::tr("Firewall ON"), "防火墙：激活") == 0);
    CHECK(std::strcmp(i18n::tr("not in the table"), "not in the table") == 0);
    CHECK(i18n::tr(std::string("Delete rule")) == "删除规则");
    CHECK(i18n::format("%s: done", "x") == "x：完成");
    CHECK(i18n::needs_cjk());
    i18n::set_language(Lang::Ja);
    CHECK(i18n::format("%zu rules, first match wins%s", static_cast<std::size_t>(3), "") ==
          "ルール 3 件、最初の一致が優先");
    // key names are not in the table, so they pass through
    CHECK(std::strcmp(i18n::tr("ENTER"), "ENTER") == 0);
    i18n::set_language(Lang::En);
    CHECK(i18n::format("Incoming default: %s.", "deny") == "Incoming default: deny.");
}

} // namespace

int main() {
    test_table();
    test_budgets();
    test_utf8_fit();
    test_detect();
    test_tr();
    if (failures) {
        std::fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    std::printf("i18n_tests: all passed\n");
    return 0;
}
