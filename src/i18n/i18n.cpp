/*
 * SPDX-License-Identifier: MIT
 */

#include "i18n.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace i18n {
namespace {

const Entry kEntries[] = {
#include "i18n_strings.inc"
};

bool starts_with(std::string_view s, std::string_view prefix) {
    return s.substr(0, prefix.size()) == prefix;
}

bool is_c_locale(const char* v) {
    if (!v || !*v) return false;
    const std::string_view s(v);
    return s == "C" || s == "POSIX" || starts_with(s, "C.");
}

// zh* / ja* / en* -> that language; anything else -> not decided by this value.
bool lang_of(std::string_view v, Lang& out) {
    if (starts_with(v, "zh")) { out = Lang::ZhCN; return true; }
    if (starts_with(v, "ja")) { out = Lang::Ja; return true; }
    if (starts_with(v, "en") || v == "C" || v == "POSIX" || starts_with(v, "C.")) {
        out = Lang::En;
        return true;
    }
    return false;
}

// First entry of a colon-separated list that names a language we know.
bool lang_of_list(const char* v, Lang& out) {
    if (!v) return false;
    std::string_view s(v);
    while (!s.empty()) {
        const auto colon = s.find(':');
        const auto item = s.substr(0, colon);
        if (!item.empty() && lang_of(item, out)) return true;
        if (colon == std::string_view::npos) break;
        s.remove_prefix(colon + 1);
    }
    return false;
}

std::mutex g_mutex;
bool g_have_lang = false;
Lang g_lang = Lang::En;

const std::unordered_map<std::string_view, const Entry*>& index() {
    static const auto* map = [] {
        auto* m = new std::unordered_map<std::string_view, const Entry*>();
        for (const auto& e : kEntries) (*m)[e.en] = &e;
        return m;
    }();
    return *map;
}

const char* pick(const Entry& e, Lang lang) {
    const char* t = lang == Lang::ZhCN ? e.zh_cn : lang == Lang::Ja ? e.ja : e.en;
    return t && *t ? t : e.en;
}

} // namespace

Lang detect(const std::function<const char*(const char*)>& getenv_fn) {
    auto get = [&](const char* name) -> const char* {
        const char* v = getenv_fn(name);
        return v && *v ? v : nullptr;
    };
    Lang lang = Lang::En;
    if (lang_of_list(get("IPDOIT_LANG"), lang)) return lang;

    // The effective message locale, as setlocale(LC_MESSAGES, "") would see it.
    const char* locale = get("LC_ALL");
    if (!locale) locale = get("LC_MESSAGES");
    if (!locale) locale = get("LANG");

    // gettext ignores LANGUAGE when the locale is C/POSIX (or unset).
    if (locale && !is_c_locale(locale) && lang_of_list(get("LANGUAGE"), lang)) return lang;
    if (locale && lang_of(locale, lang)) return lang;
    return Lang::En;
}

Lang current() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_have_lang) {
        g_lang = detect([](const char* name) { return std::getenv(name); });
        g_have_lang = true;
    }
    return g_lang;
}

void set_language(Lang lang) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_lang = lang;
    g_have_lang = true;
}

const char* lang_code(Lang lang) {
    switch (lang) {
        case Lang::ZhCN: return "zh-CN";
        case Lang::Ja: return "ja";
        default: return "en";
    }
}

bool needs_cjk() {
    return current() != Lang::En;
}

const char* tr(const char* english) {
    if (!english || !*english) return english;
    const Lang lang = current();
    if (lang == Lang::En) return english;
    const auto& m = index();
    const auto it = m.find(english);
    return it == m.end() ? english : pick(*it->second, lang);
}

std::string tr(const std::string& english) {
    if (english.empty() || current() == Lang::En) return english;
    const auto& m = index();
    const auto it = m.find(english);
    return it == m.end() ? english : std::string(pick(*it->second, current()));
}

std::string format(const char* english_format, ...) {
    const char* fmt = tr(english_format);
    va_list ap;
    va_start(ap, english_format);
    va_list copy;
    va_copy(copy, ap);
    const int n = std::vsnprintf(nullptr, 0, fmt, copy);
    va_end(copy);
    std::string out;
    if (n > 0) {
        std::vector<char> buf(static_cast<std::size_t>(n) + 1);
        std::vsnprintf(buf.data(), buf.size(), fmt, ap);
        out.assign(buf.data(), static_cast<std::size_t>(n));
    }
    va_end(ap);
    return out;
}

std::size_t utf8_fit(const char* text, std::size_t max_bytes) {
    if (!text) return 0;
    const std::size_t len = std::strlen(text);
    if (len <= max_bytes) return len;
    std::size_t n = max_bytes;
    // back up over continuation bytes (10xxxxxx) to the start of the cut sequence
    while (n > 0 && (static_cast<unsigned char>(text[n]) & 0xC0) == 0x80) --n;
    return n;
}

const Entry* entries(std::size_t& count) {
    count = sizeof(kEntries) / sizeof(kEntries[0]);
    return kEntries;
}

} // namespace i18n
